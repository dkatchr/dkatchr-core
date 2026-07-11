"""
OSVClient — HTTP wrapper + two-tier cache for OSV.dev.

MOVED FROM: dkatchr/osv_client.py (the HTTP+cache half).
WHY: The old osv_client.py mixed three concerns: HTTP wrapper, on-disk cache,
and the enrichment workflow (osv_enrich, osv_rows_for_repo, severity helpers).
The workflow now lives in core/osv_enrichment.py. This file is only the
network client + cache — same role as github.py for GitHub.

Two-tier cache:
  1. (ecosystem, package, version) → [vuln_ids]   TTL-bound (default 24h)
  2. vuln_id → full record                         immutable, no TTL.

Daily re-scans refresh the cheap tuple→IDs step; expensive per-ID detail
fetches stay cached forever.
"""

import json
import os
import re
import threading
import time

import requests

from dkatchr.clients.ratelimit import TokenBucket
from dkatchr.config import OSV_API_BASE
from dkatchr.logger import log


class OSVClient:
    def __init__(
        self,
        cache_dir: str,
        ttl_seconds: int,
        rps: float,
        burst: float,
        api_base: str = OSV_API_BASE,
    ) -> None:
        self.api_base    = api_base
        self.cache_dir   = cache_dir
        self.index_path  = os.path.join(cache_dir, "index.json")
        self.vuln_dir    = os.path.join(cache_dir, "vulns")
        self.ttl         = int(ttl_seconds)
        self.limiter     = TokenBucket(rate=rps, capacity=burst)
        self.lock        = threading.Lock()
        os.makedirs(self.vuln_dir, exist_ok=True)
        self.index       = self._load_index()

    # ---- index ----------------------------------------------------------

    @staticmethod
    def _key(ecosystem: str, package: str, version: str) -> str:
        return f"{ecosystem}|{package}|{version}"

    def _load_index(self) -> dict:
        if not os.path.exists(self.index_path):
            return {}
        try:
            with open(self.index_path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def save_index(self) -> None:
        with self.lock:
            tmp = self.index_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.index, f, indent=2)
            os.replace(tmp, self.index_path)

    def get_cached_ids(self, ecosystem: str, package: str, version: str) -> list[str] | None:
        entry = self.index.get(self._key(ecosystem, package, version))
        if not entry:
            return None
        if time.time() - entry.get("queried_at", 0) > self.ttl:
            return None
        return list(entry.get("vuln_ids") or [])

    def set_cached_ids(self, ecosystem: str, package: str, version: str, ids: list[str]) -> None:
        with self.lock:
            self.index[self._key(ecosystem, package, version)] = {
                "vuln_ids":   ids,
                "queried_at": int(time.time()),
            }

    # ---- HTTP -----------------------------------------------------------

    def _post(self, path: str, body: dict, max_retries: int = 5) -> dict:
        url = f"{self.api_base}{path}"
        for attempt in range(max_retries):
            self.limiter.acquire()
            try:
                resp = requests.post(url, json=body, timeout=60)
            except requests.RequestException as e:
                wait = 2 ** attempt
                log(f"[!] OSV POST {path} network error: {e} — retrying in {wait}s")
                time.sleep(wait)
                continue
            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                wait = int(retry_after) if (retry_after and retry_after.isdigit()) else 2 ** attempt
                log(f"[!] OSV 429 — sleeping {wait}s")
                time.sleep(wait + 1)
                continue
            if resp.status_code >= 500:
                wait = 2 ** attempt
                log(f"[!] OSV {resp.status_code} — retrying in {wait}s")
                time.sleep(wait)
                continue
            if resp.status_code >= 400:
                log(f"[!] OSV POST {path} {resp.status_code}: {resp.text[:200]}")
                resp.raise_for_status()
            return resp.json()
        raise RuntimeError(f"OSV POST {path} failed after retries")

    def _get(self, path: str, max_retries: int = 5) -> dict | None:
        url = f"{self.api_base}{path}"
        for attempt in range(max_retries):
            self.limiter.acquire()
            try:
                resp = requests.get(url, timeout=30)
            except requests.RequestException as e:
                wait = 2 ** attempt
                log(f"[!] OSV GET {path} network error: {e} — retrying in {wait}s")
                time.sleep(wait)
                continue
            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                wait = int(retry_after) if (retry_after and retry_after.isdigit()) else 2 ** attempt
                log(f"[!] OSV 429 — sleeping {wait}s")
                time.sleep(wait + 1)
                continue
            if resp.status_code >= 500:
                wait = 2 ** attempt
                time.sleep(wait)
                continue
            if resp.status_code >= 400:
                log(f"[!] OSV GET {path} {resp.status_code}")
                return None
            return resp.json()
        return None

    # ---- batch query ---------------------------------------------------

    def query_batch(self, tuples: list[tuple[str, str, str]]) -> list[list[str]]:
        """
        POST /v1/querybatch — returns list of vuln-ID lists in input order.
        OSV's querybatch returns only IDs; details require separate /vulns/{id}.
        """
        body = {
            "queries": [
                {"package": {"name": pkg, "ecosystem": eco}, "version": ver}
                for (eco, pkg, ver) in tuples
            ]
        }
        data = self._post("/querybatch", body)
        results = data.get("results") or []
        out: list[list[str]] = []
        for r in results:
            vulns = r.get("vulns") or []
            out.append([v["id"] for v in vulns if isinstance(v, dict) and v.get("id")])
        while len(out) < len(tuples):
            out.append([])
        return out

    # ---- vuln details --------------------------------------------------

    def _vuln_path(self, vuln_id: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", vuln_id)
        return os.path.join(self.vuln_dir, f"{safe}.json")

    def get_vuln(self, vuln_id: str) -> dict | None:
        """Cached fetch of a single vuln's full record. Vuln details are immutable."""
        path = self._vuln_path(vuln_id)
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        data = self._get(f"/vulns/{vuln_id}")
        if data:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f)
            except Exception as e:
                log(f"[!] OSV vuln cache write {vuln_id}: {e}")
        return data
