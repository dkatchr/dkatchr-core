"""
NVDClient — HTTP wrapper + per-CVE file cache for the NVD 2.0 CVE API.

Same role as osv.py (network client + cache), used by the credential-risk
classification pass when OSV carries no usable CWE data: it fetches a single
CVE record so we can read its CWE weaknesses. Vuln records are effectively
immutable, so the cache is permanent per CVE — including a "not found"
sentinel so we never re-query a CVE NVD doesn't know about.

This module does NOT decide credential risk or parse weaknesses — it only
returns the raw NVD JSON (or None). Classification logic lives in
web/services/classification_service.py.
"""

import json
import os
import re
import time

import requests

from dkatchr.clients.ratelimit import TokenBucket
from dkatchr.config import NVD_BASE_URL, NVD_RATE_NO_KEY, NVD_RATE_WITH_KEY
from dkatchr.logger import log

# NVD's rate budget is expressed per rolling 30-second window; TokenBucket
# wants tokens-per-second, so divide the per-30s constant by this.
_NVD_RATE_WINDOW_SECONDS = 30.0


class NVDClient:
    def __init__(self, cache_dir: str, api_key: str | None = None) -> None:
        self.api_key  = api_key or None
        self.cache_dir = cache_dir
        self.nvd_dir  = os.path.join(cache_dir, "nvd")
        rate_per_30s  = NVD_RATE_WITH_KEY if self.api_key else NVD_RATE_NO_KEY
        # capacity=2 is a tiny burst allowance; the sustained rate is what keeps
        # us under NVD's window budget.
        self.limiter  = TokenBucket(rate=rate_per_30s / _NVD_RATE_WINDOW_SECONDS, capacity=2)
        os.makedirs(self.nvd_dir, exist_ok=True)

    # ---- cache ----------------------------------------------------------

    def _cve_path(self, cve_id: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", cve_id)
        return os.path.join(self.nvd_dir, f"{safe}.json")

    def _read_cache(self, path: str) -> dict | None:
        if not os.path.exists(path):
            return None
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _write_cache(self, path: str, data: dict) -> None:
        try:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, path)
        except Exception as e:
            log(f"[!] NVD cache write {path}: {e}")

    # ---- public api -----------------------------------------------------

    def get_cve(self, cve_id: str, max_retries: int = 4) -> dict | None:
        """Return the raw NVD 2.0 record for `cve_id`, or None.

        Cache-first: a hit returns immediately with no HTTP call. A cached
        {"not_found": true} sentinel returns None without re-querying. On a
        live 404 we write that sentinel. Any other error logs and returns
        None — this never raises, so a flaky NVD never aborts a scan.
        """
        path = self._cve_path(cve_id)
        cached = self._read_cache(path)
        if cached is not None:
            if cached.get("not_found"):
                return None
            return cached

        params = {"cveId": cve_id}
        if self.api_key:
            params["apiKey"] = self.api_key

        for attempt in range(max_retries):
            self.limiter.acquire()
            try:
                resp = requests.get(NVD_BASE_URL, params=params, timeout=30)
            except requests.RequestException as e:
                wait = 2 ** attempt
                log(f"[!] NVD GET {cve_id} network error: {e} — retrying in {wait}s")
                time.sleep(wait)
                continue
            if resp.status_code == 404:
                # CVE not in NVD — cache a sentinel so we never ask again.
                self._write_cache(path, {"not_found": True})
                return None
            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                wait = int(retry_after) if (retry_after and retry_after.isdigit()) else 2 ** attempt
                log(f"[!] NVD 429 — sleeping {wait}s")
                time.sleep(wait + 1)
                continue
            if resp.status_code >= 500:
                wait = 2 ** attempt
                log(f"[!] NVD {resp.status_code} for {cve_id} — retrying in {wait}s")
                time.sleep(wait)
                continue
            if resp.status_code >= 400:
                log(f"[!] NVD GET {cve_id} {resp.status_code}: {resp.text[:200]}")
                return None
            try:
                data = resp.json()
            except ValueError as e:
                log(f"[!] NVD GET {cve_id} bad JSON: {e}")
                return None
            self._write_cache(path, data)
            return data
        return None
