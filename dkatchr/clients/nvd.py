"""
NVDClient — HTTP wrapper + per-CVE file cache for the NVD 2.0 CVE API.

Same role as osv.py (network client + cache), used by the credential-risk
classification pass when OSV carries no usable CWE data: it fetches a single
CVE record so we can read its CWE weaknesses. Vuln records are effectively
immutable, so the cache is permanent per CVE. A CVE NVD doesn't know about
comes back as HTTP 200 with zero results, and that empty record is cached like
any other.

The API key goes in the `apiKey` request HEADER — NVD's documented mechanism.
Up to 0.3.1 it was sent as an `?apiKey=` query parameter, which NVD rejects
with HTTP 404; the client then cached a permanent "not found" sentinel, so with
a key configured EVERY lookup silently failed. A 404 is therefore never cached
now, and legacy {"not_found": true} sentinels are treated as cache misses and
re-fetched (they can only have come from that bug).

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
from dkatchr.config import DEFAULT_NVD_CPE_TTL, NVD_BASE_URL, NVD_RATE_NO_KEY, NVD_RATE_WITH_KEY
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

        Cache-first: a hit returns immediately with no HTTP call. A legacy
        {"not_found": true} sentinel (written by <=0.3.1 on a rejected-key
        404) is ignored and re-fetched. HTTP errors log and return None
        without caching — this never raises, so a flaky NVD never aborts a
        scan.
        """
        path = self._cve_path(cve_id)
        cached = self._read_cache(path)
        if cached is not None and not cached.get("not_found"):
            return cached

        params = {"cveId": cve_id}
        headers = {"apiKey": self.api_key} if self.api_key else {}

        for attempt in range(max_retries):
            self.limiter.acquire()
            try:
                resp = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=30)
            except requests.RequestException as e:
                wait = 2 ** attempt
                log(f"[!] NVD GET {cve_id} network error: {e} — retrying in {wait}s")
                time.sleep(wait)
                continue
            if resp.status_code == 404:
                # NOT "CVE unknown" (that is a 200 with zero results) — NVD
                # returns 404 for a rejected request, e.g. a bad API key.
                # Never cached, so a later fix/retry can succeed.
                log(f"[!] NVD GET {cve_id} 404 — request rejected (check NVD_API_KEY); not cached")
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


    # ---- version-aware product lookup (runtime scanning) -------------------

    def cves_for_product(self, cpe_vendor_product: str, version: str,
                         ttl_seconds: int = DEFAULT_NVD_CPE_TTL) -> list[dict] | None:
        """CVEs whose ANALYSED NVD configuration matches `vendor:product` at
        `version` (virtualMatchString), as
        [{id, summary, published, cvss_score, cvss_vector, cwe_ids, fixed}].

        TTL'd per (product, version): NVD analyses CVEs late (many recent ones
        stay "Received"/"Deferred" with no configuration at all — the CVE.org
        index covers those), so a re-check picks newly analysed ranges up.
        Returns None on failure (never raises).
        """
        key = re.sub(r"[^A-Za-z0-9._-]", "_", f"{cpe_vendor_product}@{version}")
        path = os.path.join(self.cache_dir, "nvd_cpe", key + ".json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        cached = self._read_cache(path)
        if cached is not None and time.time() - cached.get("fetched_at", 0) < ttl_seconds:
            return cached.get("cves")
        match = f"cpe:2.3:a:{cpe_vendor_product}:{version}"
        headers = {"apiKey": self.api_key} if self.api_key else {}
        out: list[dict] = []
        start = 0
        while True:
            data = None
            for attempt in range(4):
                self.limiter.acquire()
                try:
                    resp = requests.get(NVD_BASE_URL, headers=headers, timeout=60, params={
                        "virtualMatchString": match, "resultsPerPage": 2000, "startIndex": start})
                except requests.RequestException as e:
                    log(f"[!] NVD product {match}: {e}")
                    time.sleep(2 ** attempt)
                    continue
                if resp.status_code in (429, 503) or resp.status_code >= 500:
                    time.sleep(2 ** attempt + 1)
                    continue
                if resp.status_code != 200:
                    log(f"[!] NVD product {match}: HTTP {resp.status_code}")
                    return cached.get("cves") if cached else None
                try:
                    data = resp.json()
                except ValueError:
                    return cached.get("cves") if cached else None
                break
            if data is None:
                return cached.get("cves") if cached else None
            for item in data.get("vulnerabilities") or []:
                out.append(_nvd_summary(item.get("cve") or {}, cpe_vendor_product, version))
            start += data.get("resultsPerPage") or 0
            if not data.get("resultsPerPage") or start >= data.get("totalResults", 0):
                break
        self._write_cache(path, {"fetched_at": time.time(), "cves": out})
        return out


def _nvd_summary(cve: dict, vendor_product: str, version: str) -> dict:
    desc = next((d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
    best = None
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key) or []:
            d = m.get("cvssData") or {}
            if d.get("baseScore") is not None and (best is None or d["baseScore"] > best[0]):
                best = (d["baseScore"], d.get("vectorString"))
        if best:
            break
    fixed: list[str] = []
    prefix = f"cpe:2.3:a:{vendor_product}:".lower()
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for cm in node.get("cpeMatch") or []:
                if cm.get("vulnerable") and cm.get("criteria", "").lower().startswith(prefix):
                    end = cm.get("versionEndExcluding")
                    if end and end not in fixed:
                        fixed.append(end)
    cwes = sorted({d.get("value") for w in cve.get("weaknesses") or []
                   for d in w.get("description") or [] if (d.get("value") or "").startswith("CWE-")})
    return {"id": cve.get("id"), "summary": desc[:500], "published": cve.get("published", ""),
            "cvss_score": best[0] if best else None, "cvss_vector": best[1] if best else None,
            "cwe_ids": cwes, "fixed": fixed}
