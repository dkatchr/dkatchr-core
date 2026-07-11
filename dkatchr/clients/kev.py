"""
KEV client — download, cache, and lookup against the CISA Known Exploited
Vulnerabilities catalog.

WHY: Cross-referencing OSV findings against KEV provides a critical
prioritisation signal. A KEV-flagged CVE should be triaged immediately.

Single ~1MB JSON GET, cached on disk with a configurable TTL (default 24h).
No rate limiter needed — one request per scan at most.
"""

import json
import os
import time

import requests

from dkatchr.config import KEV_CATALOG_URL, KEV_DEFAULT_TTL
from dkatchr.logger import log


class KEVClient:
    def __init__(self, cache_dir: str, ttl_seconds: int = KEV_DEFAULT_TTL) -> None:
        self.cache_dir = cache_dir
        self.ttl = int(ttl_seconds)
        self._catalog_path = os.path.join(cache_dir, "kev_catalog.json")
        self._meta_path = os.path.join(cache_dir, "kev_meta.json")
        self._cve_set: set[str] | None = None
        os.makedirs(cache_dir, exist_ok=True)

    # ---- public API ---------------------------------------------------------

    def load(self) -> set[str]:
        """Return the set of CVE IDs in the KEV catalog.

        Strategy: fresh cache -> download -> stale cache -> empty set.
        Once loaded, the set is memoised for the lifetime of this client.
        """
        if self._cve_set is not None:
            return self._cve_set

        # Try fresh cache first
        cached = self._read_cache()
        if cached is not None and self._is_cache_fresh():
            self._cve_set = cached
            log(f"[+] KEV: loaded {len(cached)} CVEs from cache")
            return self._cve_set

        # Try downloading
        downloaded = self._download()
        if downloaded is not None:
            self._cve_set = downloaded
            return self._cve_set

        # Fall back to stale cache
        if cached is not None:
            self._cve_set = cached
            log(f"[!] KEV: using stale cache ({len(cached)} CVEs)")
            return self._cve_set

        # Nothing available
        log("[!] KEV: no catalog available — KEV cross-reference will be empty")
        self._cve_set = set()
        return self._cve_set

    def check_vuln(self, vuln_id: str, aliases: str) -> bool:
        """Check whether a vulnerability (by ID or aliases) is in KEV.

        `aliases` is a comma-separated string of alternative IDs.
        Returns True if any CVE-* ID matches the KEV set.
        """
        cve_set = self._cve_set or set()
        if not cve_set:
            return False

        # Check primary ID
        if vuln_id.startswith("CVE-") and vuln_id in cve_set:
            return True

        # Check aliases
        for alias in aliases.split(","):
            alias = alias.strip()
            if alias.startswith("CVE-") and alias in cve_set:
                return True

        return False

    # ---- internals ----------------------------------------------------------

    def _is_cache_fresh(self) -> bool:
        if not os.path.exists(self._meta_path):
            return False
        try:
            with open(self._meta_path, encoding="utf-8") as f:
                meta = json.load(f)
            return time.time() - meta.get("fetched_at", 0) < self.ttl
        except Exception:
            return False

    def _read_cache(self) -> set[str] | None:
        if not os.path.exists(self._catalog_path):
            return None
        try:
            with open(self._catalog_path, encoding="utf-8") as f:
                data = json.load(f)
            return self._extract_cve_ids(data)
        except Exception as e:
            log(f"[!] KEV: cache read error: {e}")
            return None

    def _download(self) -> set[str] | None:
        log("[+] KEV: downloading CISA KEV catalog…")
        try:
            resp = requests.get(KEV_CATALOG_URL, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            log(f"[!] KEV: download failed: {e}")
            return None

        cve_set = self._extract_cve_ids(data)
        log(f"[+] KEV: downloaded {len(cve_set)} CVEs")

        # Persist to cache
        try:
            tmp = self._catalog_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, self._catalog_path)

            tmp_meta = self._meta_path + ".tmp"
            with open(tmp_meta, "w", encoding="utf-8") as f:
                json.dump({"fetched_at": int(time.time())}, f)
            os.replace(tmp_meta, self._meta_path)
        except Exception as e:
            log(f"[!] KEV: cache write error: {e}")

        return cve_set

    @staticmethod
    def _extract_cve_ids(data: dict) -> set[str]:
        vulns = data.get("vulnerabilities") or []
        return {v["cveID"] for v in vulns if isinstance(v, dict) and v.get("cveID")}
