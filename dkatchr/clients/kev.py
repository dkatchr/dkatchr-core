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
        self._entries: list[dict] = []
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
        cached_data = self._read_cache_data()
        cached = self._extract_cve_ids(cached_data) if cached_data is not None else None
        if cached is not None and self._is_cache_fresh():
            self._cve_set = cached
            self._entries = self._extract_entries(cached_data)
            log(f"[+] KEV: loaded {len(cached)} CVEs from cache")
            return self._cve_set

        # Try downloading
        downloaded = self._download()
        if downloaded is not None:
            self._cve_set = self._extract_cve_ids(downloaded)
            self._entries = self._extract_entries(downloaded)
            return self._cve_set

        # Fall back to stale cache
        if cached is not None:
            self._cve_set = cached
            self._entries = self._extract_entries(cached_data)
            log(f"[!] KEV: using stale cache ({len(cached)} CVEs)")
            return self._cve_set

        # Nothing available
        log("[!] KEV: no catalog available — KEV cross-reference will be empty")
        self._cve_set = set()
        return self._cve_set

    def recent(self, limit: int = 10) -> list[dict]:
        """The newest KEV additions, newest first: [{cve_id, name, vendor,
        product, date_added (YYYY-MM-DD), known_ransomware}]. Same
        fresh -> download -> stale -> empty strategy as load(); never raises."""
        self.load()
        return self._entries[: max(0, int(limit))]

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

    def _read_cache_data(self) -> dict | None:
        if not os.path.exists(self._catalog_path):
            return None
        try:
            with open(self._catalog_path, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else None
        except Exception as e:
            log(f"[!] KEV: cache read error: {e}")
            return None

    def _download(self) -> dict | None:
        log("[+] KEV: downloading CISA KEV catalog…")
        try:
            resp = requests.get(KEV_CATALOG_URL, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            log(f"[!] KEV: download failed: {e}")
            return None

        if not isinstance(data, dict):
            log("[!] KEV: unexpected catalog format")
            return None
        log(f"[+] KEV: downloaded {len(self._extract_cve_ids(data))} CVEs")

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

        return data

    @staticmethod
    def _extract_cve_ids(data: dict) -> set[str]:
        vulns = data.get("vulnerabilities") or []
        return {v["cveID"] for v in vulns if isinstance(v, dict) and v.get("cveID")}

    @staticmethod
    def _extract_entries(data: dict | None) -> list[dict]:
        """Catalog entries newest first (by dateAdded, then CVE id)."""
        out = []
        for v in (data or {}).get("vulnerabilities") or []:
            if not isinstance(v, dict) or not v.get("cveID"):
                continue
            out.append({
                "cve_id": v["cveID"],
                "name": v.get("vulnerabilityName") or "",
                "vendor": v.get("vendorProject") or "",
                "product": v.get("product") or "",
                "date_added": v.get("dateAdded") or "",
                "known_ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
            })
        out.sort(key=lambda e: (e["date_added"], e["cve_id"]), reverse=True)
        return out
