"""
Metasploit client — download, cache, and lookup against the set of CVEs that
have a Metasploit Framework module.

WHY: A CVE with a Metasploit module is point-and-click weaponised — the highest
tier of the "Has Exploit" composite (alongside CISA KEV and ExploitDB). OSV
carries no exploit-availability data, so this catalog is the free path to it.

Mirrors KEVClient exactly: a single bulk file GET wrapped in a TTL'd file cache
(default 24h), fresh→download→stale→empty fail-safe chain, memoised for the
client's lifetime. Never raises — a download failure degrades to stale cache,
then an empty set, and must never block or abort a scan.

SOURCE NOTE: rapid7/metasploit-framework has no machine-readable CVE index, so
we use a community export. Its top-level `cves` key is a DICT keyed by CVE id
(NOT an array), so we take its keys; a list shape is also tolerated defensively.
Each key is validated against the CVE id pattern before inclusion. See
config.METASPLOIT_CVES_URL.

This module does NOT do CVE-token extraction from a finding's vuln_id/aliases or
any DB work — that lives in the web repository / CLI runner (same split as
KEV/EPSS). It only returns a set[str] of uppercased CVE IDs.
"""

import json
import os
import re
import time

import requests

from dkatchr.config import METASPLOIT_CVES_URL, METASPLOIT_DEFAULT_TTL
from dkatchr.logger import log

# A full CVE id (anchored) — used to validate the dict keys / list entries.
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


class MetasploitClient:
    def __init__(self, cache_dir: str, ttl_seconds: int = METASPLOIT_DEFAULT_TTL) -> None:
        self.cache_dir = cache_dir
        self.ttl = int(ttl_seconds)
        # Cache the PARSED CVE set (a JSON list). Both download and cache-read
        # return a set[str], keeping the load() chain shape-uniform.
        self._catalog_path = os.path.join(cache_dir, "metasploit_cves.json")
        self._meta_path = os.path.join(cache_dir, "metasploit_meta.json")
        self._cve_set: set[str] | None = None
        os.makedirs(cache_dir, exist_ok=True)

    # ---- public API ---------------------------------------------------------

    def load(self) -> set[str]:
        """Return the set of CVE IDs that have a Metasploit module.

        Strategy: fresh cache -> download -> stale cache -> empty set.
        Once loaded, the set is memoised for the lifetime of this client.
        """
        if self._cve_set is not None:
            return self._cve_set

        cached = self._read_cache()
        if cached is not None and self._is_cache_fresh():
            self._cve_set = cached
            log(f"[+] Metasploit: loaded {len(cached)} CVEs from cache")
            return self._cve_set

        downloaded = self._download()
        if downloaded is not None:
            self._cve_set = downloaded
            return self._cve_set

        if cached is not None:
            self._cve_set = cached
            log(f"[!] Metasploit: using stale cache ({len(cached)} CVEs)")
            return self._cve_set

        log("[!] Metasploit: no catalog available — module cross-reference will be empty")
        self._cve_set = set()
        return self._cve_set

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
            return {str(c).upper() for c in data if c}
        except Exception as e:
            log(f"[!] Metasploit: cache read error: {e}")
            return None

    def _download(self) -> set[str] | None:
        log("[+] Metasploit: downloading Metasploit CVE catalog…")
        try:
            resp = requests.get(METASPLOIT_CVES_URL, timeout=60)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            log(f"[!] Metasploit: download failed: {e}")
            return None

        cve_set = self._extract_cve_ids(data)
        log(f"[+] Metasploit: downloaded {len(cve_set)} CVEs")

        try:
            tmp = self._catalog_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(sorted(cve_set), f)
            os.replace(tmp, self._catalog_path)

            tmp_meta = self._meta_path + ".tmp"
            with open(tmp_meta, "w", encoding="utf-8") as f:
                json.dump({"fetched_at": int(time.time())}, f)
            os.replace(tmp_meta, self._meta_path)
        except Exception as e:
            log(f"[!] Metasploit: cache write error: {e}")

        return cve_set

    @staticmethod
    def _extract_cve_ids(data) -> set[str]:
        """Extract CVE ids from the export's `cves` collection.

        Live format: {"metadata": {...}, "cves": {"CVE-…": {...}, …}} — a dict
        keyed by CVE id. A bare list or a top-level list is also tolerated. Each
        candidate is validated against the CVE id pattern.
        """
        cves = data.get("cves") if isinstance(data, dict) else data
        if isinstance(cves, dict):
            candidates = cves.keys()
        elif isinstance(cves, list):
            candidates = cves
        else:
            candidates = []
        return {c.upper() for c in candidates if isinstance(c, str) and _CVE_ID_RE.match(c)}
