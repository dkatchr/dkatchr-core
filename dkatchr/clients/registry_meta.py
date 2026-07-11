"""
Registry metadata client — "does this package name exist on the PUBLIC
registry, and what does it look like there?"

WHY: The dependency-confusion pass needs one authoritative answer per
candidate name: exists / created when / latest version / download volume.
This is the single seam for all public-registry metadata lookups (one seam
per external system) — the detection logic in dkatchr/core/confusion.py is
pure and receives get_package_meta as an injected callable.

Coverage v1: npm, PyPI, crates.io, RubyGems, Packagist. Go, Maven and NuGet
have different confusion models (module paths / group IDs / reserved
prefixes) and are deferred — SUPPORTED_ECOSYSTEMS is the source of truth.

Behavior contract (mirrors KEV/EPSS fail-safe posture):
  - get_package_meta() NEVER raises. Any fetch failure → None (log + the
    caller skips that candidate). One candidate's failure never kills a pass.
  - 404 is a VALID answer, cached as {"exists": False} — an unclaimed name is
    exactly what the caller needs to know.
  - The file cache at {cache_dir}/ is TTL'd (DEFAULT_REGISTRY_META_TTL,
    default 7 days), NOT permanent: a squat can appear tomorrow, and a 404
    cached as exists=false can become a claimed name.
  - Every request carries DKATCHR_USER_AGENT and goes through a per-registry
    TokenBucket. crates.io's policy is a HARD 1 req/s + mandatory identifying
    UA — respected via REGISTRY_META_RPS.

What this module does NOT do: no detection logic, no suspicion thresholds,
no DB access. It returns raw facts; core/confusion.py interprets them.
"""

import json
import os
import re
import time
import urllib.parse

import requests

from dkatchr.clients.ratelimit import TokenBucket
from dkatchr.config import (
    CRATESIO_META_URL,
    DEFAULT_REGISTRY_META_TTL,
    DKATCHR_USER_AGENT,
    NPM_DOWNLOADS_URL,
    NPM_REGISTRY_META_URL,
    PACKAGIST_DOWNLOADS_URL,
    PACKAGIST_META_URL,
    PYPI_META_URL,
    REGISTRY_META_RPS,
    REGISTRY_META_TIMEOUT,
    RUBYGEMS_META_URL,
    RUBYGEMS_VERSIONS_URL,
)
from dkatchr.logger import log

# Bumped when the cached value shape changes; old files fail validation and
# are treated as misses (same convention as the other shape-validated caches).
_CACHE_SCHEMA = 1

_NOT_FOUND = {"exists": False, "created_at": None, "latest_version": None, "downloads": None}


def _pep503(name: str) -> str:
    """PEP 503 name normalization — PyPI treats Foo_Bar / foo.bar / foo-bar
    as the same project; lookups must use the normalized form."""
    return re.sub(r"[-_.]+", "-", name).lower()


class RegistryMetaClient:
    SUPPORTED_ECOSYSTEMS = frozenset({"npm", "PyPI", "crates.io", "RubyGems", "Packagist"})

    def __init__(self, cache_dir: str,
                 ttl_seconds: int = DEFAULT_REGISTRY_META_TTL) -> None:
        self.cache_dir = cache_dir
        self.ttl = int(ttl_seconds)
        os.makedirs(cache_dir, exist_ok=True)
        self._buckets = {
            eco: TokenBucket(rate=rps, capacity=max(1.0, rps))
            for eco, rps in REGISTRY_META_RPS.items()
        }
        self._session = requests.Session()
        self._session.headers["User-Agent"] = DKATCHR_USER_AGENT

    # ---- public API ---------------------------------------------------------

    def get_package_meta(self, ecosystem: str, name: str) -> dict | None:
        """Public-registry metadata for (ecosystem, name).

        Returns {"exists": bool, "created_at": str|None,
                 "latest_version": str|None, "downloads": int|None},
        or None when the ecosystem is unsupported or the lookup failed
        (network error, non-404 HTTP error). Never raises.
        """
        if ecosystem not in self.SUPPORTED_ECOSYSTEMS or not name:
            return None
        if ecosystem == "PyPI":
            name = _pep503(name)

        cached = self._cache_read(ecosystem, name)
        if cached is not None:
            return cached

        try:
            meta = self._fetch(ecosystem, name)
        except Exception as e:
            log(f"[!] registry_meta: {ecosystem}/{name}: {e} — candidate skipped")
            return None
        if meta is not None:
            self._cache_write(ecosystem, name, meta)
        return meta

    # ---- fetch dispatch -----------------------------------------------------

    def _get(self, ecosystem: str, url: str) -> requests.Response:
        """Rate-limited GET. Raises on transport errors; the caller decides
        what each status code means (404 is a valid answer, not an error)."""
        self._buckets[ecosystem].acquire()
        return self._session.get(url, timeout=REGISTRY_META_TIMEOUT)

    def _fetch(self, ecosystem: str, name: str) -> dict | None:
        if ecosystem == "npm":
            return self._fetch_npm(name)
        if ecosystem == "PyPI":
            return self._fetch_pypi(name)
        if ecosystem == "crates.io":
            return self._fetch_crates(name)
        if ecosystem == "RubyGems":
            return self._fetch_rubygems(name)
        if ecosystem == "Packagist":
            return self._fetch_packagist(name)
        return None

    def _fetch_npm(self, name: str) -> dict | None:
        # Scoped names need the / encoded: @scope/pkg → @scope%2Fpkg.
        quoted = urllib.parse.quote(name, safe="@")
        resp = self._get("npm", NPM_REGISTRY_META_URL.format(package=quoted))
        if resp.status_code == 404:
            return dict(_NOT_FOUND)
        resp.raise_for_status()
        data = resp.json()
        downloads = None
        try:
            dl = self._get("npm", NPM_DOWNLOADS_URL.format(package=quoted))
            if dl.status_code == 200:
                downloads = dl.json().get("downloads")
        except Exception as e:
            log(f"[!] registry_meta: npm downloads for {name}: {e} — downloads unknown")
        return {
            "exists": True,
            "created_at": (data.get("time") or {}).get("created"),
            "latest_version": (data.get("dist-tags") or {}).get("latest"),
            "downloads": downloads if isinstance(downloads, int) else None,
        }

    def _fetch_pypi(self, name: str) -> dict | None:
        resp = self._get("PyPI", PYPI_META_URL.format(package=name))
        if resp.status_code == 404:
            return dict(_NOT_FOUND)
        resp.raise_for_status()
        data = resp.json()
        # Project creation ≈ earliest upload across all releases. PyPI's JSON
        # download counts are deprecated (always -1) and pypistats is
        # deliberately NOT called — downloads stays None for PyPI (v1 limit).
        upload_times = [
            f.get("upload_time_iso_8601")
            for files in (data.get("releases") or {}).values()
            for f in (files or [])
            if isinstance(f, dict) and f.get("upload_time_iso_8601")
        ]
        return {
            "exists": True,
            "created_at": min(upload_times) if upload_times else None,
            "latest_version": (data.get("info") or {}).get("version"),
            "downloads": None,
        }

    def _fetch_crates(self, name: str) -> dict | None:
        resp = self._get("crates.io", CRATESIO_META_URL.format(package=name))
        if resp.status_code == 404:
            return dict(_NOT_FOUND)
        resp.raise_for_status()
        crate = (resp.json().get("crate") or {})
        downloads = crate.get("downloads")
        return {
            "exists": True,
            "created_at": crate.get("created_at"),
            "latest_version": crate.get("newest_version") or crate.get("max_version"),
            "downloads": downloads if isinstance(downloads, int) else None,
        }

    def _fetch_rubygems(self, name: str) -> dict | None:
        resp = self._get("RubyGems", RUBYGEMS_META_URL.format(package=name))
        if resp.status_code == 404:
            return dict(_NOT_FOUND)
        resp.raise_for_status()
        data = resp.json()
        # The gems endpoint has no gem-level creation date (version_created_at
        # is the LATEST version's date — wrong signal for an old gem with a
        # fresh release). Earliest version date comes from the versions
        # endpoint, best-effort.
        created_at = None
        try:
            vresp = self._get("RubyGems", RUBYGEMS_VERSIONS_URL.format(package=name))
            if vresp.status_code == 200:
                times = [v.get("created_at") for v in vresp.json()
                         if isinstance(v, dict) and v.get("created_at")]
                created_at = min(times) if times else None
        except Exception as e:
            log(f"[!] registry_meta: rubygems versions for {name}: {e} — created_at unknown")
        downloads = data.get("downloads")
        return {
            "exists": True,
            "created_at": created_at,
            "latest_version": data.get("version"),
            "downloads": downloads if isinstance(downloads, int) else None,
        }

    def _fetch_packagist(self, name: str) -> dict | None:
        # Composer package names are always vendor/package — a name without a
        # slash cannot be claimed on Packagist at all.
        if "/" not in name:
            return dict(_NOT_FOUND)
        resp = self._get("Packagist", PACKAGIST_META_URL.format(package=name))
        if resp.status_code == 404:
            return dict(_NOT_FOUND)
        resp.raise_for_status()
        versions = ((resp.json().get("packages") or {}).get(name) or [])
        versions = [v for v in versions if isinstance(v, dict)]
        times = [v.get("time") for v in versions if v.get("time")]
        downloads = None
        try:
            dl = self._get("Packagist", PACKAGIST_DOWNLOADS_URL.format(package=name))
            if dl.status_code == 200:
                total = ((dl.json().get("package") or {}).get("downloads") or {}).get("total")
                downloads = total if isinstance(total, int) else None
        except Exception as e:
            log(f"[!] registry_meta: packagist downloads for {name}: {e} — downloads unknown")
        return {
            "exists": True,
            "created_at": min(times) if times else None,
            # p2 lists versions newest-first.
            "latest_version": versions[0].get("version") if versions else None,
            "downloads": downloads,
        }

    # ---- TTL'd file cache ---------------------------------------------------

    def _cache_path(self, ecosystem: str, name: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9._@-]", "_", f"{ecosystem}__{name}")
        return os.path.join(self.cache_dir, f"{safe}.json")

    def _cache_read(self, ecosystem: str, name: str) -> dict | None:
        path = self._cache_path(ecosystem, name)
        if not os.path.exists(path):
            return None
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return None
        if (not isinstance(data, dict)
                or data.get("schema") != _CACHE_SCHEMA
                or not isinstance(data.get("meta"), dict)
                or "exists" not in data["meta"]):
            return None
        if time.time() - data.get("fetched_at", 0) >= self.ttl:
            return None
        return data["meta"]

    def _cache_write(self, ecosystem: str, name: str, meta: dict) -> None:
        path = self._cache_path(ecosystem, name)
        try:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"schema": _CACHE_SCHEMA,
                           "fetched_at": int(time.time()),
                           "meta": meta}, f)
            os.replace(tmp, path)
        except Exception as e:
            log(f"[!] registry_meta: cache write for {ecosystem}/{name}: {e}")
