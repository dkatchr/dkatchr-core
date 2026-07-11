"""
Top-packages feed client — "what are the most-downloaded public packages on
this ecosystem's registry?"

WHY: The typosquatting pass needs a ranked set of popular package names per
ecosystem to measure edit-distance against — an attacker registers "reqeusts"
hoping someone typos the top package "requests". This is the single seam for
all top-package-ranking feeds (one seam per external system); the detection
logic in dkatchr/core/typosquat.py is pure and receives the fetched sets plus
an injected registry-metadata lookup (RegistryMetaClient, reused — the typosquat
pass adds NO second registry client).

Coverage v1: npm, PyPI, crates.io, RubyGems, Packagist — EXACTLY mirroring
RegistryMetaClient.SUPPORTED_ECOSYSTEMS, because the typosquat pass's metadata
gate is mandatory and only those five can be gated. Go and Maven have no public
download rankings anywhere. NuGet's v3 search API CAN rank by totalDownloads,
but RegistryMetaClient does not cover NuGet, so a NuGet candidate could never
pass the mandatory metadata gate — NuGet is therefore deferred until that client
gains NuGet support (see CLAUDE.md). SUPPORTED_ECOSYSTEMS is the source of truth.

Per-ecosystem feed reality (see CLAUDE.md Known limitations):
  - PyPI: hugovk/top-pypi-packages, ~15k names, already download-ranked.
  - crates.io: official API, download-sorted, paginated — goes through the HARD
    1 req/s TokenBucket + DKATCHR_USER_AGENT (same policy as registry_meta).
  - Packagist: popular-packages explorer, paginated.
  - RubyGems: the official "most downloaded" endpoint — ONLY ~top 50 (near-zero
    coverage; documented, included for completeness).
  - npm: NO official ranking feed. Community-maintained npm-high-impact list,
    freshness-gated (rejected if older than TOP_PACKAGES_MAX_AGE_DAYS).

Behavior contract (mirrors KEV/EPSS/registry_meta fail-safe posture):
  - get_top() NEVER raises. Any fetch failure → empty list (log + that
    ecosystem's typosquat check is skipped). One feed failure never kills a scan.
  - The file cache at {cache_dir}/ is TTL'd (DEFAULT_TOP_PACKAGES_TTL, default
    7 days), NOT permanent: the top-N set shifts over time.
  - crates.io / Packagist pagination is rate-limited per registry.

What this module does NOT do: no detection logic, no edit-distance, no DB
access, NO vendored/committed name lists (the "no static data maps" rule — the
lists are always fetched + cached). It returns raw ranked names; the core
normalizes and interprets them.
"""

import json
import math
import os
import re
import time
from datetime import datetime, timezone
from typing import Callable

import requests

from dkatchr.clients.ratelimit import TokenBucket
from dkatchr.config import (
    DEFAULT_TOP_PACKAGES_TTL,
    DKATCHR_USER_AGENT,
    REGISTRY_META_RPS,
    TOP_PACKAGES_COUNT,
    TOP_PACKAGES_CRATES_URL,
    TOP_PACKAGES_MAX_AGE_DAYS,
    TOP_PACKAGES_NPM_DATA_URL,
    TOP_PACKAGES_NPM_REGISTRY_URL,
    TOP_PACKAGES_PACKAGIST_URL,
    TOP_PACKAGES_PYPI_URL,
    TOP_PACKAGES_RUBYGEMS_URL,
    TOP_PACKAGES_TIMEOUT,
)
from dkatchr.logger import log

# Bumped when the cached value shape changes; old files fail validation and are
# treated as misses (same convention as the other shape-validated caches).
_CACHE_SCHEMA = 1

# Callback signature: progress({"phase": "top_packages_fetch", "ecosystem",
# "fetched"}). Emit failures are swallowed — progress must never break the work.
ProgressCb = Callable[[dict], None] | None

# npm-high-impact's data file is `export const topDownload = ['a', 'b', ...]`.
# npm package names never contain a single quote, so every quoted token is a name.
_NPM_NAME_RE = re.compile(r"'([^']+)'")


class TopPackagesClient:
    SUPPORTED_ECOSYSTEMS = frozenset({"npm", "PyPI", "crates.io", "RubyGems", "Packagist"})

    def __init__(self, cache_dir: str,
                 ttl_seconds: int = DEFAULT_TOP_PACKAGES_TTL,
                 count: int = TOP_PACKAGES_COUNT,
                 max_age_days: int = TOP_PACKAGES_MAX_AGE_DAYS) -> None:
        self.cache_dir = cache_dir
        self.ttl = int(ttl_seconds)
        self.count = int(count)
        self.max_age_days = int(max_age_days)
        os.makedirs(cache_dir, exist_ok=True)
        # Per-registry TokenBucket for the paginated feeds. crates.io's policy is
        # a HARD 1 req/s (REGISTRY_META_RPS) — reused so the whole codebase shares
        # one crates.io rate policy.
        self._buckets = {
            eco: TokenBucket(rate=rps, capacity=max(1.0, rps))
            for eco, rps in REGISTRY_META_RPS.items()
        }
        self._session = requests.Session()
        self._session.headers["User-Agent"] = DKATCHR_USER_AGENT
        self._memo: dict[str, list[str]] = {}

    # ---- public API ---------------------------------------------------------

    def get_top(self, ecosystem: str, on_progress: ProgressCb = None) -> list[str]:
        """Ranked list (highest downloads first) of up to `count` top package
        names for `ecosystem`, or [] when the ecosystem is unsupported or the
        feed could not be fetched. Never raises. Memoised for the client's life.
        """
        if ecosystem not in self.SUPPORTED_ECOSYSTEMS:
            return []
        if ecosystem in self._memo:
            return self._memo[ecosystem]

        cached = self._cache_read(ecosystem)
        if cached is not None:
            self._memo[ecosystem] = cached
            log(f"[+] top_packages: loaded {len(cached)} {ecosystem} names from cache")
            return cached

        try:
            names = self._fetch(ecosystem, on_progress)
        except Exception as e:
            log(f"[!] top_packages: {ecosystem} feed failed: {e} — "
                f"typosquat check skipped for this ecosystem")
            names = []

        if names:
            self._cache_write(ecosystem, names)
        self._memo[ecosystem] = names
        return names

    # ---- fetch dispatch -----------------------------------------------------

    def _emit(self, on_progress: ProgressCb, ecosystem: str, fetched: int) -> None:
        if not on_progress:
            return
        try:
            on_progress({"phase": "top_packages_fetch",
                         "ecosystem": ecosystem, "fetched": fetched})
        except Exception:
            pass  # progress emit failures must never break the work

    def _fetch(self, ecosystem: str, on_progress: ProgressCb) -> list[str]:
        if ecosystem == "PyPI":
            return self._fetch_pypi(on_progress)
        if ecosystem == "crates.io":
            return self._fetch_crates(on_progress)
        if ecosystem == "Packagist":
            return self._fetch_packagist(on_progress)
        if ecosystem == "RubyGems":
            return self._fetch_rubygems(on_progress)
        if ecosystem == "npm":
            return self._fetch_npm(on_progress)
        return []

    def _get(self, url: str, ecosystem: str | None = None) -> requests.Response:
        """Rate-limited GET (bucket applied only for paginated registry feeds)."""
        if ecosystem and ecosystem in self._buckets:
            self._buckets[ecosystem].acquire()
        return self._session.get(url, timeout=TOP_PACKAGES_TIMEOUT)

    def _fetch_pypi(self, on_progress: ProgressCb) -> list[str]:
        resp = self._get(TOP_PACKAGES_PYPI_URL)
        resp.raise_for_status()
        rows = resp.json().get("rows") or []
        names = [r["project"] for r in rows
                 if isinstance(r, dict) and r.get("project")][: self.count]
        self._emit(on_progress, "PyPI", len(names))
        log(f"[+] top_packages: fetched {len(names)} PyPI names")
        return names

    def _fetch_crates(self, on_progress: ProgressCb) -> list[str]:
        names: list[str] = []
        pages = math.ceil(self.count / 100)
        for page in range(1, pages + 1):
            resp = self._get(TOP_PACKAGES_CRATES_URL.format(page=page), ecosystem="crates.io")
            resp.raise_for_status()
            crates = resp.json().get("crates") or []
            if not crates:
                break
            names.extend(c["name"] for c in crates
                         if isinstance(c, dict) and c.get("name"))
            self._emit(on_progress, "crates.io", len(names))
            if len(names) >= self.count:
                break
        names = names[: self.count]
        log(f"[+] top_packages: fetched {len(names)} crates.io names")
        return names

    def _fetch_packagist(self, on_progress: ProgressCb) -> list[str]:
        names: list[str] = []
        pages = math.ceil(self.count / 100)
        for page in range(1, pages + 1):
            resp = self._get(TOP_PACKAGES_PACKAGIST_URL.format(page=page), ecosystem="Packagist")
            resp.raise_for_status()
            packages = resp.json().get("packages") or []
            if not packages:
                break
            names.extend(p["name"] for p in packages
                         if isinstance(p, dict) and p.get("name"))
            self._emit(on_progress, "Packagist", len(names))
            if len(names) >= self.count:
                break
        names = names[: self.count]
        log(f"[+] top_packages: fetched {len(names)} Packagist names")
        return names

    def _fetch_rubygems(self, on_progress: ProgressCb) -> list[str]:
        # The "most downloaded" endpoint returns ~top 50 as [[gem_dict, count], …].
        # RubyGems omits a bare `name` here, so derive it from full_name + number
        # ("nokogiri-1.16.0-x86_64-linux" split on "-1.16.0" → "nokogiri").
        resp = self._get(TOP_PACKAGES_RUBYGEMS_URL)
        resp.raise_for_status()
        gems = resp.json().get("gems") or []
        names: list[str] = []
        for entry in gems:
            gem = entry[0] if isinstance(entry, (list, tuple)) and entry else entry
            if not isinstance(gem, dict):
                continue
            full = gem.get("full_name") or ""
            num = gem.get("number") or ""
            name = full.split(f"-{num}")[0] if (num and f"-{num}" in full) else (gem.get("name") or full)
            if name:
                names.append(name)
        names = names[: self.count]
        self._emit(on_progress, "RubyGems", len(names))
        log(f"[+] top_packages: fetched {len(names)} RubyGems names (near-zero coverage by design)")
        return names

    def _fetch_npm(self, on_progress: ProgressCb) -> list[str]:
        # No official ranking feed — use npm-high-impact's published download
        # list, but only if it's fresh (freshness-gated per the spec).
        meta = self._get(TOP_PACKAGES_NPM_REGISTRY_URL).json()
        latest = ((meta.get("dist-tags") or {}).get("latest"))
        if not latest:
            log("[!] top_packages: npm-high-impact has no latest version — npm skipped")
            return []
        times = meta.get("time") or {}
        published = self._parse_iso(times.get(latest) or times.get("modified"))
        if published is not None:
            age_days = (datetime.now(timezone.utc) - published).days
            if age_days > self.max_age_days:
                log(f"[!] top_packages: npm feed (npm-high-impact@{latest}) is {age_days}d old "
                    f"(> {self.max_age_days}d) — npm typosquat check skipped")
                return []
        # Age unknown (unparseable timestamp) → proceed with the best available.
        resp = self._get(TOP_PACKAGES_NPM_DATA_URL.format(version=latest))
        resp.raise_for_status()
        names = _NPM_NAME_RE.findall(resp.text)[: self.count]
        self._emit(on_progress, "npm", len(names))
        log(f"[+] top_packages: fetched {len(names)} npm names (npm-high-impact@{latest})")
        return names

    @staticmethod
    def _parse_iso(ts: str | None) -> datetime | None:
        if not ts or not isinstance(ts, str):
            return None
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    # ---- TTL'd file cache ---------------------------------------------------

    def _cache_path(self, ecosystem: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", ecosystem)
        return os.path.join(self.cache_dir, f"{safe}.json")

    def _cache_read(self, ecosystem: str) -> list[str] | None:
        path = self._cache_path(ecosystem)
        if not os.path.exists(path):
            return None
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return None
        if (not isinstance(data, dict)
                or data.get("schema") != _CACHE_SCHEMA
                or not isinstance(data.get("names"), list)):
            return None
        if time.time() - data.get("fetched_at", 0) >= self.ttl:
            return None
        return [str(n) for n in data["names"] if n]

    def _cache_write(self, ecosystem: str, names: list[str]) -> None:
        path = self._cache_path(ecosystem)
        try:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"schema": _CACHE_SCHEMA,
                           "fetched_at": int(time.time()),
                           "names": names}, f)
            os.replace(tmp, path)
        except Exception as e:
            log(f"[!] top_packages: cache write for {ecosystem}: {e}")
