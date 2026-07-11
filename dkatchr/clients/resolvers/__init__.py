"""
ImportNameResolver — registry-driven import name resolution.

WHY: Reachability scanning needs the importable name(s) of every vulnerable
package so the Aho-Corasick automaton has the right strings to search for.
Install name and import name diverge across most ecosystems
(`beautifulsoup4` → `bs4`, `org.springframework:spring-web` → many Java
packages, `omniauth-oauth2` → `OmniAuth::OAuth2`, etc). Hardcoded override
maps rot silently; we instead query the package registry at scan time and
cache the answer.

Cache layout: ``{cache_dir}/registry/{ecosystem}__{package}.json``
keyed on (ecosystem, package_name) only — import names are version-stable
in practice.

On resolution failure we do NOT write a cache entry (next scan retries) and
``resolve_batch`` returns an empty list for that pair so callers emit
UNKNOWN. Never returning a guess on failure is intentional — emitting
UNUSED on a package whose import name we could not resolve would be
a silent false negative on a potentially-vulnerable dependency.

Does NOT: know about reachability, Aho-Corasick, or vulnerability rows. It
maps (package, ecosystem) → importable names. Callers are responsible for
turning those into language-specific search patterns.
"""

import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Callable

from dkatchr.clients.resolvers._base import RegistryResolverBase
from dkatchr.clients.resolvers.crates import CratesResolver
from dkatchr.clients.resolvers.maven import MavenResolver
from dkatchr.clients.resolvers.nuget import NuGetResolver
from dkatchr.clients.resolvers.packagist import PackagistResolver
from dkatchr.clients.resolvers.pypi import PyPIResolver
from dkatchr.clients.resolvers.rubygems import RubyGemsResolver
from dkatchr.config import (
    REGISTRY_RESOLVER_CACHE_SCHEMA,
    REGISTRY_RESOLVER_WORKERS,
)
from dkatchr.logger import log

ProgressCb = Callable[[dict], None] | None


# Ecosystems that need NO registry call. The package name IS the import name.
_DIRECT_ECOSYSTEMS: frozenset[str] = frozenset({"go", "npm"})


def _normalize_ecosystem(eco: str) -> str:
    """Lowercase + collapse common synonyms used in OSV / scanner output."""
    e = (eco or "").strip().lower()
    if e in ("rubygems", "rubygem", "gem", "gems"):
        return "rubygems"
    if e in ("crates.io", "cargo", "crates"):
        return "crates.io"
    if e in ("composer", "packagist"):
        return "packagist"
    return e


class ImportNameResolver:
    """
    Resolves package install names → importable names by querying registries.
    Cached by (ecosystem, package_name) in ``{cache_dir}/registry/``.
    Thread-safe. Resolves batches concurrently via ThreadPoolExecutor.
    """

    SCHEMA = REGISTRY_RESOLVER_CACHE_SCHEMA

    def __init__(
        self,
        cache_dir: str,
        max_workers: int = REGISTRY_RESOLVER_WORKERS,
    ) -> None:
        self.cache_dir = os.path.join(cache_dir, "registry")
        os.makedirs(self.cache_dir, exist_ok=True)
        self.max_workers = max(1, int(max_workers))

        # One instance per resolver — they hold no per-call state, so this
        # is fine and saves the per-request allocation cost.
        self._resolvers: dict[str, RegistryResolverBase] = {
            "pypi":      PyPIResolver(),
            "rubygems":  RubyGemsResolver(),
            "maven":     MavenResolver(),
            "nuget":     NuGetResolver(),
            "packagist": PackagistResolver(),
            "crates.io": CratesResolver(),
        }

        # Serialize cache writes per (eco, package). Reads are fine without
        # locking — atomic os.replace is used on writes.
        self._lock = threading.Lock()

    # ---- public API ----------------------------------------------------

    def resolve_batch(
        self,
        pairs: list[tuple[str, str]],
        on_progress: ProgressCb = None,
        versions: dict[tuple[str, str], str] | None = None,
    ) -> dict[tuple[str, str], list[str]]:
        """
        Resolve all (package, ecosystem) pairs concurrently.

        Returns ``{(package, ecosystem): [import_name, ...]}``. Failed
        resolutions map to an empty list — caller emits UNKNOWN for these.

        ``versions`` optionally maps a pair to a specific package version,
        used by resolvers that require the version to construct an artifact
        URL (Maven especially). When absent, resolvers either query their
        registry for the latest version or short-circuit.
        """
        # Dedupe and normalize.
        unique: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for package, ecosystem in pairs:
            key = (package, _normalize_ecosystem(ecosystem))
            if key in seen or not package:
                continue
            seen.add(key)
            unique.append(key)

        total = len(unique)
        results: dict[tuple[str, str], list[str]] = {}
        cached_count = 0
        resolved_count = 0
        failed_count = 0

        _emit(on_progress, {"phase": "resolving_start", "total": total})

        # First pass — drain cache hits and direct-ecosystem short-circuits
        # synchronously, so we only spawn worker threads for real work.
        remaining_work: list[tuple[str, str]] = []
        for package, ecosystem in unique:
            # Direct short-circuit: go / npm.
            if ecosystem in _DIRECT_ECOSYSTEMS:
                names = [package]  # `@org/pkg` is returned as-is
                results[(package, ecosystem)] = names
                _emit(on_progress, {
                    "phase":     "resolved",
                    "package":   package,
                    "ecosystem": ecosystem,
                    "names":     names,
                    "source":    "package_name_direct",
                })
                resolved_count += 1
                continue

            cached = self._cache_read(package, ecosystem)
            if cached is not None:
                results[(package, ecosystem)] = cached
                _emit(on_progress, {
                    "phase":     "cache_hit",
                    "package":   package,
                    "ecosystem": ecosystem,
                })
                cached_count += 1
                continue

            remaining_work.append((package, ecosystem))

        # Second pass — resolve uncached pairs concurrently.
        if remaining_work:
            # Callers pass `versions` keyed on the OSV-vocabulary ecosystem
            # ("Maven", "NuGet", "PyPI", ...) — same shape they got rows in.
            # `remaining_work` is keyed on the normalized form ("maven", ...).
            # Without re-keying, every Maven lookup misses and the maven
            # resolver bails with "version required". Normalize once here so
            # the lookup matches regardless of input case/aliases.
            versions_normalized: dict[tuple[str, str], str] = {}
            for (vp, ve), vv in (versions or {}).items():
                versions_normalized[(vp, _normalize_ecosystem(ve))] = vv
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                future_to_pair = {
                    pool.submit(
                        self._resolve_one,
                        package,
                        ecosystem,
                        versions_normalized.get((package, ecosystem)),
                    ): (package, ecosystem)
                    for (package, ecosystem) in remaining_work
                }

                remaining_count = len(future_to_pair)
                for future in as_completed(future_to_pair):
                    package, ecosystem = future_to_pair[future]
                    remaining_count -= 1
                    _emit(on_progress, {
                        "phase":     "resolving_package",
                        "package":   package,
                        "ecosystem": ecosystem,
                        "remaining": remaining_count,
                    })

                    try:
                        outcome = future.result()
                    except Exception as e:
                        outcome = None
                        log(f"[resolver] {ecosystem}/{package}: parse error — {e}")

                    if outcome is None:
                        results[(package, ecosystem)] = []
                        failed_count += 1
                        _emit(on_progress, {
                            "phase":     "resolution_failed",
                            "package":   package,
                            "ecosystem": ecosystem,
                            "reason":    "see log",
                        })
                        continue

                    names, source = outcome
                    # Defensive: never let an empty result reach the cache.
                    cleaned = [n for n in (names or []) if isinstance(n, str) and n]
                    if not cleaned:
                        results[(package, ecosystem)] = []
                        failed_count += 1
                        _emit(on_progress, {
                            "phase":     "resolution_failed",
                            "package":   package,
                            "ecosystem": ecosystem,
                            "reason":    "empty result",
                        })
                        continue

                    results[(package, ecosystem)] = cleaned
                    self._cache_write(package, ecosystem, cleaned, source)
                    resolved_count += 1
                    _emit(on_progress, {
                        "phase":     "resolved",
                        "package":   package,
                        "ecosystem": ecosystem,
                        "names":     cleaned,
                        "source":    source,
                    })

        _emit(on_progress, {
            "phase":    "resolving_done",
            "resolved": resolved_count,
            "failed":   failed_count,
            "cached":   cached_count,
        })

        # Return results keyed by the original (un-normalized) ecosystem
        # strings as well, so callers built against the OSV vocabulary see
        # what they passed in.
        normalized_results = dict(results)
        for package, ecosystem in pairs:
            norm_key = (package, _normalize_ecosystem(ecosystem))
            if norm_key in normalized_results:
                normalized_results[(package, ecosystem)] = normalized_results[norm_key]
        return normalized_results

    # ---- internals -----------------------------------------------------

    def _resolve_one(
        self,
        package: str,
        ecosystem: str,
        version: str | None,
    ) -> tuple[list[str], str] | None:
        resolver = self._resolvers.get(ecosystem)
        if resolver is None:
            log(f"[resolver] {ecosystem}/{package}: parse error — no resolver for ecosystem")
            return None
        return resolver.resolve(package, version)

    def _cache_path(self, package: str, ecosystem: str) -> str:
        safe_pkg = re.sub(r"[^A-Za-z0-9._@/+-]", "_", package).replace("/", "__")
        safe_eco = re.sub(r"[^A-Za-z0-9._-]", "_", ecosystem)
        return os.path.join(self.cache_dir, f"{safe_eco}__{safe_pkg}.json")

    def _cache_read(self, package: str, ecosystem: str) -> list[str] | None:
        path = self._cache_path(package, ecosystem)
        if not os.path.exists(path):
            return None
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return None
        if not isinstance(data, dict) or data.get("schema") != self.SCHEMA:
            return None
        names = data.get("import_names")
        if not isinstance(names, list):
            return None
        cleaned = [n for n in names if isinstance(n, str) and n]
        return cleaned or None

    def _cache_write(
        self,
        package: str,
        ecosystem: str,
        names: list[str],
        source: str,
    ) -> None:
        if not names:
            return
        payload = {
            "schema":       self.SCHEMA,
            "ecosystem":    ecosystem,
            "package":      package,
            "import_names": names,
            "source":       source,
            "resolved_at":  datetime.now(timezone.utc).isoformat(),
        }
        path = self._cache_path(package, ecosystem)
        tmp = path + ".tmp"
        try:
            with self._lock:
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(payload, f)
                os.replace(tmp, path)
        except Exception as e:
            log(f"[resolver] {ecosystem}/{package}: cache write failed — {e}")
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass


def _emit(cb: ProgressCb, payload: dict) -> None:
    if cb is None:
        return
    try:
        cb(payload)
    except Exception:
        pass
