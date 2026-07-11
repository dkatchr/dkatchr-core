"""
Packagist (Composer) namespace resolver.

WHY: PHP namespaces follow PSR-4/PSR-0 mappings declared in `composer.json`
under `autoload`. The package's own `composer.json` is authoritative — the
namespace `Symfony\Component\Console\` is what user code writes as
`use Symfony\Component\Console\Application;`.

Does NOT: follow `autoload-dev` (test-only namespaces), inspect dependency
graphs, or fall back to classmap unless psr-4/psr-0 are absent.
"""

import io
import json
import zipfile

from dkatchr.clients.resolvers._base import RegistryResolverBase
from dkatchr.logger import log

_PACKAGIST_API = "https://packagist.org/packages/{vendor}/{name}.json"


class PackagistResolver(RegistryResolverBase):
    ECOSYSTEM = "packagist"

    def resolve(
        self, package: str, version: str | None = None
    ) -> tuple[list[str], str] | None:
        if "/" not in package:
            log(f"[resolver] packagist/{package}: parse error — expected 'vendor/name'")
            return None
        vendor, name = package.split("/", 1)
        if not vendor or not name:
            log(f"[resolver] packagist/{package}: parse error — empty vendor or name")
            return None

        api_url = _PACKAGIST_API.format(vendor=vendor, name=name)
        data = self._get_json(api_url, package)
        if not isinstance(data, dict):
            return None

        pkg = data.get("package")
        if not isinstance(pkg, dict):
            log(f"[resolver] packagist/{package}: unexpected response from {api_url} — missing package")
            return None

        versions = pkg.get("versions")
        if not isinstance(versions, dict) or not versions:
            log(f"[resolver] packagist/{package}: unexpected response from {api_url} — no versions")
            return None

        entry = _pick_latest_stable(versions)
        if entry is None:
            log(f"[resolver] packagist/{package}: parse error — no stable version with dist.url")
            return None

        dist = entry.get("dist") or {}
        dist_url = dist.get("url") if isinstance(dist, dict) else None
        if not isinstance(dist_url, str) or not dist_url:
            log(f"[resolver] packagist/{package}: parse error — version entry missing dist.url")
            return None

        blob = self._download_bytes(dist_url, package)
        if blob is None:
            return None

        try:
            zf = zipfile.ZipFile(io.BytesIO(blob))
        except zipfile.BadZipFile as e:
            log(f"[resolver] packagist/{package}: parse error — bad dist zip: {e}")
            return None

        with zf:
            composer_entry = _find_root_composer(zf)
            if composer_entry is None:
                log(f"[resolver] packagist/{package}: parse error — no composer.json in dist")
                return None

            try:
                raw = zf.read(composer_entry).decode("utf-8", errors="ignore")
                composer = json.loads(raw)
            except (KeyError, ValueError) as e:
                log(f"[resolver] packagist/{package}: parse error — composer.json: {e}")
                return None

        autoload = composer.get("autoload") if isinstance(composer, dict) else None
        if not isinstance(autoload, dict):
            log(f"[resolver] packagist/{package}: parse error — composer.json has no autoload")
            return None

        namespaces: list[str] = []
        for section_key in ("psr-4", "psr-0"):
            section = autoload.get(section_key)
            if isinstance(section, dict):
                for ns in section.keys():
                    if isinstance(ns, str):
                        clean = ns.rstrip("\\")
                        if clean:
                            namespaces.append(clean)

        if not namespaces:
            classmap = autoload.get("classmap")
            if isinstance(classmap, list):
                # We have no path-to-namespace evidence from a classmap alone.
                # Skip and return None — the spec is explicit: only fall back
                # if psr-4 and psr-0 are both absent, AND there is something
                # usable. Without parsing the .php files in the classmap, we
                # cannot produce a reliable namespace, so emit UNKNOWN.
                log(f"[resolver] packagist/{package}: parse error — classmap-only autoload not supported")
                return None
            log(f"[resolver] packagist/{package}: parse error — empty autoload section")
            return None

        # Dedupe while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for ns in namespaces:
            if ns not in seen:
                seen.add(ns)
                unique.append(ns)

        return unique, "composer_autoload"


def _pick_latest_stable(versions: dict) -> dict | None:
    """Return the version entry that looks like the latest stable release."""
    # Packagist returns versions keyed by version string. Prefer entries that
    # do NOT contain '-dev', '-alpha', '-beta', '-rc'. Return the one whose
    # `time` field is the most recent.
    stable_entries: list[dict] = []
    for key, entry in versions.items():
        if not isinstance(key, str) or not isinstance(entry, dict):
            continue
        lk = key.lower()
        if "-dev" in lk or "alpha" in lk or "beta" in lk or "rc" in lk or lk.endswith("-patch"):
            continue
        stable_entries.append(entry)

    if not stable_entries:
        # Fall back to any version entry rather than failing outright.
        for entry in versions.values():
            if isinstance(entry, dict):
                stable_entries.append(entry)

    if not stable_entries:
        return None

    stable_entries.sort(key=lambda e: e.get("time") or "", reverse=True)
    return stable_entries[0]


def _find_root_composer(zf: zipfile.ZipFile) -> str | None:
    """Composer zips wrap content in a top-level directory. Find composer.json at depth 1."""
    candidates: list[str] = []
    for name in zf.namelist():
        if name.endswith("/composer.json") or name == "composer.json":
            # Depth 1 (e.g. `foo-abc1234/composer.json`) is the canonical place.
            depth = name.count("/")
            if depth <= 1:
                candidates.append(name)
    if not candidates:
        return None
    candidates.sort(key=lambda n: n.count("/"))
    return candidates[0]
