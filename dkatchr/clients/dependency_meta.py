"""
DependencyMetaClient — a package VERSION's direct dependencies, from its
registry, for manifest formats that record no dependency edges.

WHY: dependency-graph reachability needs edges. Lockfiles carry them
(`depends_on` on inventory rows); requirements.txt, Pipfile.lock and Go's
go.mod/go.sum do not. This client fills that gap from the authoritative source
— the registry's own metadata for that exact version — instead of any static
map ("no static data maps for domain knowledge").

Coverage:
  * PyPI — `Requires-Dist` from the release's WHEEL core metadata, fetched via
    PEP 658 ("<wheel-url>.metadata", a few KB) with a fallback to reading
    *.dist-info/METADATA out of the wheel itself. The release JSON's
    `info.requires_dist` is deliberately NOT used: it is None both for a
    package with no dependencies and for one that never published the
    metadata, so it cannot tell "none" from "unknown". A release with no wheel
    (sdist-only) is read from the sdist's build-time metadata instead (PKG-INFO
    Requires-Dist, else egg-info/requires.txt, else a PEP 643 static
    "no dependencies") and stays UNKNOWN only when none of those decides it. Extra- and marker-gated requirements are KEPT:
    an over-approximated edge can only over-flag, never hide a path.
  * Go — the module proxy's go.mod for that module version (`require` lines,
    // indirect included).

Return contract of get_dependencies(): a sorted list of (name, conditional)
pairs (possibly empty = "known, no dependencies"), or None = UNKNOWN
(unsupported ecosystem, sdist-only, not found, network failure). Callers must
never treat None as []. `conditional` marks a requirement that is only
installed when chosen — a PyPI `extra == …` or environment marker
(`sys_platform == 'win32'`), and every Go requirement (go.sum lists the whole
module graph, so a module missing from it is simply not in the build). The
graph drops a conditional edge whose target is not installed.

Caching: permanent per (ecosystem, package, version) at
{cache_dir}/dependency_meta/ — published metadata is immutable. Definitive
answers ([] / list / sdist-only unknown) are cached; transient failures are
NOT, so they retry next scan. Thread-safe; never raises.
"""

import hashlib
import io
import json
import os
import re
import zipfile

import requests

from dkatchr.clients.ratelimit import TokenBucket
from dkatchr.config import (
    DEPENDENCY_META_CACHE_SCHEMA,
    DEPENDENCY_META_RPS,
    DEPENDENCY_META_TIMEOUT,
    DKATCHR_USER_AGENT,
    GO_PROXY_LATEST_URL,
    GO_PROXY_MOD_URL,
    PYPI_PROJECT_JSON_URL,
    PYPI_RELEASE_JSON_URL,
)
from dkatchr.logger import log

_MAX_WHEEL_BYTES = 50 * 1024 * 1024
# Requires-Dist: name [extras] (constraints) ; markers  -> leading name
_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _go_escape(path: str) -> str:
    """Module-proxy case encoding: 'Azure' -> '!azure'."""
    return "".join("!" + c.lower() if c.isupper() else c for c in path)


def parse_requires_dist(metadata_text: str) -> list[tuple[str, bool]]:
    """(name, conditional) from every `Requires-Dist:` header of a core-metadata
    file (pure). conditional = the requirement carries a `;` marker (extra or
    environment). A name listed both ways is unconditional."""
    out: dict[str, bool] = {}
    for line in metadata_text.splitlines():
        if not line.lower().startswith("requires-dist:"):
            continue
        spec = line.split(":", 1)[1]
        m = _REQ_NAME_RE.match(spec)
        if m:
            conditional = ";" in spec
            out[m.group(1)] = out.get(m.group(1), True) and conditional
    return sorted(out.items())


def parse_go_mod_requires(go_mod_text: str) -> list[str]:
    """Module paths from a go.mod's `require` directives (pure)."""
    mods = set()
    for m in re.finditer(r"^require\s+(\S+)\s+v\S+", go_mod_text, re.MULTILINE):
        mods.add(m.group(1))
    for block in re.finditer(r"^require\s*\(([^)]*)\)", go_mod_text, re.MULTILINE | re.DOTALL):
        for line in block.group(1).splitlines():
            line = line.split("//", 1)[0].strip()
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("v"):
                mods.add(parts[0])
    return sorted(mods)


def parse_egg_requires(text: str) -> list[tuple[str, bool]]:
    """(name, conditional) from a setuptools *.egg-info/requires.txt: lines
    before any section are unconditional; `[extra]` / `[:marker]` sections are
    conditional."""
    out: set[tuple[str, bool]] = set()
    conditional = False
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            conditional = True
            continue
        m = _REQ_NAME_RE.match(line)
        if m:
            out.add((m.group(1), conditional))
    return sorted(out)


def _pep643_static_requires(pkg_info: str) -> bool:
    """True when core metadata >= 2.2 does not mark Requires-Dist as Dynamic,
    i.e. an absent Requires-Dist really means "no dependencies" (PEP 643)."""
    version, dynamic = "", set()
    for line in pkg_info.splitlines():
        if not line.strip():
            break                       # headers end at the first blank line
        key, _, val = line.partition(":")
        if key.lower() == "metadata-version":
            version = val.strip()
        elif key.lower() == "dynamic":
            dynamic.add(val.strip().lower())
    try:
        major, minor = (int(x) for x in version.split(".")[:2])
    except ValueError:
        return False
    return (major, minor) >= (2, 2) and "requires-dist" not in dynamic


def _sdist_members(blob: bytes, url: str) -> dict[str, str]:
    """Text of the metadata files inside an sdist (.tar.gz or .zip)."""
    import tarfile
    wanted = lambda n: n.endswith("/PKG-INFO") or n.endswith(".egg-info/requires.txt")
    out: dict[str, str] = {}
    # A TOP-LEVEL egg-info dir only ("pkg-1.0/pkg.egg-info/..."); a vendored
    # package's egg-info deeper in the tree says nothing about this one.
    egg = lambda n: n.count("/") >= 2 and n.split("/")[1].endswith(".egg-info")
    if url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for n in zf.namelist():
                if egg(n):
                    out["__egg_info_dir__"] = ""
                if wanted(n):
                    out[n] = zf.read(n).decode("utf-8", "replace")
        return out
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
        for m in tf.getmembers():
            if egg(m.name):
                out["__egg_info_dir__"] = ""
            if m.isfile() and wanted(m.name):
                fh = tf.extractfile(m)
                if fh is not None:
                    out[m.name] = fh.read().decode("utf-8", "replace")
    return out


class _Unknown(Exception):
    """A definitive 'cannot know' (cacheable), e.g. sdist-only release."""


class DependencyMetaClient:
    SUPPORTED_ECOSYSTEMS = frozenset({"PyPI", "Go"})

    def __init__(self, cache_dir: str) -> None:
        self.cache_dir = os.path.join(cache_dir, "dependency_meta")
        os.makedirs(self.cache_dir, exist_ok=True)
        self._buckets = {eco: TokenBucket(rate=rps, capacity=max(1.0, rps))
                         for eco, rps in DEPENDENCY_META_RPS.items()}
        self._session = requests.Session()
        self._session.headers["User-Agent"] = DKATCHR_USER_AGENT

    # ---- cache ----------------------------------------------------------

    def _path(self, eco: str, package: str, version: str) -> str:
        key = hashlib.sha1(f"{eco}\0{package}\0{version}".encode()).hexdigest()
        return os.path.join(self.cache_dir, f"{key}.json")

    def _read(self, path: str):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return False, None
        if not isinstance(data, dict) or data.get("schema") != DEPENDENCY_META_CACHE_SCHEMA:
            return False, None
        deps = data.get("deps")
        if not isinstance(deps, list):
            return True, None
        return True, sorted((str(n), bool(c)) for n, c in deps)

    def _write(self, path: str, deps: list[tuple[str, bool]] | None) -> None:
        try:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"schema": DEPENDENCY_META_CACHE_SCHEMA,
                           "deps": None if deps is None else [list(d) for d in deps]}, fh)
            os.replace(tmp, path)
        except OSError as e:
            log(f"[!] dependency-meta cache write {path}: {e}")

    # ---- http -----------------------------------------------------------

    def _get(self, eco: str, url: str, stream: bool = False):
        self._buckets[eco].acquire()
        return self._session.get(url, timeout=DEPENDENCY_META_TIMEOUT, stream=stream)

    # ---- public ---------------------------------------------------------

    def get_dependencies(self, ecosystem: str, package: str,
                         version: str | None) -> list[tuple[str, bool]] | None:
        """version=None -> the registry's CURRENT version is resolved first
        (one uncached request), then answered from the per-version cache."""
        if ecosystem not in self.SUPPORTED_ECOSYSTEMS or not package:
            return None
        if not version:
            try:
                version = self._current_version(ecosystem, package)
            except Exception as e:  # noqa: BLE001 — unknown, retried next scan
                log(f"[!] dependency-meta {ecosystem}/{package}: current version lookup failed: {e}")
                return None
            if not version:
                return None
        path = self._path(ecosystem, package, version)
        hit, deps = self._read(path)
        if hit:
            return deps
        try:
            deps = (self._pypi(package, version) if ecosystem == "PyPI"
                    else self._go(package, version))
        except _Unknown as e:
            log(f"[dependency-meta] {ecosystem}/{package}@{version}: unknown ({e})")
            self._write(path, None)
            return None
        except Exception as e:  # noqa: BLE001 — transient: not cached, retried next scan
            log(f"[!] dependency-meta {ecosystem}/{package}@{version}: {type(e).__name__}: {e}")
            return None
        self._write(path, deps)
        return deps

    # ---- per ecosystem --------------------------------------------------

    def _current_version(self, ecosystem: str, package: str) -> str | None:
        if ecosystem == "PyPI":
            resp = self._get("PyPI", PYPI_PROJECT_JSON_URL.format(package=package))
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return ((resp.json() or {}).get("info") or {}).get("version")
        resp = self._get("Go", GO_PROXY_LATEST_URL.format(module=_go_escape(package)))
        if resp.status_code in (404, 410):
            return None
        resp.raise_for_status()
        return (resp.json() or {}).get("Version")

    def _pypi(self, package: str, version: str) -> list[tuple[str, bool]]:
        resp = self._get("PyPI", PYPI_RELEASE_JSON_URL.format(package=package, version=version))
        if resp.status_code == 404:
            raise _Unknown("release not on PyPI")
        resp.raise_for_status()
        files = (resp.json() or {}).get("urls") or []
        wheels = [f for f in files if isinstance(f, dict) and f.get("packagetype") == "bdist_wheel"]
        if not wheels:
            return self._pypi_sdist(files)
        # Prefer a pure-Python wheel (same choice the import-name resolver makes).
        wheel = next((w for w in wheels if str(w.get("filename", "")).endswith("none-any.whl")), wheels[0])
        url = wheel.get("url")
        if not url:
            raise _Unknown("wheel has no URL")
        meta = self._get("PyPI", url + ".metadata")
        if meta.status_code == 200:
            return parse_requires_dist(meta.text)
        # No PEP 658 metadata file: read METADATA out of the wheel itself.
        blob = self._download(url)
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            name = next((n for n in zf.namelist() if n.endswith(".dist-info/METADATA")), None)
            if name is None:
                raise _Unknown("wheel without dist-info/METADATA")
            return parse_requires_dist(zf.read(name).decode("utf-8", "replace"))

    def _pypi_sdist(self, files: list) -> list[tuple[str, bool]]:
        """Dependencies of an sdist-only release, read from the archive's
        build-time metadata (never by running setup.py):
          1. PKG-INFO `Requires-Dist` lines, when present;
          2. else <pkg>.egg-info/requires.txt (older setuptools wrote the
             requirements there and left PKG-INFO without them);
          3. else, with Metadata-Version >= 2.2 and Requires-Dist NOT declared
             `Dynamic` (PEP 643), PKG-INFO is authoritative: no dependencies;
          4. else a setuptools egg-info directory WITHOUT requires.txt: no
             dependencies (egg_info writes that file only when there are some).
        Anything else stays unknown."""
        sdists = [f for f in files if isinstance(f, dict) and f.get("packagetype") == "sdist"
                  and f.get("url")]
        if not sdists:
            raise _Unknown("no wheel and no sdist")
        url = sdists[0]["url"]
        blob = self._download(url)
        members = _sdist_members(blob, url)
        pkg_info = next((t for n, t in members.items() if n.count("/") == 1 and n.endswith("/PKG-INFO")), None)
        if pkg_info:
            deps = parse_requires_dist(pkg_info)
            if deps:
                return deps
        requires = next((t for n, t in members.items()
                         if n.endswith(".egg-info/requires.txt") and n.count("/") == 2), None)
        if requires is not None:
            return parse_egg_requires(requires)
        if pkg_info and _pep643_static_requires(pkg_info):
            return []
        # setuptools writes <name>.egg-info/ into every sdist it builds, and
        # requires.txt only when the project has requirements — an egg-info
        # directory without one means "no dependencies".
        if "__egg_info_dir__" in members:
            return []
        raise _Unknown("sdist metadata does not record its dependencies")

    def _download(self, url: str) -> bytes:
        with self._get("PyPI", url, stream=True) as resp:
            resp.raise_for_status()
            buf = io.BytesIO()
            for chunk in resp.iter_content(64 * 1024):
                buf.write(chunk)
                if buf.tell() > _MAX_WHEEL_BYTES:
                    raise _Unknown("archive larger than the download guard")
            return buf.getvalue()

    def _go(self, module: str, version: str) -> list[tuple[str, bool]]:
        url = GO_PROXY_MOD_URL.format(module=_go_escape(module), version=_go_escape(version))
        resp = self._get("Go", url)
        if resp.status_code in (404, 410):
            raise _Unknown("module version not on the proxy (private module?)")
        resp.raise_for_status()
        return [(m, True) for m in parse_go_mod_requires(resp.text)]
