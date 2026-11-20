"""
TransitiveResolver — the resolved dependency tree of ONE direct dependency,
from the registry ecosystem, for manifests that list only direct dependencies.

WHY: a pom.xml, a .csproj or a top-level requirements.txt names what the
project asks for, not what gets installed. The packages those pull in are
installed too (jackson-databind brings jackson-core) and can be vulnerable,
but nothing in the repo names them, so no advisory lookup ever saw them. The
authoritative answer lives in the registry ecosystem, never in a static map.

Sources (endpoints in config.py):
  * Maven / PyPI / npm — deps.dev's resolved graph for the package version
    (`:dependencies`): every node with its version, plus edges. Version ranges
    resolve to the newest match TODAY, i.e. what a fresh install would get;
    Maven pins exact versions, so Maven trees are exact.
  * NuGet — deps.dev has no NuGet graphs, so each package's .nuspec (NuGet's
    flat-container CDN, one request per package version, cached per version so
    trees share their common core) is walked breadth-first. Each dependency range
    resolves to its LOWEST version, which is NuGet's own resolution rule, and a
    package seen twice keeps the version found nearest the root (NuGet's
    "nearest wins"). Every target framework's group is included: an
    over-approximation (a net461-only dependency also shows up for net6.0),
    the safe direction for a security scanner.

get_graph(ecosystem, package, version) returns
    [{"name": str, "version": str, "deps": [names]}, ...]   (root first)
or None = unknown (unsupported ecosystem, not found, malformed answer).
Permanent cache at {cache_dir}/transitive/ keyed (ecosystem, package,
version): a published version's resolved dependencies are treated as fixed.
Definitive answers (a graph, or "not found") are cached; transient failures
are not, so they retry next scan. Thread-safe; never raises.

What this module does NOT do: decide which inventory rows need resolving or
add rows (dkatchr/core/transitive.py), or judge reachability.
"""

import hashlib
import json
import os
import re
from urllib.parse import quote

import requests

from dkatchr.clients.ratelimit import TokenBucket
from dkatchr.config import (
    DEPS_DEV_DEPENDENCIES_URL,
    DKATCHR_USER_AGENT,
    NUGET_NUSPEC_URL,
    TRANSITIVE_CACHE_SCHEMA,
    TRANSITIVE_NUGET_MAX_NODES,
    TRANSITIVE_RPS,
    TRANSITIVE_TIMEOUT,
)
from dkatchr.logger import log

# Our ecosystem label -> deps.dev system name.
_DEPS_DEV_SYSTEM = {"Maven": "maven", "PyPI": "pypi", "npm": "npm"}
# NuGet range "[1.2.3, )" / "[1.2.3]" / "1.2.3" -> inclusive lower bound.
_NUGET_LOWER = re.compile(r"^\s*\[?\s*([0-9][^,\]\)\s]*)")


def _nuget_normalize(version: str) -> str:
    """NuGet's normalized version string (the flat-container path segment):
    lowercase, at least three numeric parts, a zero fourth part dropped,
    build metadata removed. "1.0" -> "1.0.0", "4.0.0.0" -> "4.0.0"."""
    v = version.strip().lower().split("+", 1)[0]
    core, sep, pre = v.partition("-")
    parts = core.split(".")
    if all(p.isdigit() for p in parts):
        parts = [str(int(p)) for p in parts]
        while len(parts) < 3:
            parts.append("0")
        if len(parts) == 4 and parts[3] == "0":
            parts = parts[:3]
        core = ".".join(parts)
    return core + (sep + pre if sep else "")


class _NotFound(Exception):
    """A definitive 'no answer' (cacheable): unknown package/version."""


class TransitiveResolver:
    SUPPORTED_ECOSYSTEMS = frozenset({"Maven", "PyPI", "npm", "NuGet"})

    def __init__(self, cache_dir: str) -> None:
        self.cache_dir = os.path.join(cache_dir, "transitive")
        os.makedirs(self.cache_dir, exist_ok=True)
        self._buckets = {src: TokenBucket(rate=rps, capacity=max(1.0, rps))
                         for src, rps in TRANSITIVE_RPS.items()}
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
        if not isinstance(data, dict) or data.get("schema") != TRANSITIVE_CACHE_SCHEMA:
            return False, None
        nodes = data.get("nodes")
        return True, nodes if isinstance(nodes, list) else None

    def _write(self, path: str, nodes: list | None) -> None:
        try:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"schema": TRANSITIVE_CACHE_SCHEMA, "nodes": nodes}, fh)
            os.replace(tmp, path)
        except OSError as e:
            log(f"[!] transitive cache write {path}: {e}")

    def _get(self, source: str, url: str):
        self._buckets[source].acquire()
        return self._session.get(url, timeout=TRANSITIVE_TIMEOUT)

    # ---- public ---------------------------------------------------------

    def get_graph(self, ecosystem: str, package: str, version: str) -> list[dict] | None:
        if ecosystem not in self.SUPPORTED_ECOSYSTEMS or not package or not version:
            return None
        path = self._path(ecosystem, package, version)
        hit, nodes = self._read(path)
        if hit:
            return nodes
        try:
            nodes = (self._nuget(package, version) if ecosystem == "NuGet"
                     else self._deps_dev(ecosystem, package, version))
        except _NotFound as e:
            log(f"[transitive] {ecosystem}/{package}@{version}: unknown ({e})")
            self._write(path, None)
            return None
        except Exception as e:  # noqa: BLE001 — transient: not cached, retried next scan
            log(f"[!] transitive {ecosystem}/{package}@{version}: {type(e).__name__}: {e}")
            return None
        self._write(path, nodes)
        return nodes

    # ---- deps.dev -------------------------------------------------------

    def _deps_dev(self, ecosystem: str, package: str, version: str) -> list[dict]:
        url = DEPS_DEV_DEPENDENCIES_URL.format(
            system=_DEPS_DEV_SYSTEM[ecosystem], package=quote(package, safe=""),
            version=quote(version, safe=""))
        resp = self._get("deps.dev", url)
        if resp.status_code == 404:
            raise _NotFound("deps.dev has no graph for this version")
        resp.raise_for_status()
        data = resp.json() or {}
        raw = data.get("nodes") or []
        if not raw:
            raise _NotFound("deps.dev returned no nodes")
        nodes = []
        for n in raw:
            key = n.get("versionKey") or {}
            nodes.append({"name": key.get("name") or "", "version": key.get("version") or "",
                          "deps": []})
        for e in data.get("edges") or []:
            a, b = e.get("fromNode"), e.get("toNode")
            if isinstance(a, int) and isinstance(b, int) and 0 <= a < len(nodes) and 0 <= b < len(nodes):
                nodes[a]["deps"].append(nodes[b]["name"])
        for n in nodes:
            n["deps"] = sorted(set(d for d in n["deps"] if d))
        return [n for n in nodes if n["name"] and n["version"]]

    # ---- NuGet ----------------------------------------------------------

    def _nuget_deps(self, package: str, version: str) -> list[tuple[str, str]]:
        """One package version's direct dependencies, cached per (package,
        version) so trees that share packages (most .NET trees share the
        Microsoft.Extensions.* / System.* core) fetch each one once."""
        path = self._path("NuGet-deps", package.lower(), version.lower())
        hit, cached = self._read(path)
        if hit:
            if cached is None:
                raise _NotFound("cached: no .nuspec on nuget.org")
            return [(d["name"], d["version"]) for d in cached]
        try:
            deps = self._nuget_deps_fetch(package, version)
        except _NotFound:
            self._write(path, None)
            raise
        self._write(path, [{"name": n, "version": v} for n, v in deps])
        return deps

    def _nuget_deps_fetch(self, package: str, version: str) -> list[tuple[str, str]]:
        """Direct dependencies from the package's .nuspec (one request, served
        by NuGet's flat-container CDN)."""
        import xml.etree.ElementTree as ET
        pid, ver = package.lower(), _nuget_normalize(version)
        url = NUGET_NUSPEC_URL.format(package=quote(pid, safe=""), version=quote(ver, safe=""))
        resp = self._get("NuGet", url)
        if resp.status_code == 404:
            raise _NotFound("no .nuspec for this version on nuget.org")
        resp.raise_for_status()
        try:
            root = ET.fromstring(resp.content)
        except ET.ParseError as e:
            raise _NotFound(f"unparseable .nuspec: {e}")
        out: dict[str, str] = {}
        for el in root.iter():
            if el.tag.rsplit("}", 1)[-1] != "dependency":
                continue
            dep_id = el.get("id")
            m = _NUGET_LOWER.match(el.get("version") or "")
            if dep_id and m and dep_id not in out:
                out[dep_id] = m.group(1)
        return sorted(out.items())

    def _nuget(self, package: str, version: str) -> list[dict]:
        root = {"name": package, "version": version, "deps": []}
        nodes = [root]
        seen = {package.lower()}
        queue = [root]
        while queue:
            node = queue.pop(0)
            try:
                deps = self._nuget_deps(node["name"], node["version"])
            except _NotFound:
                if node is root:
                    raise
                continue            # a dependency we can't see: keep it as a leaf
            node["deps"] = [d for d, _ in deps]
            for dep_id, dep_ver in deps:
                if dep_id.lower() in seen or len(nodes) >= TRANSITIVE_NUGET_MAX_NODES:
                    continue
                seen.add(dep_id.lower())
                child = {"name": dep_id, "version": dep_ver, "deps": []}
                nodes.append(child)
                queue.append(child)
        return nodes
