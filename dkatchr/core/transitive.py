"""
Transitive expansion — add the packages that a repo's DIRECT dependencies pull
in, for manifests that record no lockfile.

WHY: OSV is only asked about packages the inventory names. A pom.xml, .csproj
or top-level requirements.txt names direct dependencies only, so everything
they install underneath was invisible (the evaluation's largest remaining gap:
~150 advisories on one Maven repo). Lockfile-backed projects already list the
full tree and are left alone.

Pure: inventory rows + an injected get_graph(ecosystem, package, version)
lookup (dkatchr.clients.transitive_resolver) in, new rows out. No I/O here.

Rules:
  * Roots = declared, registry-origin rows of a supported ecosystem in a
    directory WITHOUT a lockfile of that ecosystem (a resolved row from the
    same directory). Distinct (eco, package, version), capped per repo.
  * A resolved package the repo ALREADY names (any version, any file) is not
    added: the repo's own pin is the installed version. Without this a
    pip-freeze file would gain a second, never-installed version of every
    pinned package — false findings.
  * Added rows: version_source "transitive", the first root's manifest as
    `file`, `depends_on` from the graph (feeds dependency-graph reachability),
    scope "dev" only when every root that reaches the package is dev-only.
  * Root rows with no edges get the root's direct dependencies as
    `depends_on`, so Maven/NuGet/npm manifests gain graph edges too.

What this module does NOT do: fetch anything, or decide reachability.
"""

import os
import re
from typing import Callable

_EXACTISH = re.compile(r"^[0-9][0-9A-Za-z.+_-]*$")


def _norm(eco: str, name: str) -> str:
    if eco == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if eco == "NuGet":
        return name.lower()
    return name


def expand_transitive(
    inventory: list[dict],
    get_graph: Callable[[str, str, str], list[dict] | None],
    supported_ecosystems: frozenset[str] | set[str],
    max_roots: int,
    on_progress: Callable[[dict], None] | None = None,
) -> list[dict]:
    """New inventory rows for the transitive packages of unlocked manifests.
    May also set `depends_on` on root rows in place (edges only, never data)."""
    locked: set[tuple[str, str]] = set()
    known: set[tuple[str, str]] = set()
    for row in inventory:
        eco = row.get("ecosystem", "")
        known.add((eco, _norm(eco, row.get("package", ""))))
        if row.get("version_source") == "resolved":
            locked.add((eco, os.path.dirname(row.get("file", ""))))

    roots: dict[tuple[str, str, str], list[dict]] = {}
    for row in inventory:
        eco = row.get("ecosystem", "")
        version = row.get("version") or ""
        if (eco not in supported_ecosystems
                or row.get("version_source") != "declared"
                or row.get("origin", "registry") != "registry"
                or (eco, os.path.dirname(row.get("file", ""))) in locked
                or not _EXACTISH.match(version)):
            continue
        roots.setdefault((eco, row["package"], version), []).append(row)

    keys = sorted(roots)[:max_roots]
    added: dict[tuple[str, str], dict] = {}     # (eco, norm name) -> row
    reached_by_runtime: set[tuple[str, str]] = set()
    for i, key in enumerate(keys, 1):
        eco, package, version = key
        root_rows = roots[key]
        nodes = None
        try:
            nodes = get_graph(eco, package, version)
        except Exception:  # noqa: BLE001 — a lookup failure skips only this root
            nodes = None
        if on_progress and (i % 25 == 0 or i == len(keys)):
            try:
                on_progress({"phase": "transitive_resolve", "current": i, "total": len(keys)})
            except Exception:  # noqa: BLE001 — progress must never break the work
                pass
        if not nodes:
            continue
        root_dev = all(r.get("scope") == "dev" for r in root_rows)
        for r in root_rows:
            if "depends_on" not in r:
                r["depends_on"] = list(nodes[0].get("deps") or [])
        for node in nodes[1:]:
            name, ver = node.get("name"), node.get("version")
            if not name or not ver:
                continue
            nk = (eco, _norm(eco, name))
            if nk in known:
                continue                       # the repo pins this one itself
            if not root_dev:
                reached_by_runtime.add(nk)
            if nk in added:
                continue
            added[nk] = {
                "file":           root_rows[0]["file"],
                "ecosystem":      eco,
                "package":        name,
                "version":        ver,
                "version_source": "transitive",
                "origin":         "registry",
                "depends_on":     list(node.get("deps") or []),
            }
    for nk, row in added.items():
        if nk not in reached_by_runtime:
            row["scope"] = "dev"
    return list(added.values())
