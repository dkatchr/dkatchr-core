"""
Dependency graph + transitive reachability verdicts (pure, no I/O).

WHY: Level 1 reachability asks "does YOUR code import the vulnerable
package?". A transitive dependency (certifi, pulled in by requests) is never
imported by the project itself, so that question alone can neither prove it
reachable nor prove it unreachable. This module answers the real question:
is the vulnerable package loaded by anything your code imports?

Model — deliberately anchored on IMPORTS, not on declared "root" deps:
  * nodes are (ecosystem, normalized package name); a repo's graph is the
    union of every manifest/lockfile in it (same scope as the repo-wide
    import grep);
  * edges come from lockfile `depends_on` lists and, for edge-less formats,
    from registry metadata (an injected lookup — this module never does I/O);
  * starting from every package the code imports, walk the edges.

Verdict for a vulnerable package P:
  REACHABLE      P is imported, or reachable from an imported package. The
                 shortest chain is returned as evidence
                 (certifi <- requests <- imported in app/client.py).
  NOT_REACHABLE  only when the walk is COMPLETE: every node reached from the
                 imported set has known edges, and the import status of P and
                 of every package that could lead to P was actually checked.
  UNKNOWN        otherwise — never NOT_REACHABLE on missing information
                 ("prefer false positives over false negatives").

Because the anchor is the imported set, no "declared root" is needed: a
pip-freeze requirements.txt (every installed package pinned) and a Poetry /
Cargo repo whose pyproject.toml / Cargo.toml isn't parsed both work.

Name-level graph: all versions of a package share one node and their edges
union (over-approximation = the safe direction).

Does NOT: grep source, resolve import names, call registries, or touch rows.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field

REACHABLE = "REACHABLE"
NOT_REACHABLE = "NOT_REACHABLE"
UNKNOWN = "UNKNOWN"

_PEP503 = re.compile(r"[-_.]+")

Node = tuple[str, str]   # (ecosystem, normalized name)


def normalize_name(ecosystem: str, name: str) -> str:
    """Per-ecosystem name identity, so a lockfile edge 'charset_normalizer'
    and an inventory row 'charset-normalizer' meet on one node."""
    n = (name or "").strip()
    if ecosystem == "PyPI":
        return _PEP503.sub("-", n).lower()
    if ecosystem == "crates.io":
        return n.lower().replace("_", "-")
    if ecosystem in ("NuGet", "Packagist"):
        return n.lower()
    return n   # npm, Go, RubyGems, Maven: case-sensitive identities


@dataclass
class DependencyGraph:
    edges: dict[Node, set[Node]] = field(default_factory=dict)
    known: set[Node] = field(default_factory=set)       # nodes whose edges are known
    display: dict[Node, str] = field(default_factory=dict)
    # In-repo packages (path / workspace origin): their source is part of the
    # repo, so the import grep already sees every import they make — they are
    # never "loaders" whose import status or edges need checking.
    local: set[Node] = field(default_factory=set)
    meta_lookups: int = 0
    truncated: bool = False                               # lookup budget exhausted

    def node(self, ecosystem: str, name: str) -> Node:
        n = (ecosystem, normalize_name(ecosystem, name))
        self.display.setdefault(n, name)
        self.edges.setdefault(n, set())
        return n

    def applies_to(self, ecosystem: str) -> bool:
        """The graph only says anything for an ecosystem where at least one
        node has known edges (Maven, or an npm repo with no lockfile, has
        none) — elsewhere callers keep plain import presence."""
        return any(n[0] == ecosystem for n in self.known)

    def unknown_nodes(self, ecosystem: str) -> set[Node]:
        return {n for n in self.edges
                if n[0] == ecosystem and n not in self.known and n not in self.local}

    def probe_set(self, target: Node) -> set[Node]:
        """Every package whose import status must be checked to decide
        `target`: its ancestors over known edges, plus every same-ecosystem
        node with UNKNOWN edges (it could secretly depend on `target`) and
        their ancestors. Packages outside this set provably cannot lead to
        `target`, so whether they are imported doesn't matter."""
        unknown = self.unknown_nodes(target[0]) - {target}
        out = self.ancestors(target) | unknown
        for u in unknown:
            out |= self.ancestors(u)
        out.discard(target)
        return out - self.local

    def ancestors(self, target: Node) -> set[Node]:
        """Every node with a path to `target` (reverse-edge walk)."""
        reverse: dict[Node, set[Node]] = {}
        for src, dsts in self.edges.items():
            for d in dsts:
                reverse.setdefault(d, set()).add(src)
        seen: set[Node] = set()
        queue = deque([target])
        while queue:
            for parent in reverse.get(queue.popleft(), ()):
                if parent not in seen and parent != target:
                    seen.add(parent)
                    queue.append(parent)
        return seen


def build_dependency_graph(
    inventory_rows: list[dict],
    meta_lookup=None,
    meta_ecosystems: frozenset[str] = frozenset(),
    max_meta_lookups: int = 0,
    on_progress=None,
) -> DependencyGraph:
    """Build the repo graph from inventory rows (pure apart from the injected
    `meta_lookup(ecosystem, package, version) -> list | None`, whose items are
    names (unconditional) or (name, conditional) pairs).

    Rows carrying `depends_on` (lockfiles) give known edges directly. For a
    registry-origin package that NO row gives edges for, every one of its
    versions is looked up via `meta_lookup` when its ecosystem is in
    `meta_ecosystems`; the node is known only if every lookup answered.
    Lookups beyond `max_meta_lookups` are skipped and the graph is marked
    truncated (those nodes stay unknown)."""
    g = DependencyGraph()
    versions_needing_meta: dict[Node, set[str]] = {}
    installed: set[Node] = set()            # nodes with an inventory row
    via_lock: set[Node] = set()             # edge targets named by a lockfile
    via_meta: set[Node] = set()             # edge targets named by registry metadata

    for row in inventory_rows:
        eco, pkg = row.get("ecosystem") or "", row.get("package") or ""
        if not eco or not pkg:
            continue
        n = g.node(eco, pkg)
        installed.add(n)
        if row.get("origin") in ("path", "workspace"):
            g.local.add(n)
        if "depends_on" in row:
            g.known.add(n)
            for d in row.get("depends_on") or []:
                if d:
                    t = g.node(eco, d)
                    g.edges[n].add(t)
                    via_lock.add(t)
        elif row.get("origin", "registry") == "registry" and row.get("version"):
            versions_needing_meta.setdefault(n, set()).add(row["version"])

    def _lookup(n: Node, version: str | None) -> list[tuple[str, bool]] | None:
        if g.meta_lookups >= max_meta_lookups:
            g.truncated = True
            return None
        g.meta_lookups += 1
        try:
            deps = meta_lookup(n[0], g.display[n], version)
        except Exception:  # noqa: BLE001 — a lookup failure only makes that node unknown
            return None
        if deps is None:
            return None
        return [(d, False) if isinstance(d, str) else (d[0], bool(d[1])) for d in deps]

    def _add_meta_edges(n: Node, deps: list[tuple[str, bool]]) -> None:
        for name, conditional in deps:
            if not name:
                continue
            t = (n[0], normalize_name(n[0], name))
            # A conditional requirement (extra / environment marker) that
            # is not installed was simply not chosen: no edge. Installed
            # -> keep it (it may be loaded for this reason too).
            if conditional and t not in installed:
                continue
            g.edges[n].add(g.node(n[0], name))
            if t not in installed:
                via_meta.add(t)

    def _progress(i: int, total: int) -> None:
        if on_progress is not None and (i % 25 == 0 or i == total):
            try:
                on_progress({"phase": "dependency_meta_fetch", "current": i, "total": total})
            except Exception:  # noqa: BLE001
                pass

    # 1. Installed packages with no lockfile edges: their exact versions.
    todo = [(n, v) for n, vs in versions_needing_meta.items()
            if n not in g.known and n[0] in meta_ecosystems and meta_lookup
            for v in sorted(vs)]
    failed: set[Node] = set()
    answered: set[Node] = set()
    for i, (n, version) in enumerate(todo, 1):
        deps = _lookup(n, version)
        if deps is None:
            failed.add(n)
        else:
            answered.add(n)
            _add_meta_edges(n, deps)
        _progress(i, len(todo))
    g.known |= (answered - failed)

    # 2. Packages that only appear as an edge target (no inventory row).
    #    Named by a LOCKFILE edge -> the lockfile records everything that was
    #    resolved, so it is NOT installed (an unselected optional / extra /
    #    peer dependency) and can load nothing: a known leaf.
    #    Named by an UNCONDITIONAL registry requirement -> pip installed it, so
    #    the requirements file lists only top-level packages: look its edges
    #    up at the registry's current version (an approximation that can only
    #    add edges), never guess "leaf". Its own unconditional targets are
    #    followed too, within the same lookup budget. (Conditional ones that
    #    aren't installed never became edges — see _add_meta_edges.)
    queue = deque(sorted(n for n in g.edges if n not in installed and n not in g.known))
    done = 0
    while queue:
        n = queue.popleft()
        if n in g.known:
            continue
        if n in via_meta and n[0] in meta_ecosystems and meta_lookup:
            deps = _lookup(n, None)
            done += 1
            _progress(done, done + len(queue))
            if deps is None:
                continue                      # stays unknown
            g.known.add(n)
            before = set(g.edges[n])
            _add_meta_edges(n, deps)
            for t in g.edges[n] - before:
                if t not in installed and t not in g.known:
                    queue.append(t)
        elif n in via_lock:
            g.known.add(n)                    # not installed: leaf
    return g


@dataclass
class GraphVerdict:
    verdict: str                       # REACHABLE | NOT_REACHABLE | UNKNOWN
    chain: list[str] = field(default_factory=list)   # [vulnerable, ..., imported]
    anchor_files: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        out = {"method": "graph", "verdict": self.verdict}
        if self.chain:
            out["chain"] = self.chain
        if self.anchor_files:
            out["anchor_files"] = self.anchor_files
        if self.reason:
            out["reason"] = self.reason
        return out


def decide_transitive(
    graph: DependencyGraph,
    target: Node,
    imported: dict[Node, list[str]],
    import_unknown: set[Node],
) -> GraphVerdict:
    """Verdict for `target` given the imported packages ({node: evidence
    files}) and the packages whose import status could not be checked.
    `imported` / `import_unknown` must cover graph.probe_set(target) plus
    target itself (other packages can't lead to target and are ignored)."""
    # Multi-source BFS from every imported node: parent pointers then give
    # each reached node's SHORTEST chain back to its nearest import.
    # In-repo packages are not walk sources: their code is in the grep, so
    # whatever THEY import is already detected directly.
    sources = [n for n in imported if n not in graph.local]
    parent: dict[Node, Node | None] = {n: None for n in sources}
    queue = deque(sources)
    while queue:
        cur = queue.popleft()
        for nxt in graph.edges.get(cur, ()):
            if nxt not in parent:
                parent[nxt] = cur
                queue.append(nxt)

    if target in parent:
        chain_nodes = [target]
        while parent[chain_nodes[-1]] is not None:
            chain_nodes.append(parent[chain_nodes[-1]])
        root = chain_nodes[-1]
        return GraphVerdict(REACHABLE, [graph.display.get(n, n[1]) for n in chain_nodes],
                            list(imported.get(root, []))[:3])

    # A reached package whose dependencies are unknown might load target.
    unknown_edges = sorted(graph.display.get(n, n[1]) for n in parent
                           if n not in graph.known and n not in graph.local
                           and n[0] == target[0])
    if unknown_edges:
        return GraphVerdict(UNKNOWN, reason=f"dependencies unknown for imported/loaded package(s): "
                                            f"{', '.join(unknown_edges[:3])}")
    # An in-repo package's own imports are already in the grep — its import
    # status (often unresolvable: it's not on any registry) is irrelevant.
    candidates = (({target} | graph.probe_set(target)) & import_unknown) - graph.local
    if candidates:
        names = sorted(graph.display.get(n, n[1]) for n in candidates)
        return GraphVerdict(UNKNOWN, reason=f"couldn't check whether your code imports: "
                                            f"{', '.join(names[:3])}")
    return GraphVerdict(NOT_REACHABLE, reason="nothing your code imports depends on it")
