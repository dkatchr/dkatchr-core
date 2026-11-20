"""Pure dependency-graph reachability: build + verdicts."""

from dkatchr.core.dependency_graph import (
    NOT_REACHABLE, REACHABLE, UNKNOWN, build_dependency_graph, decide_transitive,
    normalize_name,
)


def _row(pkg, deps=None, eco="PyPI", version="1.0", origin="registry"):
    r = {"ecosystem": eco, "package": pkg, "version": version, "origin": origin}
    if deps is not None:
        r["depends_on"] = deps
    return r


def _decide(g, target, imported=(), unknown=(), eco="PyPI"):
    t = g.node(eco, target)
    imp = {g.node(eco, n): [f"src/{n}.py"] for n in imported}
    unk = {g.node(eco, n) for n in unknown}
    return decide_transitive(g, t, imp, unk)


def test_normalization():
    assert normalize_name("PyPI", "Charset_Normalizer") == "charset-normalizer"
    assert normalize_name("crates.io", "Rustls_WebPKI") == "rustls-webpki"
    assert normalize_name("npm", "React") == "React"


def test_certifi_reachable_through_requests_with_chain():
    g = build_dependency_graph([_row("requests", ["certifi", "urllib3"]),
                                _row("certifi", []), _row("urllib3", [])])
    v = _decide(g, "certifi", imported=["requests"])
    assert v.verdict == REACHABLE
    assert v.chain == ["certifi", "requests"]
    assert v.anchor_files == ["src/requests.py"]


def test_shortest_chain_wins():
    g = build_dependency_graph([_row("app", ["a", "c"]), _row("a", ["b"]), _row("b", ["c"]),
                                _row("c", [])])
    assert _decide(g, "c", imported=["app"]).chain == ["c", "app"]


def test_not_reachable_only_when_complete():
    g = build_dependency_graph([_row("requests", ["certifi"]), _row("certifi", []),
                                _row("flask", ["click"]), _row("click", [])])
    assert _decide(g, "certifi", imported=["flask"]).verdict == NOT_REACHABLE


def test_unknown_edges_on_a_loaded_package_block_not_reachable():
    g = build_dependency_graph([_row("mystery"),            # no edges, no lookup
                                _row("certifi", []), _row("flask", ["mystery"])])
    v = _decide(g, "certifi", imported=["flask"])
    assert v.verdict == UNKNOWN and "mystery" in v.reason


def test_unchecked_import_of_a_possible_parent_blocks_not_reachable():
    g = build_dependency_graph([_row("requests", ["certifi"]), _row("certifi", [])])
    v = _decide(g, "certifi", imported=[], unknown=["requests"])
    assert v.verdict == UNKNOWN and "requests" in v.reason


def test_cycles_terminate():
    g = build_dependency_graph([_row("a", ["b"]), _row("b", ["a", "c"]), _row("c", [])])
    assert _decide(g, "c", imported=["a"]).verdict == REACHABLE


def test_meta_lookup_fills_edge_less_rows_and_tracks_unknown():
    calls = []

    def lookup(eco, pkg, ver):
        calls.append((pkg, ver))
        return {"requests": ["certifi"], "certifi": []}.get(pkg)   # pycrypto -> None
    rows = [_row("requests", version="2.31.0"), _row("certifi", version="2024.7.4"),
            _row("pycrypto", version="2.6.1")]
    g = build_dependency_graph(rows, lookup, frozenset({"PyPI"}), max_meta_lookups=10)
    assert _decide(g, "certifi", imported=["requests"]).verdict == REACHABLE
    assert g.node("PyPI", "pycrypto") not in g.known
    assert len(calls) == 3


def test_lookup_budget_truncates_to_unknown():
    rows = [_row(f"p{i}", version="1") for i in range(5)]
    g = build_dependency_graph(rows, lambda *a: [], frozenset({"PyPI"}), max_meta_lookups=2)
    assert g.truncated and len(g.known) == 2


def test_graph_does_not_apply_to_ecosystem_without_known_edges():
    g = build_dependency_graph([_row("org.x:y", eco="Maven")])
    assert not g.applies_to("Maven")


def test_probe_set_includes_unknown_edge_nodes_and_their_ancestors():
    g = build_dependency_graph([_row("app", ["mystery"]), _row("mystery"),
                                _row("certifi", []), _row("requests", ["certifi"])])
    probes = {n[1] for n in g.probe_set(g.node("PyPI", "certifi"))}
    assert probes == {"requests", "mystery", "app"}


def test_edges_stay_within_an_ecosystem():
    g = build_dependency_graph([_row("debug", ["ms"], eco="npm"), _row("ms", [], eco="npm"),
                                _row("ms", [], eco="PyPI")])
    assert _decide(g, "ms", imported=[], eco="PyPI").verdict == NOT_REACHABLE


def test_lockfile_edge_to_uninstalled_package_is_a_leaf():
    # requests lists PySocks (socks extra) but the lockfile never resolved it.
    g = build_dependency_graph([_row("requests", ["certifi", "PySocks"]), _row("certifi", [])])
    assert g.node("PyPI", "pysocks") in g.known
    assert _decide(g, "certifi", imported=[]).verdict == NOT_REACHABLE


def test_registry_edge_to_unlisted_package_is_looked_up_at_current_version():
    seen = []

    def lookup(eco, pkg, ver):
        seen.append((pkg, ver))
        return {("app-lib", "1.0"): ["middle"], ("middle", None): ["certifi"],
                ("certifi", "1.0"): []}.get((pkg, ver))
    rows = [_row("app-lib", version="1.0"), _row("certifi", version="1.0")]   # middle unlisted
    g = build_dependency_graph(rows, lookup, frozenset({"PyPI"}), max_meta_lookups=10)
    assert ("middle", None) in seen
    v = _decide(g, "certifi", imported=["app-lib"])
    assert v.verdict == REACHABLE and v.chain == ["certifi", "middle", "app-lib"]


def test_in_repo_packages_are_ignored_as_loaders():
    rows = [_row("my-project", ["requests", "flask"], origin="path"),
            _row("requests", ["certifi"]), _row("certifi", []), _row("flask", [])]
    g = build_dependency_graph(rows)
    # my-project's import status is unknown (not on any registry) and it is
    # even "imported" by its own code — neither may affect the verdict.
    assert _decide(g, "certifi", imported=["my-project"], unknown=["my-project"]).verdict == NOT_REACHABLE
    assert _decide(g, "certifi", imported=["requests"]).verdict == REACHABLE


def test_conditional_requirement_to_uninstalled_package_is_dropped():
    calls = []

    def lookup(eco, pkg, ver):
        calls.append(pkg)
        return {"requests": [("certifi", False), ("PySocks", True)], "certifi": []}.get(pkg)
    rows = [_row("requests", version="2.31.0"), _row("certifi", version="1.0")]
    g = build_dependency_graph(rows, lookup, frozenset({"PyPI"}), max_meta_lookups=10)
    assert g.node("PyPI", "pysocks") not in g.edges[g.node("PyPI", "requests")]
    assert "PySocks" not in calls                       # never looked up, never expanded
    assert _decide(g, "certifi", imported=["requests"]).verdict == REACHABLE


def test_conditional_requirement_to_installed_package_is_kept():
    lookup = lambda eco, pkg, ver: {"requests": [("PySocks", True)], "PySocks": []}.get(pkg)
    rows = [_row("requests", version="2"), _row("PySocks", version="1.7.1")]
    g = build_dependency_graph(rows, lookup, frozenset({"PyPI"}), max_meta_lookups=10)
    assert _decide(g, "PySocks", imported=["requests"]).verdict == REACHABLE
