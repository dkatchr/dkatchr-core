"""enrich_reachability with a dependency graph: one tarball pass covers the
probe set, and transitive verdicts land on the rows."""

import io
import tarfile

from dkatchr.clients.resolvers import ImportNameResolver
from dkatchr.core.dependency_graph import build_dependency_graph
from dkatchr.core.reachability import enrich_reachability
from dkatchr.storage.reachability_cache import ReachabilityCache


class _Stream(io.BytesIO):
    failure_reason = None

    def __init__(self, data):
        super().__init__(data)
        self.bytes_read = len(data)


class _GitHub:
    def __init__(self, files):
        self.files, self.calls = files, 0

    def open_repo_tarball_stream(self, repo, ref=None, on_progress=None):
        self.calls += 1
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for path, text in self.files.items():
                data = text.encode()
                info = tarfile.TarInfo(f"repo-abc/{path}")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        return _Stream(buf.getvalue()), None


def _resolver(monkeypatch, names):
    def fake(self, pairs, on_progress=None, versions=None):
        return {p: names.get(p[0], []) for p in pairs}
    monkeypatch.setattr(ImportNameResolver, "resolve_batch", fake)


def _rows(*pkgs):
    return [{"package": p, "ecosystem": "PyPI", "version": "1.0", "vuln_id": f"V-{p}"} for p in pkgs]


def _graph():
    return build_dependency_graph([
        {"ecosystem": "PyPI", "package": "requests", "depends_on": ["certifi", "urllib3"]},
        {"ecosystem": "PyPI", "package": "certifi", "depends_on": []},
        {"ecosystem": "PyPI", "package": "urllib3", "depends_on": []},
        {"ecosystem": "PyPI", "package": "flask", "depends_on": ["itsdangerous"]},
        {"ecosystem": "PyPI", "package": "itsdangerous", "depends_on": []},
    ])


NAMES = {p: [p] for p in ("requests", "certifi", "urllib3", "flask", "itsdangerous")}


def test_transitive_reachable_and_not_reachable(tmp_path, monkeypatch):
    _resolver(monkeypatch, NAMES)
    gh = _GitHub({"src/app.py": "import requests\n"})
    rows = _rows("certifi", "itsdangerous")
    enrich_reachability(rows, "o/r", "sha1", gh, ReachabilityCache(str(tmp_path)),
                        str(tmp_path), dependency_graph=_graph())
    by = {r["package"]: r for r in rows}
    assert by["certifi"]["reachability"] == "REACHABLE"
    assert by["certifi"]["reachability_path"]["chain"] == ["certifi", "requests"]
    assert "src/app.py" in by["certifi"]["reachability_evidence"]
    assert by["itsdangerous"]["reachability"] == "UNUSED"           # proven: flask not imported
    assert by["itsdangerous"]["reachability_path"]["verdict"] == "NOT_REACHABLE"


def test_without_graph_behaviour_is_unchanged(tmp_path, monkeypatch):
    _resolver(monkeypatch, NAMES)
    rows = _rows("certifi")
    enrich_reachability(rows, "o/r", "sha2", _GitHub({"src/app.py": "import requests\n"}),
                        ReachabilityCache(str(tmp_path)), str(tmp_path))
    assert rows[0]["reachability"] == "UNUSED" and "reachability_path" not in rows[0]


def test_cache_from_a_graph_less_run_is_regrepped_for_probes(tmp_path, monkeypatch):
    _resolver(monkeypatch, NAMES)
    gh = _GitHub({"src/app.py": "import requests\n"})
    cache = ReachabilityCache(str(tmp_path))
    enrich_reachability(_rows("certifi"), "o/r", "sha3", gh, cache, str(tmp_path))   # no graph
    rows = _rows("certifi")
    enrich_reachability(rows, "o/r", "sha3", gh, cache, str(tmp_path), dependency_graph=_graph())
    assert gh.calls == 2                       # probes weren't in the cached run -> re-grep
    assert rows[0]["reachability"] == "REACHABLE"
    rows2 = _rows("certifi")
    enrich_reachability(rows2, "o/r", "sha3", gh, cache, str(tmp_path), dependency_graph=_graph())
    assert gh.calls == 2                       # now fully cached
    assert rows2[0]["reachability_path"]["chain"] == ["certifi", "requests"]


def test_unresolvable_parent_import_is_unknown_not_unused(tmp_path, monkeypatch):
    _resolver(monkeypatch, {**NAMES, "requests": []})     # can't resolve requests' import names
    rows = _rows("certifi")
    enrich_reachability(rows, "o/r", "sha4", _GitHub({"src/app.py": "import flask\n"}),
                        ReachabilityCache(str(tmp_path)), str(tmp_path), dependency_graph=_graph())
    assert rows[0]["reachability"] == "UNKNOWN"
    assert "requests" in rows[0]["reachability_path"]["reason"]
