"""Transitive resolution for manifests without a lockfile (pom.xml, .csproj,
top-level requirements.txt): which rows are roots, what gets added, and the
resolver's parsing of deps.dev graphs and NuGet .nuspec files."""

import json

from dkatchr.clients import transitive_resolver as tr
from dkatchr.clients.transitive_resolver import TransitiveResolver, _nuget_normalize
from dkatchr.core.transitive import expand_transitive

SUPPORTED = frozenset({"Maven", "PyPI", "npm", "NuGet"})


def _row(file, eco, pkg, ver, src="declared", **kw):
    return {"file": file, "ecosystem": eco, "package": pkg, "version": ver,
            "version_source": src, "origin": "registry", **kw}


_GRAPHS = {
    ("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.10"): [
        {"name": "com.fasterxml.jackson.core:jackson-databind", "version": "2.9.10",
         "deps": ["com.fasterxml.jackson.core:jackson-annotations", "com.fasterxml.jackson.core:jackson-core"]},
        {"name": "com.fasterxml.jackson.core:jackson-annotations", "version": "2.9.10", "deps": []},
        {"name": "com.fasterxml.jackson.core:jackson-core", "version": "2.9.10", "deps": []},
    ],
    ("PyPI", "requests", "2.25.0"): [
        {"name": "requests", "version": "2.25.0", "deps": ["urllib3", "certifi"]},
        {"name": "urllib3", "version": "1.26.20", "deps": []},
        {"name": "certifi", "version": "2026.10.23", "deps": []},
    ],
    ("Maven", "junit:junit", "4.12"): [
        {"name": "junit:junit", "version": "4.12", "deps": ["org.hamcrest:hamcrest-core"]},
        {"name": "org.hamcrest:hamcrest-core", "version": "1.3", "deps": []},
    ],
}


def _lookup(calls):
    def get_graph(eco, pkg, ver):
        calls.append((eco, pkg, ver))
        return _GRAPHS.get((eco, pkg, ver))
    return get_graph


def test_adds_transitive_packages_with_edges():
    root = _row("pom.xml", "Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.10")
    calls = []
    added = expand_transitive([root], _lookup(calls), SUPPORTED, 100)
    assert {(r["package"], r["version"]) for r in added} == {
        ("com.fasterxml.jackson.core:jackson-annotations", "2.9.10"),
        ("com.fasterxml.jackson.core:jackson-core", "2.9.10")}
    assert all(r["version_source"] == "transitive" and r["file"] == "pom.xml" for r in added)
    assert root["depends_on"] == ["com.fasterxml.jackson.core:jackson-annotations",
                                  "com.fasterxml.jackson.core:jackson-core"]


def test_repo_pins_win_over_resolved_versions():
    # pip-freeze style: urllib3 is pinned by the repo itself, so the resolver's
    # newer urllib3 must NOT be added as a second, never-installed version.
    inv = [_row("requirements.txt", "PyPI", "requests", "2.25.0"),
           _row("requirements.txt", "PyPI", "urllib3", "1.26.5")]
    added = expand_transitive(inv, _lookup([]), SUPPORTED, 100)
    assert [(r["package"], r["version"]) for r in added] == [("certifi", "2026.10.23")]


def test_locked_directories_and_unpinned_versions_are_skipped():
    inv = [_row("web/package.json", "npm", "express", "4.18.2"),
           _row("web/package-lock.json", "npm", "express", "4.18.2", src="resolved"),
           _row("pom.xml", "Maven", "x:y", "${unresolved}"),
           _row("go.mod", "Go", "golang.org/x/net", "v0.17.0")]
    calls = []
    assert expand_transitive(inv, _lookup(calls), SUPPORTED, 100) == []
    assert calls == []


def test_dev_scope_follows_the_roots():
    inv = [_row("pom.xml", "Maven", "junit:junit", "4.12", scope="dev")]
    added = expand_transitive(inv, _lookup([]), SUPPORTED, 100)
    assert added[0]["package"] == "org.hamcrest:hamcrest-core" and added[0]["scope"] == "dev"


def test_lookup_failure_and_root_cap():
    def boom(*a):
        raise RuntimeError("network")
    inv = [_row("pom.xml", "Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.10")]
    assert expand_transitive(inv, boom, SUPPORTED, 100) == []
    calls = []
    two = inv + [_row("pom.xml", "Maven", "junit:junit", "4.12")]
    expand_transitive(two, _lookup(calls), SUPPORTED, 1)
    assert len(calls) == 1


# ---- resolver parsing --------------------------------------------------------

class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self.content = body if isinstance(body, bytes) else json.dumps(body).encode()

    def json(self):
        return json.loads(self.content)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)


def _resolver(tmp_path, routes):
    r = TransitiveResolver(str(tmp_path))
    r._get = lambda source, url: routes.get(url, _Resp(404, b""))
    return r


def test_deps_dev_graph(tmp_path):
    url = tr.DEPS_DEV_DEPENDENCIES_URL.format(system="pypi", package="requests", version="2.31.0")
    r = _resolver(tmp_path, {url: _Resp(200, {
        "nodes": [{"versionKey": {"name": "requests", "version": "2.31.0"}},
                  {"versionKey": {"name": "idna", "version": "3.10"}}],
        "edges": [{"fromNode": 0, "toNode": 1}]})})
    nodes = r.get_graph("PyPI", "requests", "2.31.0")
    assert nodes == [{"name": "requests", "version": "2.31.0", "deps": ["idna"]},
                     {"name": "idna", "version": "3.10", "deps": []}]
    r._get = lambda *a: (_ for _ in ()).throw(AssertionError("cache miss"))
    assert r.get_graph("PyPI", "requests", "2.31.0") == nodes          # permanent cache
    assert r.get_graph("Go", "x", "v1") is None                        # unsupported


def _nuspec(deps):
    items = "".join(f'<dependency id="{i}" version="{v}" />' for i, v in deps)
    return (f'<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata>'
            f'<dependencies><group targetFramework="net6.0">{items}</group></dependencies>'
            f'</metadata></package>').encode()


def test_nuget_walk_takes_lowest_version_and_nearest_wins(tmp_path):
    u = lambda p, v: tr.NUGET_NUSPEC_URL.format(package=p, version=v)
    r = _resolver(tmp_path, {
        u("app.lib", "1.0.0"): _Resp(200, _nuspec([("Newtonsoft.Json", "[12.0.1, )"), ("Shared", "1.0")])),
        u("newtonsoft.json", "12.0.1"): _Resp(200, _nuspec([("Shared", "2.0")])),
        u("shared", "1.0.0"): _Resp(200, _nuspec([])),
    })
    nodes = r.get_graph("NuGet", "App.Lib", "1.0")
    got = {n["name"]: n["version"] for n in nodes}
    assert got == {"App.Lib": "1.0", "Newtonsoft.Json": "12.0.1", "Shared": "1.0"}


def test_nuget_normalize():
    assert _nuget_normalize("1.0") == "1.0.0"
    assert _nuget_normalize("4.0.0.0") == "4.0.0"
    assert _nuget_normalize("1.2.3.4") == "1.2.3.4"
    assert _nuget_normalize("2.0.0-Beta1+sha") == "2.0.0-beta1"


# ---- monorepos: rules apply per directory (sub-project), not per repo -------

def test_other_subprojects_pins_do_not_block_transitive_rows():
    # galileo: components/a/poetry.lock pins certifi, but tools/requirements.txt
    # (no lockfile) still installs certifi through requests.
    inv = [_row("components/a/poetry.lock", "PyPI", "certifi", "2021.5.30", src="resolved"),
           _row("tools/requirements.txt", "PyPI", "requests", "2.25.0")]
    added = expand_transitive(inv, _lookup([]), SUPPORTED, 100)
    assert ("certifi", "2026.10.23") in {(r["package"], r["version"]) for r in added}
    assert all(r["file"] == "tools/requirements.txt" for r in added)


def test_same_package_in_two_modules_gets_a_row_per_module():
    inv = [_row("mod-a/pom.xml", "Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.10"),
           _row("mod-b/pom.xml", "Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.10")]
    added = expand_transitive(inv, _lookup([]), SUPPORTED, 100)
    assert sorted({r["file"] for r in added}) == ["mod-a/pom.xml", "mod-b/pom.xml"]
