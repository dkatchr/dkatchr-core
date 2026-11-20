"""P1 manifest coverage from the 10-repo evaluation: requirements-file variants,
setup.py / setup.cfg / pyproject.toml, .NET *.deps.json, and Maven projects
whose versions live in a parent pom."""

from dkatchr.core.inventory import extract_maven_project_inventory
from dkatchr.parsers import manifest_handler
from dkatchr.parsers.maven import from_pom_xml, resolve_maven_project
from dkatchr.parsers.nuget import from_deps_json
from dkatchr.parsers.pypi import from_pyproject_toml, from_setup_cfg, from_setup_py


def _pv(rows):
    return {(r["package"], r["version"]) for r in rows}


def test_requirements_variants_are_manifests():
    for name in ("requirements-dev.txt", "dev-requirements.txt", "requirements_prod.txt",
                 "requirements.in", "requirements.txt"):
        assert manifest_handler(name)[0] == "PyPI", name
    for name in ("requirements", "requirements.txt.bak", "notrequirementsx.txt"):
        assert manifest_handler(name) is None, name
    assert manifest_handler("App.deps.json")[0] == "NuGet"


def test_setup_py_reads_literals_without_executing():
    src = '''
import os
REQS = ["requests>=2.31.0", "click==8.1.7"]
os.system("echo should never run")
setup(
    name="x",
    install_requires=REQS,
    tests_require=["pytest==7.4.0"],
    extras_require={"aws": ["boto3>=1.28.0"]},
)
'''
    rows = from_setup_py(src)
    assert _pv(rows) == {("requests", "2.31.0"), ("click", "8.1.7"),
                         ("pytest", "7.4.0"), ("boto3", "1.28.0")}
    assert next(r for r in rows if r["package"] == "pytest")["scope"] == "dev"
    assert from_setup_py("def broken(:") == []


def test_setup_cfg():
    cfg = """[options]
install_requires =
    flask==2.3.2
    jinja2>=3.1.2
tests_require =
    pytest==7.4.0

[options.extras_require]
s3 = boto3==1.28.0
"""
    assert _pv(from_setup_cfg(cfg)) == {("flask", "2.3.2"), ("jinja2", "3.1.2"),
                                        ("pytest", "7.4.0"), ("boto3", "1.28.0")}


def test_pyproject_pep621_and_poetry():
    toml = """
[project]
dependencies = ["httpx>=0.27.0", "pydantic==2.7.1"]
[project.optional-dependencies]
pg = ["psycopg==3.1.18"]
[dependency-groups]
test = ["pytest==8.2.0"]

[tool.poetry.dependencies]
python = "^3.11"
fastapi = "^0.110.0"
mylib = {path = "../mylib"}
[tool.poetry.group.dev.dependencies]
ruff = "^0.4.0"
"""
    rows = from_pyproject_toml(toml)
    assert _pv(rows) >= {("httpx", "0.27.0"), ("pydantic", "2.7.1"), ("psycopg", "3.1.18"),
                         ("pytest", "8.2.0"), ("fastapi", "0.110.0"), ("ruff", "0.4.0")}
    assert not any(r["package"] == "python" for r in rows)
    assert next(r for r in rows if r["package"] == "mylib")["origin"] == "path"
    assert next(r for r in rows if r["package"] == "ruff")["scope"] == "dev"
    assert next(r for r in rows if r["package"] == "pytest")["scope"] == "dev"


def test_deps_json_resolved_graph():
    doc = """{
      "targets": {".NETCoreApp,Version=v6.0": {
        "App/1.0.0": {"dependencies": {"Newtonsoft.Json": "13.0.1"}},
        "Newtonsoft.Json/13.0.1": {"dependencies": {"System.Memory": "4.5.4"}},
        "System.Memory/4.5.4": {}
      }},
      "libraries": {
        "App/1.0.0": {"type": "project"},
        "Newtonsoft.Json/13.0.1": {"type": "package"},
        "System.Memory/4.5.4": {"type": "package"},
        "mscorlib/4.0.0.0": {"type": "reference"}
      }
    }"""
    rows = from_deps_json(doc)
    assert _pv(rows) == {("Newtonsoft.Json", "13.0.1"), ("System.Memory", "4.5.4")}
    assert all(r["version_source"] == "resolved" for r in rows)
    assert next(r for r in rows if r["package"] == "Newtonsoft.Json")["depends_on"] == ["System.Memory"]
    assert from_deps_json("not json") == []


_PARENT = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.acme</groupId><artifactId>parent</artifactId><version>2.1.0</version>
  <properties>
    <jackson.version>2.9.10</jackson.version>
    <jackson.databind.version>${jackson.version}</jackson.databind.version>
  </properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>1.26</version></dependency>
    <dependency><groupId>com.acme</groupId><artifactId>bom</artifactId><version>${project.version}</version>
      <type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
</project>"""

_BOM = """<project><groupId>com.acme</groupId><artifactId>bom</artifactId><version>2.1.0</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>commons-io</groupId><artifactId>commons-io</artifactId><version>2.6</version></dependency>
  </dependencies></dependencyManagement>
</project>"""

_CHILD = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>2.1.0</version></parent>
  <artifactId>child</artifactId>
  <dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId>
      <version>${jackson.databind.version}</version></dependency>
    <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId></dependency>
    <dependency><groupId>commons-io</groupId><artifactId>commons-io</artifactId></dependency>
    <dependency><groupId>com.acme</groupId><artifactId>sibling</artifactId><version>${project.version}</version></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version><scope>test</scope></dependency>
    <dependency><groupId>org.external</groupId><artifactId>x</artifactId><version>${from.external.parent}</version></dependency>
  </dependencies>
</project>"""


def test_maven_child_resolves_through_parent_and_bom():
    rows = resolve_maven_project({"pom.xml": _PARENT, "bom/pom.xml": _BOM,
                                  "child/pom.xml": _CHILD})["child/pom.xml"]
    got = _pv(rows)
    assert ("com.fasterxml.jackson.core:jackson-databind", "2.9.10") in got   # property chain via parent
    assert ("org.yaml:snakeyaml", "1.26") in got                              # parent dependencyManagement
    assert ("commons-io:commons-io", "2.6") in got                            # in-repo import-scope BOM
    assert ("com.acme:sibling", "2.1.0") in got                               # inherited project.version
    assert next(r for r in rows if r["package"] == "junit:junit")["scope"] == "dev"
    assert not any("${" in v for _, v in got)                                 # external parent: skipped, not junk


def test_maven_per_file_skips_unresolved_versions():
    assert not any("${" in r["version"] for r in from_pom_xml(_CHILD))


def test_maven_project_inventory_rows():
    rows = extract_maven_project_inventory({"pom.xml": _PARENT, "child/pom.xml": _CHILD})
    assert all(r["ecosystem"] == "Maven" and r["origin"] == "registry" for r in rows)
    assert {r["file"] for r in rows} <= {"pom.xml", "child/pom.xml"}
    assert resolve_maven_project({"bad/pom.xml": "<not xml"}) == {}


# ---- sdist-only releases: dependencies from build-time metadata --------------

import io
import tarfile

from dkatchr.clients.dependency_meta import (
    _pep643_static_requires,
    _sdist_members,
    parse_egg_requires,
)


def _tgz(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_egg_requires_sections_are_conditional():
    assert parse_egg_requires("six>=1.9\nrequests\n\n[socks]\nPySocks\n[:python_version<'3']\nenum34\n") == [
        ("PySocks", True), ("enum34", True), ("requests", False), ("six", False)]


def test_pep643_static_requires():
    assert _pep643_static_requires("Metadata-Version: 2.2\nName: x\n")
    assert not _pep643_static_requires("Metadata-Version: 2.2\nDynamic: Requires-Dist\n")
    assert not _pep643_static_requires("Metadata-Version: 2.1\nName: x\n")


def test_sdist_members_top_level_only():
    blob = _tgz({
        "pkg-1.0/PKG-INFO": "Metadata-Version: 1.1\n",
        "pkg-1.0/pkg.egg-info/SOURCES.txt": "x",
        "pkg-1.0/vendor/other.egg-info/requires.txt": "evil\n",
    })
    members = _sdist_members(blob, "https://x/pkg-1.0.tar.gz")
    assert "__egg_info_dir__" in members
    assert "pkg-1.0/PKG-INFO" in members


# ---- dev / test-only scope ---------------------------------------------------

from dkatchr.core.inventory import dedupe_inventory, extract_file_inventory
from dkatchr.parsers.composer import from_composer_lock
from dkatchr.parsers.npm import from_package_json, from_package_lock
from dkatchr.parsers.ruby import from_gemfile


def _scope(rows, name):
    return next(r for r in rows if r["package"] == name).get("scope")


def test_npm_dev_scope():
    pj = from_package_json('{"dependencies": {"express": "^4.18.2"}, "devDependencies": {"vite": "^5.0.0"}}')
    assert _scope(pj, "vite") == "dev" and _scope(pj, "express") is None
    lock = from_package_lock('''{"lockfileVersion": 3, "packages": {
        "": {}, "node_modules/vite": {"version": "5.0.0", "dev": true},
        "node_modules/esbuild": {"version": "0.19.0", "dev": true},
        "node_modules/fsevents": {"version": "2.3.3", "devOptional": true},
        "node_modules/express": {"version": "4.18.2"}}}''')
    assert _scope(lock, "esbuild") == "dev"            # transitive dev package
    assert _scope(lock, "fsevents") is None            # devOptional is not dev-only
    assert _scope(lock, "express") is None


def test_composer_and_gemfile_dev_scope():
    lock = from_composer_lock('{"packages": [{"name": "a/b", "version": "1.0"}], '
                              '"packages-dev": [{"name": "phpunit/phpunit", "version": "9.6.0"}]}')
    assert _scope(lock, "phpunit/phpunit") == "dev" and _scope(lock, "a/b") is None
    gemfile = """source "https://rubygems.org"
gem "rails", "7.1.0"
gem "pry", "0.14.2", group: :development
group :development, :test do
  gem "rspec-rails", "6.1.0"
  if ENV["CI"]
    gem "simplecov", "0.22.0"
  end
end
group :production do
  gem "pg", "1.5.4"
end
gem "puma", "6.4.0"
"""
    rows = from_gemfile(gemfile)
    assert _scope(rows, "pry") == "dev"
    assert _scope(rows, "rspec-rails") == "dev"
    assert _scope(rows, "simplecov") == "dev"
    assert _scope(rows, "rails") is None and _scope(rows, "pg") is None and _scope(rows, "puma") is None


def test_dedupe_keeps_dev_only_when_all_rows_are_dev():
    a = extract_file_inventory("package.json", '{"devDependencies": {"lodash": "4.17.21"}}')
    b = extract_file_inventory("web/package.json", '{"dependencies": {"lodash": "4.17.21"}}')
    assert dedupe_inventory(a + b)[0].get("scope") is None
    a = extract_file_inventory("package.json", '{"devDependencies": {"lodash": "4.17.21"}}')
    c = extract_file_inventory("tools/package.json", '{"devDependencies": {"lodash": "4.17.21"}}')
    assert dedupe_inventory(a + c)[0].get("scope") == "dev"
