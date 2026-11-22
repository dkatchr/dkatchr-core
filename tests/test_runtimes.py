"""Runtime & base-image scanning: parsing, image expansion, findings, CVE.org
range matching and the three-source merge."""

from datetime import date

from dkatchr.clients.cvelist import _summarize, affected_fix
from dkatchr.clients.runtime_advisories import _merge
from dkatchr.core.runtime_inventory import expand_image_runtimes, runtime_findings
from dkatchr.parsers.runtime import extract_runtime_inventory as extract
from dkatchr.parsers.runtime import is_runtime_source, parse_image_ref, parse_spec


def _pv(rows):
    return [(r["ecosystem"], r["package"], r["version"], r["version_source"], r.get("scope")) for r in rows]


# ---- specs + file selection ----------------------------------------------------------

def test_parse_spec():
    assert parse_spec("3.2.2") == ("3.2.2", "exact", "exact", 3)
    assert parse_spec("v18.17.0") == ("18.17.0", "exact", "exact", 3)
    assert parse_spec("18") == ("18.0.0", "minimum", "line", 1)
    assert parse_spec("~> 3.2") == ("3.2.0", "minimum", "line", 2)
    assert parse_spec(">=3.9") == ("3.9.0", "minimum", "range", 2)
    assert parse_spec("1.8") == ("8.0.0", "minimum", "line", 1)         # Java 8
    assert parse_spec("17.0.9+9") == ("17.0.9", "exact", "exact", 3)
    assert parse_spec("3.x") == ("3.0.0", "minimum", "line", 1)
    for none in ("lts/*", "stable", "<4", "${{ matrix.node }}", "system"):
        assert parse_spec(none) is None


def test_runtime_sources():
    for p in (".ruby-version", "svc/Dockerfile", "Dockerfile.prod", "docker-compose.yml",
              ".github/workflows/ci.yml", "deploy/k8s/app.yaml", "charts/api/values.yaml",
              "App/App.csproj", "go.mod", "global.json"):
        assert is_runtime_source(p), p
    for p in ("src/config.yaml", "README.md", "app/models/user.rb"):
        assert not is_runtime_source(p), p


# ---- per-format extraction ---------------------------------------------------------

def test_version_files():
    assert _pv(extract(".ruby-version", "ruby-3.2.2\n")) == [("Runtime", "ruby", "3.2.2", "exact", None)]
    assert _pv(extract(".nvmrc", "18\n")) == [("Runtime", "node", "18.0.0", "minimum", None)]
    rows = extract(".tool-versions", "nodejs 20.11.1\npython 3.12.2\nelixir 1.15.7-otp-26\n")
    assert {(r["package"], r["version"]) for r in rows} == {
        ("node", "20.11.1"), ("python", "3.12.2"), ("elixir", "1.15.7")}
    assert _pv(extract("go.mod", "module x\n\ngo 1.21\ntoolchain go1.21.5\n")) == [
        ("Runtime", "go", "1.21.0", "minimum", None), ("Runtime", "go", "1.21.5", "exact", None)]
    assert _pv(extract("package.json", '{"engines": {"node": ">=18"}}'))[0][2] == "18.0.0"
    assert _pv(extract("global.json", '{"sdk": {"version": "8.0.100"}}')) == [
        ("Runtime", "dotnet", "8.0.0", "minimum", None)]                 # SDK != runtime
    assert {r["version"] for r in extract("A.csproj", "<TargetFrameworks>net8.0;net48</TargetFrameworks>")} == {"8.0.0"}


def test_dockerfile_stages_args_and_digests():
    df = ("ARG NODE=20\n"
          "FROM golang:1.21.5 AS build\n"
          "RUN go build \\\n  -o app .\n"
          "FROM build AS test\n"
          "FROM node:${NODE}-alpine\n")
    rows = extract("svc/Dockerfile", df)
    assert [(r["package"], r["version"], r["stage"], r.get("scope"), r["line"]) for r in rows] == [
        ("docker.io/library/golang", "1.21.5", "build", "dev", 2),
        ("docker.io/library/node", "20-alpine", "final", None, 6)]
    assert parse_image_ref("gcr.io/distroless/static@sha256:ab")["digest"] == "sha256:ab"
    assert parse_image_ref("ghcr.io/acme/api:1.4")["repository"] == "acme/api"


def test_yaml_ci_and_helm():
    ci = extract(".github/workflows/ci.yml",
                 "    strategy:\n      matrix:\n        node-version: [16, 18.x]\n"
                 "      - uses: actions/setup-python@v5\n        with:\n          python-version: '3.11'\n")
    assert {(r["package"], r["version"], r.get("scope")) for r in ci} == {
        ("node", "16.0.0", "dev"), ("node", "18.0.0", "dev"), ("python", "3.11.0", "dev")}
    k8s = extract("deploy/k8s/app.yaml", "containers:\n- image: node:20-alpine\n  image: ghcr.io/acme/api:1.4\n")
    assert {r["package"] for r in k8s} == {"docker.io/library/node", "ghcr.io/acme/api"}
    helm = extract("charts/api/values.yaml", "image:\n  repository: python\n  tag: \"3.11-slim\"\n")
    assert [(r["package"], r["version"]) for r in helm] == [("docker.io/library/python", "3.11-slim")]


# ---- image expansion -------------------------------------------------------------------

def test_expand_resolved_fallback_and_build_stage():
    inv = extract("Dockerfile", "FROM golang:1.21 AS build\nFROM ruby:3.2-slim-bookworm\n")

    def resolve(registry, repository, ref):
        return {"env": {"RUBY_VERSION": "3.2.11"}} if repository == "library/ruby" else None

    rows = expand_image_runtimes(inv, resolve)
    got = {(r["ecosystem"], r["package"], r["version"], r["version_source"], r.get("scope")) for r in rows}
    assert ("Runtime", "ruby", "3.2.11", "resolved_tag", None) in got
    # build stage + no resolution: tag text at its minimum; Go bakes its stdlib -> not dev
    assert ("Runtime", "go", "1.21.0", "minimum", None) in got
    assert ("OS", "debian", "bookworm", "image_tag", None) in got


# ---- findings ----------------------------------------------------------------------------

_CYCLES = {"ruby": [{"cycle": "3.4", "eol": "2028-03-31", "latest": "3.4.7"},
                    {"cycle": "3.2", "eol": "2026-03-31", "latest": "3.2.11"}],
           "debian": [{"cycle": "12", "eol": "2028-06-10", "codename": "Bookworm", "latest": "12.9"}]}


def test_findings_cves_eol_and_ranges():
    inv = [{"file": ".ruby-version", "ecosystem": "Runtime", "package": "ruby", "version": "3.2.2",
            "version_source": "exact", "spec": "3.2.2", "spec_kind": "exact", "line": 1},
           {"file": "pyproject.toml", "ecosystem": "Runtime", "package": "python", "version": "3.8.0",
            "version_source": "minimum", "spec": ">=3.8", "spec_kind": "range", "line": 3},
           {"file": "Dockerfile", "ecosystem": "OS", "package": "debian", "version": "bookworm",
            "version_source": "image_tag", "spec_kind": "line"}]

    def advisories(rt, v):
        return [{"id": "CVE-2026-132825", "aliases": [], "summary": "heap overflow", "cvss_score": 7.4,
                 "severity": "", "fixed": ["3.3.14", "3.2.1"], "cwe_ids": ["CWE-122"]}] if rt == "ruby" else []

    eol = lambda product: _CYCLES.get(product) or [{"cycle": "3.8", "eol": "2024-10-07", "latest": "3.8.20"}]
    rows = runtime_findings("o/r", inv, advisories, eol, today=date(2026, 11, 21), kev_cve_set=set())
    by = {r["vuln_id"]: r for r in rows}
    assert by["CVE-2026-132825"]["fix_versions"] == "3.3.14"          # only fixes newer than 3.2.2
    assert by["CVE-2026-132825"]["eol_date"] == "2026-03-31"
    assert by["EOL-ruby-3.2"]["severity"] == "HIGH" and by["EOL-ruby-3.2"]["fix_versions"] == "3.4.7"
    assert "EOL-python-3.8" not in by                                 # open range names no line
    assert not any(k.startswith("EOL-debian") for k in by)            # bookworm still supported
    assert all(r["source"] == "RUNTIME" for r in rows)


# ---- CVE.org range matching + merge ------------------------------------------------------

_RUBY_RECORD = {
    "cveMetadata": {"cveId": "CVE-2026-132825", "state": "PUBLISHED", "datePublished": "2026-11-01"},
    "containers": {"cna": {
        "affected": [{"vendor": "ruby-lang", "product": "Ruby", "versions": [
            {"version": "0", "lessThan": "3.3.14", "status": "affected", "versionType": "semver"},
            {"version": "3.4.0", "lessThan": "3.4.13", "status": "affected", "versionType": "semver"},
            {"version": "4.0.0", "lessThan": "4.0.10", "status": "affected", "versionType": "semver"}]}],
        "descriptions": [{"lang": "en", "value": "Ruby before 3.3.14 ..."}],
        "metrics": [{"cvssV3_1": {"baseScore": 7.4, "vectorString": "CVSS:3.1/AV:N"}}]}}}


def test_cvelist_record_and_ranges():
    cid, rec = _summarize(_RUBY_RECORD)
    assert cid == "CVE-2026-132825" and list(rec["runtimes"]) == ["ruby"] and rec["cvss_score"] == 7.4
    versions = rec["runtimes"]["ruby"][0]
    assert affected_fix(versions, "3.2.11") == (True, "3.3.14")
    assert affected_fix(versions, "3.3.14") == (False, None)
    assert affected_fix(versions, "3.4.12") == (True, "3.4.13")
    assert affected_fix(versions, "4.0.10") == (False, None)
    assert affected_fix([{"version": "< 1.77.2", "status": "affected"}], "1.60.0") == (True, "1.77.2")
    assert affected_fix([{"version": "n/a", "status": "affected"}], "1.0.0") == (False, None)


def test_merge_three_sources():
    osv = {"id": "BIT-ruby-2024-27282", "aliases": ["CVE-2024-27282"], "summary": "", "cvss_score": None,
           "severity": "", "fixed": ["3.3.1"], "cwe_ids": [], "sources": ["OSV"]}
    cve = {"id": "CVE-2024-27282", "aliases": [], "summary": "regex", "cvss_score": 6.6,
           "severity": "CVSS:3.1/x", "fixed": ["3.2.4"], "cwe_ids": ["CWE-125"], "sources": ["CVE.org"]}
    other = {"id": "CVE-2026-1", "aliases": [], "summary": "x", "cvss_score": 5.0, "severity": "",
             "fixed": [], "cwe_ids": [], "sources": ["NVD"]}
    merged = _merge([osv, cve, other])
    assert len(merged) == 2
    m = merged[0]
    assert m["id"] == "BIT-ruby-2024-27282" and m["cvss_score"] == 6.6 and m["summary"] == "regex"
    assert set(m["fixed"]) == {"3.3.1", "3.2.4"} and m["sources"] == ["OSV", "CVE.org"]


# ---- SSRF guard: repo-controlled registry hosts are never contacted ----------------

def test_image_resolver_only_contacts_public_registries(tmp_path, monkeypatch):
    import requests

    from dkatchr.clients import image_tags
    calls = []
    monkeypatch.setattr(requests, "get", lambda url, **kw: calls.append(url) or (_ for _ in ()).throw(
        AssertionError("network")))
    r = image_tags.ImageTagResolver(str(tmp_path))
    for host in ("169.254.169.254", "10.0.0.5:5000", "registry.internal.corp", "localhost:5000"):
        assert r.resolve(host, "x/app", "1.0") is None
    assert r.resolve("docker.io", "library/ruby", "3.2;rm -rf") is None
    assert calls == []
    assert not list(tmp_path.joinpath("image_tags").iterdir())     # nothing cached either


def test_token_realm_must_be_the_registry_auth_host():
    from dkatchr.clients.image_tags import ImageTagResolver
    evil = 'Bearer realm="http://169.254.169.254/latest",service="x",scope="y"'
    assert ImageTagResolver._anonymous_token(evil, ("auth.docker.io",)) is None
    other = 'Bearer realm="https://attacker.example/token",service="x"'
    assert ImageTagResolver._anonymous_token(other, ("auth.docker.io",)) is None


def test_vendored_third_party_files_are_not_the_repos_runtime():
    assert not is_runtime_source(".github/actions/x/node_modules/tunnel/package.json")
    assert not is_runtime_source("vendor/github.com/foo/bar/go.mod")
    assert is_runtime_source("web/package.json")


def test_spec_coarser_than_a_release_line_reports_nothing():
    inv = [{"file": "ci.yml", "ecosystem": "Runtime", "package": "python", "version": "3.0.0",
            "version_source": "minimum", "spec": "3.x", "spec_kind": "line", "precision": 1},
           {"file": ".nvmrc", "ecosystem": "Runtime", "package": "node", "version": "18.0.0",
            "version_source": "minimum", "spec": "18", "spec_kind": "line", "precision": 1}]
    py = [{"cycle": "3.12", "eol": "2028-10-31", "latest": "3.12.8"},
          {"cycle": "3.0", "eol": "2009-06-27", "latest": "3.0.1"}]
    node = [{"cycle": "22", "eol": "2027-04-30", "latest": "22.11.0"},
            {"cycle": "18", "eol": "2025-04-30", "latest": "18.20.5"}]
    adv = lambda rt, v: [{"id": "CVE-X", "aliases": [], "fixed": ["99"], "cwe_ids": []}]
    rows = runtime_findings("o/r", inv, adv, lambda p: py if p == "python" else node,
                            today=date(2026, 11, 22))
    assert {r["package"] for r in rows} == {"node"}            # "3.x" names no Python line
    assert "EOL-node-18" in {r["vuln_id"] for r in rows}        # "18" IS a Node line


def test_imprecise_versions_report_only_whole_line_cves():
    inv = [{"file": "go.mod", "ecosystem": "Runtime", "package": "go", "version": "1.20.0",
            "version_source": "minimum", "spec": "1.20", "spec_kind": "line", "precision": 2},
           {"file": ".go-version", "ecosystem": "Runtime", "package": "go", "version": "1.20.3",
            "version_source": "exact", "spec": "1.20.3", "spec_kind": "exact", "precision": 3}]
    cycles = [{"cycle": "1.24", "eol": False, "latest": "1.24.5"},
              {"cycle": "1.20", "eol": "2024-02-06", "latest": "1.20.14"}]
    advs = [{"id": "CVE-PATCHED", "aliases": [], "fixed": ["1.20.5", "1.21.1"], "cwe_ids": []},
            {"id": "CVE-WHOLE-LINE", "aliases": [], "fixed": ["1.22.0"], "cwe_ids": []}]
    rows = runtime_findings("o/r", inv, lambda rt, v: advs, lambda p: cycles, today=date(2026, 11, 22))
    by_ver = {}
    for r in rows:
        by_ver.setdefault(r["version"], set()).add(r["vuln_id"])
    assert by_ver["1.20.0"] == {"CVE-WHOLE-LINE", "EOL-go-1.20"}       # patched-on-line CVE dropped
    assert by_ver["1.20.3"] == {"CVE-PATCHED", "CVE-WHOLE-LINE", "EOL-go-1.20"}   # exact keeps all


def test_registry_suse_is_a_public_registry_with_its_own_auth_host():
    from dkatchr.config import PUBLIC_IMAGE_REGISTRIES
    assert PUBLIC_IMAGE_REGISTRIES["registry.suse.com"]["auth"] == ("scc.suse.com",)
