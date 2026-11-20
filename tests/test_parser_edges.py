"""Every lockfile parser attaches `depends_on`; edge-less formats don't; the
inventory layer passes it through and dedupe merges it."""

import json

from dkatchr.core.inventory import dedupe_inventory, extract_file_inventory
from dkatchr.parsers import cargo, composer, npm, nuget, pypi, ruby


def _edges(rows):
    return {r["package"]: r.get("depends_on") for r in rows}


def test_cargo_lock():
    lock = ('[[package]]\nname = "reqwest"\nversion = "0.11.0"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            'dependencies = [\n "rustls 0.21.0",\n "webpki-roots",\n]\n\n'
            '[[package]]\nname = "webpki-roots"\nversion = "0.25.0"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n')
    assert _edges(cargo.from_cargo_lock(lock)) == {"reqwest": ["rustls", "webpki-roots"],
                                                  "webpki-roots": []}


def test_poetry_lock_keeps_optional_extras_edges():
    lock = ('[[package]]\nname = "requests"\nversion = "2.31.0"\n\n[package.dependencies]\n'
            'certifi = ">=2017.4.17"\n'
            'PySocks = {version = ">=1.5.6", optional = true}\n\n'
            '[package.extras]\nsocks = ["PySocks"]\n\n'
            '[[package]]\nname = "certifi"\nversion = "2024.7.4"\n')
    assert _edges(pypi.from_poetry_lock(lock)) == {"requests": ["certifi", "PySocks"], "certifi": []}


def test_edge_less_formats_carry_no_edges():
    assert "depends_on" not in pypi.from_requirements_txt("certifi==2024.7.4\n")[0]
    assert "depends_on" not in npm.from_package_json(json.dumps({"dependencies": {"a": "^1.0.0"}}))[0]


def test_package_lock_v1_and_v3():
    v3 = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/axios": {
        "version": "1.6.0", "dependencies": {"follow-redirects": "^1"}, "peerDependencies": {"x": "*"}},
        "node_modules/follow-redirects": {"version": "1.15.0"}}}
    assert _edges(npm.from_package_lock(json.dumps(v3))) == {
        "axios": ["follow-redirects", "x"], "follow-redirects": []}
    v1 = {"lockfileVersion": 1, "dependencies": {"axios": {"version": "0.21.0", "requires": {
        "follow-redirects": "^1"}}, "follow-redirects": {"version": "1.13.0"}}}
    assert _edges(npm.from_package_lock(json.dumps(v1)))["axios"] == ["follow-redirects"]


def test_yarn_classic_and_berry():
    classic = ('"@babel/core@^7.0.0":\n  version "7.20.0"\n  dependencies:\n'
               '    "@babel/generator" "^7.20.0"\n    debug "^4.1.0"\n\n'
               'debug@^4.1.0:\n  version "4.3.4"\n')
    assert _edges(npm.from_yarn_lock(classic)) == {"@babel/core": ["@babel/generator", "debug"],
                                                   "debug": []}
    berry = ('__metadata:\n  version: 6\n\n"debug@npm:^4.1.0":\n  version: 4.3.4\n'
             '  dependencies:\n    ms: 2.1.2\n\n"ms@npm:2.1.2":\n  version: 2.1.2\n')
    assert _edges(npm.from_yarn_lock(berry)) == {"debug": ["ms"], "ms": []}


def test_pnpm_v5_v6_v9_parse_and_edges():
    v5 = ("lockfileVersion: 5.4\n\npackages:\n\n  /axios/0.21.0:\n    dependencies:\n"
          "      follow-redirects: 1.13.0\n\n  /follow-redirects/1.13.0:\n    dev: false\n")
    v6 = ("lockfileVersion: '6.0'\n\npackages:\n\n  /axios@0.21.0:\n    dependencies:\n"
          "      follow-redirects: 1.13.0(debug@4.3.4)\n\n"
          "  /follow-redirects@1.13.0(debug@4.3.4):\n    dev: false\n")
    v9 = ("lockfileVersion: '9.0'\n\npackages:\n\n  axios@1.6.0:\n    resolution: {}\n\n"
          "  '@scope/x@2.0.0':\n    resolution: {}\n\nsnapshots:\n\n  axios@1.6.0:\n"
          "    dependencies:\n      '@scope/x': 2.0.0\n\n  '@scope/x@2.0.0': {}\n")
    for text, expected in ((v5, {"axios": ["follow-redirects"], "follow-redirects": []}),
                           (v6, {"axios": ["follow-redirects"], "follow-redirects": []}),
                           (v9, {"axios": ["@scope/x"], "@scope/x": []})):
        assert _edges(npm.from_pnpm_lock(text)) == expected


def test_gemfile_composer_nuget():
    gl = ("GEM\n  remote: https://rubygems.org/\n  specs:\n    actionpack (7.0.4)\n"
          "      actionview (= 7.0.4)\n      rack (~> 2.0)\n    rack (2.2.4)\n\nDEPENDENCIES\n  actionpack\n")
    assert _edges(ruby.from_gemfile_lock(gl)) == {"actionpack": ["actionview", "rack"], "rack": []}
    cl = {"packages": [{"name": "a/b", "version": "1.0", "require": {
        "php": "^8", "ext-json": "*", "c/d": "^1"}}]}
    assert _edges(composer.from_composer_lock(json.dumps(cl))) == {"a/b": ["c/d"]}
    nl = {"dependencies": {"net6.0": {"Serilog": {"resolved": "2.12.0", "dependencies": {
        "System.Text.Json": "6.0.0"}}, "System.Text.Json": {"resolved": "6.0.0"}}}}
    assert _edges(nuget.from_packages_lock_json(json.dumps(nl)))["Serilog"] == ["System.Text.Json"]


def test_inventory_passthrough_and_dedupe_merge():
    rows = extract_file_inventory("poetry.lock", '[[package]]\nname = "certifi"\nversion = "1"\n')
    assert rows[0]["depends_on"] == []
    req = extract_file_inventory("requirements.txt", "certifi==1\n")
    assert "depends_on" not in req[0]
    merged = dedupe_inventory(req + rows)
    assert len(merged) == 1 and merged[0]["depends_on"] == []
