"""Regression tests for the P0 bugs found by the 10-repo scanner evaluation
(2026-11-20): >1 MB manifests, dedupe hiding resolved versions from OSV, Go
subpackage imports, RubyGems platform versions, and the malware-title marker."""

import base64
import json

from dkatchr.clients.github import GitHubClient
from dkatchr.config import MALWARE_SUMMARY_MARKERS, REACHABILITY_CACHE_SCHEMA
from dkatchr.core.inventory import dedupe_inventory, extract_file_inventory
from dkatchr.core.osv_enrichment import osv_enrich
from dkatchr.core.reachability import _build_patterns
from dkatchr.parsers.ruby import from_gemfile_lock
from dkatchr.storage.reachability_cache import ReachabilityCache


# ---- 1. large files via the blobs API --------------------------------------

class _Json:
    def __init__(self, payload):
        self._p = payload

    def json(self):
        return self._p


def _gh(responses, calls):
    c = GitHubClient.__new__(GitHubClient)
    c.api_base = "https://api.github.com"

    def fake_get(url, params=None):
        calls.append(url)
        return _Json(responses[url.rsplit("/", 2)[-2]])
    c.get = fake_get
    return c


def test_large_file_falls_back_to_blob_api():
    text = '{"lockfileVersion": 3}'
    calls: list[str] = []
    gh = _gh({
        # contents API: file too large to inline
        "contents": {"encoding": "none", "content": "", "size": 2_500_000, "sha": "abc"},
        "blobs": {"encoding": "base64", "content": base64.b64encode(text.encode()).decode()},
    }, calls)
    assert gh.fetch_file("o", "r", "package-lock.json", "main") == text
    assert gh.get_file_contents("o", "r", "package-lock.json", "main") == text
    assert any(u.endswith("/git/blobs/abc") for u in calls)


def test_small_file_uses_inline_content():
    calls: list[str] = []
    gh = _gh({"contents": {"encoding": "base64", "size": 2,
                           "content": base64.b64encode(b"{}").decode(), "sha": "x"}}, calls)
    assert gh.fetch_file("o", "r", "package.json", "main") == "{}"
    assert len(calls) == 1


# ---- 2. dedupe keeps resolved versions visible to OSV ------------------------

def test_declared_and_resolved_same_version_stays_resolved():
    inv = dedupe_inventory([
        {"file": "package.json", "ecosystem": "npm", "package": "js-yaml",
         "version": "4.1.0", "version_source": "declared"},
        {"file": "yarn.lock", "ecosystem": "npm", "package": "js-yaml",
         "version": "4.1.0", "version_source": "resolved"},
        {"file": "yarn.lock", "ecosystem": "npm", "package": "js-yaml",
         "version": "3.14.1", "version_source": "resolved"},
    ])
    row = next(r for r in inv if r["version"] == "4.1.0")
    assert row["file"] == "package.json"          # blame still on the manifest
    assert row["version_source"] == "resolved"


def test_osv_queries_merged_version():
    inv = dedupe_inventory([
        {"file": "package.json", "ecosystem": "npm", "package": "js-yaml",
         "version": "4.1.0", "version_source": "declared"},
        {"file": "yarn.lock", "ecosystem": "npm", "package": "js-yaml",
         "version": "4.1.0", "version_source": "resolved"},
        {"file": "yarn.lock", "ecosystem": "npm", "package": "js-yaml",
         "version": "3.14.1", "version_source": "resolved"},
    ])

    queried: list[tuple] = []

    class _Osv:
        def get_cached_ids(self, *t):
            return None

        def query_batch(self, chunk):
            queried.extend(chunk)
            return [[] for _ in chunk]

        def set_cached_ids(self, *a):
            pass

        def save_index(self):
            pass

    osv_enrich({"o/r": inv}, _Osv())
    assert ("npm", "js-yaml", "4.1.0") in queried
    assert ("npm", "js-yaml", "3.14.1") in queried


# ---- 3. Go subpackage imports ------------------------------------------------

def test_go_patterns_match_subpackages():
    pats = _build_patterns(["k8s.io/client-go"], "Go")
    assert '"k8s.io/client-go"' in pats
    assert '"k8s.io/client-go/' in pats
    src = 'import "k8s.io/client-go/kubernetes"'
    assert any(p in src for p in pats)
    assert not any(p in 'import "k8s.io/client-gofoo"' for p in pats)


def test_reachability_cache_rejects_old_schema(tmp_path):
    cache = ReachabilityCache(str(tmp_path))
    cache.write("o/r", "abc", {"x::Go": {"label": "UNUSED", "evidence": []}}, {})
    assert cache.read("o/r", "abc")[0] is not None
    path = cache._path("o/r", "abc")
    data = json.load(open(path))
    data["schema"] = REACHABILITY_CACHE_SCHEMA - 1
    json.dump(data, open(path, "w"))
    assert cache.read("o/r", "abc") == (None, None)


# ---- 4. RubyGems platform versions ------------------------------------------

def test_gemfile_lock_strips_platform_suffix():
    lock = """GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.18.10-arm64-darwin)
      racc (~> 1.4)
    nokogiri (1.18.10-x86_64-linux-gnu)
      racc (~> 1.4)
    ffi (1.16.3-java)
    rails (7.1.0)
    pre (1.0.0-rc1)

PLATFORMS
  arm64-darwin
"""
    rows = from_gemfile_lock(lock)
    versions = {(r["package"], r["version"]) for r in rows}
    assert ("nokogiri", "1.18.10") in versions
    assert ("ffi", "1.16.3") in versions
    assert ("rails", "7.1.0") in versions
    assert ("pre", "1.0.0-rc1") in versions          # prerelease untouched
    assert sum(1 for r in rows if r["package"] == "nokogiri") == 1
    assert extract_file_inventory("Gemfile.lock", lock)


# ---- 5. malware-title marker -------------------------------------------------

def _flags(summary: str) -> bool:
    low = summary.lower()
    return any(m in low for m in MALWARE_SUMMARY_MARKERS)


def test_malware_markers():
    assert _flags("Malware in ctx")
    assert _flags("Malicious Package in flatmap-stream")
    assert _flags("Malicious code in bb-builder")
    assert not _flags("NLTK: Missing Post-Download Integrity Verification "
                      "Allows Malicious Package Injection")
    assert not _flags("Babel vulnerable when compiling specifically crafted malicious code")
