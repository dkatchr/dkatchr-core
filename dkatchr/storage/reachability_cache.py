"""
Per-repo reachability cache.

WHY: tarball-based reachability is expensive (download + scan can take seconds
per repo). Cache the per-package label decisions keyed on the branch SHA so
re-scans of an unchanged repo are free. The SHA is the natural invalidation
signal — when the repo changes, a new SHA produces a fresh cache file and the
old one is simply ignored.

On-disk layout:
  {cache_dir}/reachability/{owner}__{repo}__{sha}.json

Cache entry shape:
  {
    "repo":      "owner/repo",
    "sha":       "abc123...",
    "cached_at": "2026-05-18T12:34:56+00:00",
    "results": {
      "requests::PyPI":  {"label": "REACHABLE",     "evidence": ["src/api.py"]},
      "lodash::npm":     {"label": "UNUSED", "evidence": []},
    },
    "matched_patterns": {
      "import requests":  ["src/api.py"],
      "from requests import": [],
      "require('lodash')": [],
    }
  }

Key format for the results dict is "{package}::{ecosystem}".

Packages with failed resolution are intentionally omitted from `results`
(rather than written as UNKNOWN) so a future scan retries resolution
rather than replaying a stale error state. `matched_patterns` is the raw
Aho-Corasick output from the original scan — pattern string → list of
files where matched (empty if none). That lets a cache hit retry resolution
for those omitted packages and decide their label against the stored
matches, without re-downloading the tarball.

Does NOT: TTL-expire, prune old cache files, or know about the engine. Stale
SHAs accumulate on disk — that's intentional for now; a sweep job is future work.

Old cache files written before `matched_patterns` existed will fail the
shape check in `read()` and be silently treated as misses (the next scan
rebuilds them in the current shape). No versioning required.
"""

import json
import os
import re
from datetime import datetime, timezone

from dkatchr.logger import log


class ReachabilityCache:
    def __init__(self, cache_dir: str) -> None:
        self.cache_dir = os.path.join(cache_dir, "reachability")
        os.makedirs(self.cache_dir, exist_ok=True)

    def _path(self, repo_full_name: str, sha: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", repo_full_name.replace("/", "__"))
        safe_sha = re.sub(r"[^A-Za-z0-9]", "", sha)
        return os.path.join(self.cache_dir, f"{safe}__{safe_sha}.json")

    def read(
        self, repo_full_name: str, sha: str
    ) -> tuple[dict, dict] | tuple[None, None]:
        """Return (results, matched_patterns) on hit, (None, None) on miss or bad shape."""
        path = self._path(repo_full_name, sha)
        if not os.path.exists(path):
            return None, None
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return None, None
        if not isinstance(data, dict):
            return None, None
        results = data.get("results")
        matched_patterns = data.get("matched_patterns")
        if not isinstance(results, dict) or not isinstance(matched_patterns, dict):
            return None, None
        log(f"[reachability] cache hit for {repo_full_name} @ {sha[:8]}")
        return results, matched_patterns

    def write(
        self,
        repo_full_name: str,
        sha: str,
        results: dict,
        matched_patterns: dict,
    ) -> None:
        """Write results + matched_patterns to cache. Silently swallow any write errors."""
        path = self._path(repo_full_name, sha)
        payload = {
            "repo":             repo_full_name,
            "sha":              sha,
            "cached_at":        datetime.now(timezone.utc).isoformat(),
            "results":          results,
            "matched_patterns": matched_patterns,
        }
        try:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f)
            os.replace(tmp, path)
        except Exception as e:
            log(f"[reachability] cache write failed for {repo_full_name}: {e}")
