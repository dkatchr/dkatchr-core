"""
Per-manifest attribution cache.

WHY: The attribution pass ("Introduced By") makes two GitHub calls per manifest
file — fetch the file's text, then blame it. Both are pure functions of
(repo, manifest path, commit SHA): the same manifest at the same SHA always
returns the same text and the same blame. Cache that pair keyed on the triple so
re-scans of an unchanged branch cost zero attribution API calls.

On-disk layout:
  {cache_dir}/attribution/{owner}__{repo}__{path}__{sha}.json

Cache entry shape:
  {
    "schema":     1,
    "repo":       "owner/repo",
    "path":       "requirements.txt",
    "sha":        "abc123...",
    "cached_at":  "2026-06-02T12:34:56+00:00",
    "content":    "<raw manifest text>",
    "ranges":     [ {blame range dict}, ... ]   # the WHOLE file's blame, all
                                                 # packages — never per-package
  }

The value covers the entire manifest file (all packages in it), never a single
package: find_package_line() needs the text and resolve_attribution() needs the
blame ranges, so BOTH are stored. That's what lets a cache hit skip BOTH
get_file_contents and get_file_blame while still resolving each package's line.
find_package_line() + resolve_attribution() pick the right range per package at
read time, so swapping which packages are vulnerable costs zero API calls.

Mirrors dkatchr/storage/inventory_cache.py (schema-versioned JSON) and
reachability_cache.py (SHA-keyed per-entry files). Like both, it does NOT
TTL-expire or prune stale-SHA files — that's future sweep-job work.

Old files whose `schema` doesn't match ATTRIBUTION_CACHE_SCHEMA are silently
treated as misses and rebuilt.
"""

import json
import os
import re
from datetime import datetime, timezone

from dkatchr.config import ATTRIBUTION_CACHE_SCHEMA
from dkatchr.logger import log


class AttributionCache:
    def __init__(self, cache_dir: str) -> None:
        self.cache_dir = os.path.join(cache_dir, "attribution")
        os.makedirs(self.cache_dir, exist_ok=True)

    def _path(self, repo_full_name: str, manifest_path: str, sha: str) -> str:
        safe_repo = re.sub(r"[^A-Za-z0-9._-]", "_", repo_full_name.replace("/", "__"))
        safe_path = re.sub(r"[^A-Za-z0-9._-]", "_", manifest_path)
        safe_sha = re.sub(r"[^A-Za-z0-9]", "", sha)
        return os.path.join(self.cache_dir, f"{safe_repo}__{safe_path}__{safe_sha}.json")

    def read(
        self, repo_full_name: str, manifest_path: str, sha: str
    ) -> tuple[str, list[dict]] | tuple[None, None]:
        """Return (content, ranges) on hit, (None, None) on miss / bad shape."""
        path = self._path(repo_full_name, manifest_path, sha)
        if not os.path.exists(path):
            return None, None
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return None, None
        if not isinstance(data, dict) or data.get("schema") != ATTRIBUTION_CACHE_SCHEMA:
            return None, None
        content = data.get("content")
        ranges = data.get("ranges")
        if not isinstance(content, str) or not isinstance(ranges, list):
            return None, None
        return content, ranges

    def write(
        self, repo_full_name: str, manifest_path: str, sha: str, content: str, ranges: list[dict]
    ) -> None:
        """Persist the manifest text + full blame-ranges list. Best-effort —
        swallow write errors (a cache miss is always recoverable)."""
        path = self._path(repo_full_name, manifest_path, sha)
        payload = {
            "schema":    ATTRIBUTION_CACHE_SCHEMA,
            "repo":      repo_full_name,
            "path":      manifest_path,
            "sha":       sha,
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "content":   content,
            "ranges":    ranges,
        }
        try:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f)
            os.replace(tmp, path)
        except Exception as e:
            log(f"[attribution] cache write failed for {repo_full_name}:{manifest_path}: {e}")
