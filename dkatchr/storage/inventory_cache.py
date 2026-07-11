"""
Per-repo inventory cache.

MOVED FROM: dkatchr/inventory_cache.py
WHY: It's local filesystem storage — belongs in storage/, separated from
both the network clients and the business logic that uses it.

Two on-disk pieces:
  index.json                  — {full_name: {sha: ...}} — cache key
  {owner}__{repo}.json        — {schema: int, deps: [...]} — full inventory

Cache key is the commit SHA. If sha matches, we can reuse the inventory and
skip the tree+manifest fetches entirely. Cache is rule-agnostic: rules apply
at read time, so swapping rule sets costs zero API calls.
"""

import json
import os
import re
import threading

from dkatchr.config import CACHE_SCHEMA


class InventoryCache:
    def __init__(self, cache_dir: str) -> None:
        self.cache_dir   = cache_dir
        self.index_path  = os.path.join(cache_dir, "index.json")
        self._lock       = threading.Lock()
        os.makedirs(cache_dir, exist_ok=True)
        self.index: dict = self._load_index()

    # ---- index ----------------------------------------------------------

    def _load_index(self) -> dict:
        if not os.path.exists(self.index_path):
            return {}
        try:
            with open(self.index_path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def save_index(self) -> None:
        with self._lock:
            tmp = self.index_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.index, f, indent=2)
            os.replace(tmp, self.index_path)

    def get_index_sha(self, full_name: str) -> str | None:
        entry = self.index.get(full_name) or {}
        return entry.get("sha")

    def update_index(self, full_name: str, sha: str) -> None:
        with self._lock:
            self.index[full_name] = {"sha": sha}

    # ---- per-repo files -------------------------------------------------

    def repo_path(self, owner: str, repo: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", f"{owner}__{repo}")
        return os.path.join(self.cache_dir, f"{safe}.json")

    def read(self, owner: str, repo: str) -> list[dict] | None:
        """Return inventory list if schema matches, else None (= miss)."""
        path = self.repo_path(owner, repo)
        if not os.path.exists(path):
            return None
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return None
        if not isinstance(data, dict) or data.get("schema") != CACHE_SCHEMA:
            return None
        deps = data.get("deps")
        return deps if isinstance(deps, list) else None

    def write(self, owner: str, repo: str, deps: list[dict]) -> None:
        path = self.repo_path(owner, repo)
        payload = {"schema": CACHE_SCHEMA, "deps": deps}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f)
