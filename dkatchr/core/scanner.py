"""
Scanner — orchestrates per-repo work.

MOVED FROM: dkatchr/scanner.py
WHY: It's pure orchestration logic — given a repo dict, cache, and GitHub
client, produce an inventory + rule-matched rows. It doesn't know about
argparse, CSV files, threading pools, or the database. Belongs in core/.

Scanner.scan_repo(repo) does one repo end-to-end:
  - SHA check
  - Cache lookup
  - Tree fetch + manifest extraction (on miss)
  - Cache write
  - Apply rules → CSV-shaped rows

The result dict is consumed by:
  - the CLI runner (cli/run.py), which writes CSV
  - the web ScanRunner (web/services/scan_runner.py), which writes SQLite

Both pass an optional `on_progress` callback so long-running scans can
emit fine-grained UI events.
"""

import os
from typing import Callable

from dkatchr.clients.github import GitHubClient
from dkatchr.core.inventory import dedupe_inventory, extract_file_inventory
from dkatchr.core.rules import apply_rules
from dkatchr.logger import log, repo_log
from dkatchr.parsers import manifest_handler
from dkatchr.storage.inventory_cache import InventoryCache

# Callback signature: progress({"phase": str, ...}) — emit liveness/progress
# events from inside scan_repo. Used by the web layer to push fine-grained
# updates over WebSocket so big repos don't look frozen.
ProgressCb = Callable[[dict], None] | None


class Scanner:
    def __init__(
        self,
        github: GitHubClient,
        cache: InventoryCache,
        package_config: dict,
    ) -> None:
        self.github         = github
        self.cache          = cache
        self.package_config = package_config

    def scan_repo(self, repo: dict, prefix: str, full_rescan: bool,
                   on_progress: ProgressCb = None) -> dict:
        """
        Returns:
          {
            full_name:  str,
            skipped:    bool,
            rows:       list[dict],   # rule-matched CSV rows
            inventory:  list[dict],   # full inventory (for OSV pass)
            from_cache: bool,
            sha:        str | None,
            error:      str | None,
          }
        """
        owner     = repo["owner"]["login"]
        name      = repo["name"]
        full_name = repo["full_name"]
        branch    = repo.get("default_branch")

        result: dict = {
            "full_name":  full_name,
            "skipped":    False,
            "rows":       [],
            "inventory":  [],
            "from_cache": False,
            "sha":        None,
            "error":      None,
        }

        if repo.get("archived"):
            repo_log(f"{prefix} Skip (archived): {full_name}")
            result["skipped"] = True
            return result
        if not branch:
            repo_log(f"{prefix} Skip (no default branch): {full_name}")
            result["skipped"] = True
            return result

        repo_log(f"{prefix} {full_name} @ {branch}")

        if on_progress:
            on_progress({"phase": "branch_sha", "full_name": full_name})

        try:
            sha = self.github.get_branch_sha(owner, name, branch)
        except Exception as e:
            log(f"    [!] {full_name}: could not get branch SHA: {e}")
            result["error"] = str(e)
            return result
        result["sha"] = sha

        # Cache lookup
        inventory: list[dict] | None = None
        if not full_rescan:
            cached = self.cache.read(owner, name)
            if cached is not None and self.cache.get_index_sha(full_name) == sha:
                inventory = cached
                result["from_cache"] = True

        # Cold path — fetch tree + manifests
        if inventory is None:
            if on_progress:
                on_progress({"phase": "tree_fetch", "full_name": full_name})
            try:
                tree = self.github.get_repo_tree(owner, name, sha)
            except Exception as e:
                log(f"    [!] {full_name}: could not get repo tree: {e}")
                result["error"] = str(e)
                return result

            # Collect manifest blobs first so we know the total upfront —
            # gives the UI a denominator and lets us emit % progress.
            manifest_blobs = [
                n for n in tree
                if n.get("type") == "blob"
                and manifest_handler(os.path.basename(n.get("path", ""))) is not None
            ]
            total_manifests = len(manifest_blobs)
            if on_progress:
                on_progress({"phase": "manifests_found", "full_name": full_name,
                              "total": total_manifests})

            inventory = []
            for i, node in enumerate(manifest_blobs, 1):
                path = node.get("path", "")
                try:
                    content = self.github.fetch_file(owner, name, path, branch)
                except Exception as e:
                    log(f"    [!] {full_name}: could not fetch {path}: {e}")
                    if on_progress and (i % 5 == 0 or i == total_manifests):
                        on_progress({"phase": "fetching_manifests", "full_name": full_name,
                                      "fetched": i, "total": total_manifests})
                    continue
                if not content:
                    continue

                inventory.extend(extract_file_inventory(path, content))

                # Tick every 5 manifests (or at the end). Cheap, keeps UI alive.
                if on_progress and (i % 5 == 0 or i == total_manifests):
                    on_progress({"phase": "fetching_manifests", "full_name": full_name,
                                  "fetched": i, "total": total_manifests})

            try:
                self.cache.write(owner, name, inventory)
            except Exception as e:
                log(f"    [!] {full_name}: cache write error: {e}")

        # Collapse duplicates — applies to BOTH cache-hit and cold paths so
        # stale caches written before this fix get cleaned on read.
        inventory = dedupe_inventory(inventory)

        rows = apply_rules(inventory, self.package_config, full_name)
        vuln = sum(1 for r in rows if r.get("status") == "vulnerable")
        tag  = "[CACHE]" if result["from_cache"] else "       "
        repo_log(f"    {tag} {full_name}: inventory={len(inventory)}, rule_hits={len(rows)}, rule_vulnerable={vuln}")

        result["rows"]      = rows
        result["inventory"] = inventory
        return result
