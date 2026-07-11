"""
Inventory extraction — turn a manifest file's text into inventory rows.

MOVED FROM: dkatchr/output.py (extract_file_inventory).
WHY: This function dispatches parsers, which is core logic, not output
formatting. The old name 'output.py' hid that.
"""

import os

from dkatchr.parsers import manifest_handler


def extract_file_inventory(file_path: str, content: str) -> list[dict]:
    """
    Run the appropriate parser for this filename and return inventory rows
    tagged with file path + ecosystem. Rule-agnostic.
    """
    filename = os.path.basename(file_path)
    handler = manifest_handler(filename)
    if handler is None:
        return []
    ecosystem, parser = handler
    out = []
    for dep in parser(content):
        row = {
            "file":           file_path,
            "ecosystem":      ecosystem,
            "package":        dep["package"],
            "version":        dep["version"],
            "version_source": dep["version_source"],
            # Where the dependency resolves from. Parsers set a non-registry
            # origin (path|git|workspace|url) only when they detect one;
            # "registry" is materialized here so every row carries the field
            # (the dependency-confusion pass and the CSV/DB layers read it).
            "origin":         dep.get("origin", "registry"),
        }
        # The URL the lockfile records the dep as resolving from — carried
        # only when the format records one (absent = no signal, deliberately
        # NOT materialized: absence must never read as public or private).
        # Consumed by the Dependency Confusion Exposure audit check.
        if dep.get("resolved_url"):
            row["resolved_url"] = dep["resolved_url"]
        out.append(row)
    return out


def dedupe_inventory(inventory: list[dict]) -> list[dict]:
    """
    Collapse duplicate dependencies to one row each.

    The dedup key is (ecosystem, package, version) — deliberately NOT including
    `file`. The SAME exact (eco, package, version) can legitimately appear in two
    files of one repo: Go pins exact versions in BOTH go.mod (version_source
    "declared") and go.sum ("resolved"), so keying on file would inventory — and
    report — the dep twice (one row per file → duplicate OSV findings). It also
    still collapses a dep listed in multiple sections of one manifest (e.g.
    dependencies + devDependencies in package.json).

    When the same (eco, package, version) appears as both a declared and a
    resolved entry, the DECLARED one wins. The version is identical in that case,
    so this is purely about which file/source label is kept — and the declared
    manifest (e.g. go.mod over go.sum) is the better one: it's the human-facing
    file, so the "Introduced By" git-blame attributes to whoever ADDED the
    dependency, not whoever last regenerated the lockfile's checksums (go.sum
    churns on every `go mod tidy`/build and is often rewritten by a tidy/bot
    commit). OSV/reachability are unaffected — the version is the same either way.

    npm / RubyGems are unaffected: their declared entry is a semver RANGE, so its
    version differs from the resolved pin → the two are NOT collapsed (and the
    declared range yields no OSV rows anyway, since osv_enrich only queries the
    resolved version). Transitive deps that exist only in a lockfile keep their
    single entry.

    MOVED FROM: dkatchr/scanner.py (was _dedupe_inventory).
    WHY: It's a pure inventory operation, reusable outside scan_repo.
    """
    best: dict[tuple, dict] = {}
    order: list[tuple] = []
    for dep in inventory:
        key = (dep.get("ecosystem", ""), dep.get("package", ""),
               dep.get("version", ""))
        existing = best.get(key)
        if existing is None:
            best[key] = dep
            order.append(key)
            continue
        if (existing.get("version_source") == "resolved"
                and dep.get("version_source") != "resolved"):
            # We kept a resolved (lockfile) entry, but this one is declared
            # (manifest) for the same exact version — prefer the declared
            # manifest so blame lands on the file where the dep was added.
            best[key] = dep
            kept, other = dep, existing
        else:
            kept, other = existing, dep
        # OR-merge internality: if EITHER merged row carried a non-registry
        # origin, the surviving row keeps it. A dep that is path/git/workspace
        # in one manifest is internal, period — the registry-shaped duplicate
        # must not wash that signal out of the confusion pass.
        if (kept.get("origin", "registry") == "registry"
                and other.get("origin", "registry") != "registry"):
            kept["origin"] = other["origin"]
    return [best[k] for k in order]
