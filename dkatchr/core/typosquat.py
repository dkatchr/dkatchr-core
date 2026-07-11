"""
Typosquatting detection — pure logic, no I/O.

WHY: A dependency whose name closely resembles a POPULAR public package is a
classic supply-chain attack — the attacker registers "reqeusts" hoping a
developer typos "requests" (or an LLM/autocomplete does). This is a DIFFERENT
attack from dependency confusion: confusion targets YOUR INTERNAL names
republished publicly; typosquatting targets a POPULAR PUBLIC name. It is
complementary to the OSV/classification path — an already-REPORTED squat arrives
as a MAL- advisory; this catches the ones nobody has reported yet.

The detection is: for each installed registry dependency, measure Damerau-
Levenshtein edit distance against a ranked set of the ecosystem's top packages;
on a close (but non-zero) match, confirm via a MANDATORY registry-metadata gate
(recently created OR few downloads) before flagging. A close name alone is NOT
enough — a distance-1 neighbour of a popular package that is itself old and
widely downloaded is almost always a legitimate different package. Both the top
sets and the metadata lookup are injected: this module is pure.

What this module does NOT do: no HTTP (top sets are pre-fetched by
dkatchr/clients/top_packages.py; the registry lookup is the injected callable —
the SAME RegistryMetaClient.get_package_meta the confusion pass uses, reused not
duplicated), no DB, no threading, no CSV. Thresholds live in config.py.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Callable

from rapidfuzz.distance import DamerauLevenshtein

from dkatchr.config import (
    CONFUSION_LOW_DOWNLOADS,
    CONFUSION_RECENT_CREATION_DAYS,
    TYPOSQUAT_LONG_NAME_LEN,
    TYPOSQUAT_MIN_NAME_LEN,
)

# Callback signature: progress({"phase": "typosquat_lookup", "current", "total",
# "ecosystem", "package"}) — same contract as the other long-running core passes.
ProgressCb = Callable[[dict], None] | None

# Callable signature: lookup(ecosystem, name) -> dict | None with keys
# {exists, created_at, latest_version, downloads}. None = lookup failed → that
# candidate is skipped, never fatal. (RegistryMetaClient.get_package_meta.)
LookupFn = Callable[[str, str], dict | None]


def _normalize_pypi_name(name: str) -> str:
    """PEP 503: runs of -_. collapse to '-', lowercased. Kept local (not imported
    from core/confusion) so the two sibling passes stay decoupled."""
    return re.sub(r"[-_.]+", "-", name or "").lower()


def _canon_name(ecosystem: str, name: str) -> str:
    """Comparison identity: PyPI normalizes per PEP 503, npm lowercases (scoped
    @scope/pkg names are compared whole); other ecosystems match verbatim."""
    if ecosystem == "PyPI":
        return _normalize_pypi_name(name)
    if ecosystem == "npm":
        return (name or "").lower()
    return name or ""


def _max_distance_for(length: int) -> int:
    """Length-scaled edit-distance ceiling. Short names collide too easily, so
    they're never checked; longer names tolerate a second edit. Returns 0 to mean
    'do not check this name'."""
    if length < TYPOSQUAT_MIN_NAME_LEN:
        return 0
    return 2 if length >= TYPOSQUAT_LONG_NAME_LEN else 1


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts or not isinstance(ts, str):
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _build_length_index(names: list[str], ecosystem: str) -> tuple[set[str], dict[int, list[str]]]:
    """Normalize a ranked top-name list into (membership set, length→names index).

    Names keep their rank order within each length bucket (the input is ranked
    highest-downloads first), so a distance tie is broken toward the more popular
    package. De-duplicates after normalization.
    """
    seen: set[str] = set()
    by_len: dict[int, list[str]] = {}
    for raw in names:
        canon = _canon_name(ecosystem, raw)
        if not canon or canon in seen:
            continue
        seen.add(canon)
        by_len.setdefault(len(canon), []).append(canon)
    return seen, by_len


def _closest_top(canon: str, max_dist: int, by_len: dict[int, list[str]]) -> tuple[str | None, int]:
    """Best (lowest-distance, then highest-rank) top name within `max_dist` of
    `canon`, or (None, 0). Only lengths within ±max_dist of len(canon) can match
    (a longer/shorter name needs at least that many edits) — the length index
    makes this sub-second on org-scale inventories."""
    best_name: str | None = None
    best_dist = max_dist + 1
    L = len(canon)
    for length in range(L - max_dist, L + max_dist + 1):
        for top in by_len.get(length, ()):
            d = DamerauLevenshtein.distance(canon, top, score_cutoff=max_dist)
            if 0 < d < best_dist:
                best_dist, best_name = d, top
                if best_dist == 1:      # can't do better than an edit distance of 1
                    return best_name, best_dist
    return (best_name, best_dist) if best_name is not None else (None, 0)


def _summary(package: str, ecosystem: str, similar_to: str, dist: int, meta: dict) -> str:
    created = meta.get("created_at")
    downloads = meta.get("downloads")
    parts = [
        f"Typosquatting risk: '{package}' closely resembles top {ecosystem} package "
        f"'{similar_to}' (edit distance {dist})"
    ]
    tail = []
    if created:
        tail.append(f"published {created[:10]}")
    if downloads is not None:
        tail.append(f"{downloads} downloads")
    if tail:
        parts.append("; " + ", ".join(tail))
    return "".join(parts) + "."


def detect_typosquats(
    per_repo_inventory: dict[str, list[dict]],
    top_sets: dict[str, list[str]],
    lookup: LookupFn,
    on_progress: ProgressCb = None,
    supported_ecosystems: frozenset[str] | set[str] | None = None,
) -> dict:
    """Run typosquatting detection across a scan's inventories.

    Args:
      per_repo_inventory: {repo_full_name: [deduped inventory rows]} — rows carry
        {file, ecosystem, package, version, version_source, origin}.
      top_sets: {ecosystem: [ranked top package names]} — pre-fetched by
        TopPackagesClient. An empty/absent list = that ecosystem is skipped.
      lookup: injected registry-metadata callable (RegistryMetaClient.
        get_package_meta). None result skips that candidate (never fatal).
      on_progress: optional phase callback ({"phase": "typosquat_lookup",
        "current", "total", "ecosystem", "package"}); emit failures swallowed.
      supported_ecosystems: candidates outside this set are counted as
        skipped_unsupported (pass the TopPackagesClient's SUPPORTED_ECOSYSTEMS).

    Returns {"findings": [finding dicts], "stats": {...}}. One finding per
    (implicated repo, candidate): source="TYPOSQUAT", vuln_id="TYPOSQUAT-{eco}-
    {canon}", severity HIGH, finding_type, summary, and the suspicion_signals
    dict {similar_to, edit_distance, created_at, downloads, latest_version,
    recent_creation, low_downloads, signals:["TYPOSQUAT"]}.
    """
    # Per-ecosystem normalized top-name membership set + length index (built once).
    top_index: dict[str, tuple[set[str], dict[int, list[str]]]] = {}
    for eco, names in (top_sets or {}).items():
        if names:
            top_index[eco] = _build_length_index(names, eco)

    # ---- candidate build: unique registry deps, keyed (ecosystem, canonical) --
    candidates: dict[tuple[str, str], dict] = {}
    for repo, inv in (per_repo_inventory or {}).items():
        for dep in inv or []:
            eco = dep.get("ecosystem")
            pkg = dep.get("package")
            if not eco or not pkg:
                continue
            # Only registry-installed deps can be typosquats — a path/git/
            # workspace dep resolves to a pinned source, not a name lookup.
            if (dep.get("origin", "registry") or "registry") != "registry":
                continue
            canon = _canon_name(eco, pkg)
            key = (eco, canon)
            c = candidates.get(key)
            if c is None:
                c = {"ecosystem": eco, "canon": canon, "package": pkg, "repos": {}}
                candidates[key] = c
            c["repos"].setdefault(repo, {
                "file":           dep.get("file", ""),
                "version":        dep.get("version", ""),
                "version_source": dep.get("version_source", ""),
                "origin":         dep.get("origin", "registry") or "registry",
            })

    stats = {"candidates": 0, "distance_hits": 0, "checked": 0, "public": 0,
             "findings": 0, "skipped_unsupported": 0, "skipped_unresolved": 0}

    # ---- distance pass: keep only candidates that resemble a top package -----
    # (deterministic order for stable progress + output)
    distance_hits: list[dict] = []
    for key in sorted(candidates):
        c = candidates[key]
        eco, canon = c["ecosystem"], c["canon"]
        if supported_ecosystems is not None and eco not in supported_ecosystems:
            stats["skipped_unsupported"] += 1
            continue
        if eco not in top_index:
            stats["skipped_unsupported"] += 1
            continue
        members, by_len = top_index[eco]
        # A name that IS a top package is not a squat of one.
        if canon in members:
            continue
        max_dist = _max_distance_for(len(canon))
        if max_dist == 0:
            continue
        stats["candidates"] += 1
        similar_to, dist = _closest_top(canon, max_dist, by_len)
        if similar_to is None:
            continue
        stats["distance_hits"] += 1
        c["similar_to"] = similar_to
        c["edit_distance"] = dist
        distance_hits.append(c)

    # ---- metadata gate: confirm each distance hit is suspicious --------------
    findings: list[dict] = []
    now = datetime.now(timezone.utc)
    total = len(distance_hits)

    for i, c in enumerate(distance_hits, 1):
        eco = c["ecosystem"]
        if on_progress:
            try:
                on_progress({"phase": "typosquat_lookup", "current": i, "total": total,
                             "ecosystem": eco, "package": c["package"]})
            except Exception:
                pass  # progress emit failures must never break the work

        # PyPI lookups use the canonical (PEP 503) name; others the raw name.
        lookup_name = c["canon"] if eco == "PyPI" else c["package"]
        meta = lookup(eco, lookup_name)
        stats["checked"] += 1
        if meta is None:
            stats["skipped_unresolved"] += 1
            continue
        if not meta.get("exists"):
            continue
        stats["public"] += 1

        created_dt = _parse_iso(meta.get("created_at"))
        recent = bool(created_dt is not None
                      and now - created_dt < timedelta(days=CONFUSION_RECENT_CREATION_DAYS))
        downloads = meta.get("downloads")
        low = downloads is not None and downloads < CONFUSION_LOW_DOWNLOADS
        # The gate: a close name is only a finding when the package ALSO looks
        # freshly-minted or barely-downloaded. A clean-metadata neighbour of a
        # popular package is almost always a legitimate different package.
        if not (recent or low):
            continue

        suspicion = {
            "similar_to":      c["similar_to"],
            "edit_distance":   c["edit_distance"],
            "created_at":      meta.get("created_at"),
            "downloads":       downloads,
            "latest_version":  meta.get("latest_version"),
            "recent_creation": recent,
            "low_downloads":   low,
            "signals":         ["TYPOSQUAT"],
        }
        summary = _summary(c["package"], eco, c["similar_to"], c["edit_distance"], meta)
        vuln_id = f"TYPOSQUAT-{eco}-{c['canon']}"

        for repo in sorted(c["repos"]):
            info = c["repos"][repo]
            findings.append({
                "repo":              repo,
                "file":              info["file"],
                "ecosystem":         eco,
                "package":           c["package"],
                "version":           info["version"],
                "version_source":    info["version_source"],
                "origin":            info["origin"],
                "source":            "TYPOSQUAT",
                "vuln_id":           vuln_id,
                "severity":          "HIGH",
                "finding_type":      "typosquatting risk",
                "summary":           summary,
                "suspicion_signals": suspicion,
            })
            stats["findings"] += 1

    return {"findings": findings, "stats": stats}
