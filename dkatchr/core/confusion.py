"""
Dependency Confusion detection — pure logic, no I/O.

WHY: Internal/private package names that also exist on a public registry can
be silently substituted at install time (Birsan 2021). The detection is a
cross-repo set computation plus one registry lookup per candidate — pure
logic that both the CLI runner and the web scan runner call with their own
I/O at the edges.

Three suspicion signals build the candidate set:
  S1 manifest-internal : a dep's declared/resolved source is path/git/
                         workspace/url — not a registry (`origin` field).
  S2 declared-pattern  : the package name matches a user-declared internal
                         namespace glob (e.g. "acme-*", "@acme/*").
  S3 cross-repo        : the same (ecosystem, package) is manifest-internal
                         in one repo of the scan but a bare registry dep in
                         another repo of the SAME scan.

A candidate that EXISTS on the public registry becomes a finding. S2/S3 →
"dependency confusion risk" (HIGH); S1-only → "namespace exposure" (MEDIUM —
a pinned path/git dep cannot be silently confused at install time; the risk
is the claimed public name). Names that do NOT exist publicly produce no
finding (v1). The candidate set is S1 ∪ S2 ∪ S3 ONLY — never the whole
inventory.

What this module does NOT do: no HTTP (the registry lookup is an injected
callable — dkatchr/clients/registry_meta.py in production), no DB, no
threading, no CSV. Thresholds live in config.py.
"""

import fnmatch
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Callable

from dkatchr.config import (
    CONFUSION_INFLATED_MAJOR_VERSION,
    CONFUSION_LOW_DOWNLOADS,
    CONFUSION_RECENT_CREATION_DAYS,
)
from dkatchr.logger import log

# Callback signature: progress({"phase": str, ...}) — same contract as the
# other long-running core passes.
ProgressCb = Callable[[dict], None] | None

# Callable signature: lookup(ecosystem, name) -> dict | None with keys
# {exists, created_at, latest_version, downloads}. None = lookup failed →
# that candidate is skipped, never fatal.
LookupFn = Callable[[str, str], dict | None]

_MAJOR_RE = re.compile(r"^v?(\d+)")


def normalize_pypi_name(name: str) -> str:
    """PEP 503: runs of -_. collapse to '-', lowercased. Applied to PyPI
    names AND patterns before matching, and to PyPI registry lookups."""
    return re.sub(r"[-_.]+", "-", name or "").lower()


def load_internal_patterns(path: str | None) -> list[dict]:
    """Load internal namespace patterns from a JSON file:
        [{"ecosystem": "npm", "pattern": "@acme/*"}, ...]
    Mirrors load_package_config: a missing/invalid file logs and returns []
    (the pass still runs on S1 + S3 signals alone)."""
    if not path:
        return []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("top-level JSON value must be a list")
    except Exception as e:
        log(f"[!] Could not load internal patterns from {path}: {e} — "
            f"running without S2 (declared-pattern) signals.")
        return []
    patterns = []
    for entry in data:
        if (isinstance(entry, dict)
                and isinstance(entry.get("ecosystem"), str)
                and isinstance(entry.get("pattern"), str)
                and entry["pattern"].strip()):
            patterns.append({"ecosystem": entry["ecosystem"],
                             "pattern": entry["pattern"].strip()})
        else:
            log(f"[!] Skipping malformed internal-pattern entry: {entry!r}")
    return patterns


def _canon_name(ecosystem: str, name: str) -> str:
    """Candidate identity: PyPI names normalize per PEP 503 (Foo_Bar and
    foo-bar are the same project); other ecosystems match verbatim."""
    return normalize_pypi_name(name) if ecosystem == "PyPI" else name


def _match_pattern(ecosystem: str, canon: str, patterns_for_eco: list[str]) -> str | None:
    """First glob pattern the canonical name matches, or None. fnmatchcase is
    used so matching is deterministic across platforms (fnmatch.fnmatch is
    case-insensitive on macOS/Windows)."""
    for pat in patterns_for_eco:
        p = normalize_pypi_name(pat) if ecosystem == "PyPI" else pat
        if fnmatch.fnmatchcase(canon, p):
            return pat
    return None


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts or not isinstance(ts, str):
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _major_version(version: str | None) -> int | None:
    if not version or not isinstance(version, str):
        return None
    m = _MAJOR_RE.match(version.strip())
    return int(m.group(1)) if m else None


def _suspicion_signals(meta: dict, signals: list[str],
                       internal_repos: dict, bare_repos: dict,
                       now: datetime) -> dict:
    created_at = meta.get("created_at")
    downloads = meta.get("downloads")
    latest = meta.get("latest_version")

    created_dt = _parse_iso(created_at)
    recent = bool(
        created_dt is not None
        and now - created_dt < timedelta(days=CONFUSION_RECENT_CREATION_DAYS)
    )
    low = downloads is not None and downloads < CONFUSION_LOW_DOWNLOADS
    major = _major_version(latest)
    inflated = major is not None and major >= CONFUSION_INFLATED_MAJOR_VERSION

    out = {
        "created_at":       created_at,
        "downloads":        downloads,
        "latest_version":   latest,
        "recent_creation":  recent,
        "low_downloads":    low,
        "inflated_version": inflated,
        "signals":          signals,
    }
    if "S3" in signals:
        out["cross_repo"] = {
            "internal_in": sorted(internal_repos),
            "bare_in":     sorted(bare_repos),
        }
    return out


def _summary(package: str, ecosystem: str, signals: list[str], high: bool,
             matched_pattern: str | None, internal_repos: dict,
             bare_repos: dict, meta: dict) -> str:
    origins = sorted({info["origin"] for info in internal_repos.values()})
    parts = []
    if "S3" in signals:
        parts.append(
            f"is consumed as an internal ({'/'.join(origins)}) dependency in "
            f"{', '.join(sorted(internal_repos))} but installed from the "
            f"public registry in {', '.join(sorted(bare_repos))}"
        )
    elif "S1" in signals:
        parts.append(
            f"is declared as an internal ({'/'.join(origins)}) dependency in "
            f"{', '.join(sorted(internal_repos))}"
        )
    if matched_pattern:
        parts.append(f"matches internal namespace pattern '{matched_pattern}'")
    latest = meta.get("latest_version")
    label = "Dependency confusion risk" if high else "Namespace exposure"
    return (
        f"{label}: '{package}' "
        + "; ".join(parts)
        + f" — and the name exists on the public {ecosystem} registry"
        + (f" (latest {latest})" if latest else "")
        + "."
    )


def detect_confusion(
    per_repo_inventory: dict[str, list[dict]],
    patterns: list[dict],
    lookup: LookupFn,
    on_progress: ProgressCb = None,
    supported_ecosystems: frozenset[str] | set[str] | None = None,
) -> dict:
    """Run dependency-confusion detection across a scan's inventories.

    Args:
      per_repo_inventory: {repo_full_name: [deduped inventory rows]} — rows
        carry {file, ecosystem, package, version, version_source, origin}.
      patterns: [{"ecosystem", "pattern"}] internal namespace globs (S2 input;
        empty list = only S1 + S3 signals fire).
      lookup: injected registry-metadata callable (see LookupFn). A None
        result skips that candidate — one lookup failure never kills the pass.
      on_progress: optional phase callback ({"phase": "confusion_lookup",
        "current", "total", "ecosystem", "package"}); emit failures are
        swallowed (progress must never break the work).
      supported_ecosystems: candidates outside this set are skipped before
        lookup (pass the registry client's SUPPORTED_ECOSYSTEMS). None = all.

    Returns {"findings": [finding dicts], "stats": {...}}. One finding per
    (implicated repo, candidate): repo/file/ecosystem/package/version/
    version_source/origin anchor the row; source="CONFUSION",
    vuln_id="CONFUSION-{eco}-{name}", severity HIGH (S2/S3) or MEDIUM
    (S1-only), finding_type, summary, and the suspicion_signals dict.
    """
    pats_by_eco: dict[str, list[str]] = {}
    for p in patterns or []:
        eco, pat = p.get("ecosystem"), p.get("pattern")
        if eco and pat:
            pats_by_eco.setdefault(eco, []).append(pat)

    # ---- candidate build: S1 ∪ S2 ∪ S3, keyed (ecosystem, canonical name) --
    candidates: dict[tuple[str, str], dict] = {}
    for repo, inv in (per_repo_inventory or {}).items():
        for dep in inv or []:
            eco = dep.get("ecosystem")
            pkg = dep.get("package")
            if not eco or not pkg:
                continue
            canon = _canon_name(eco, pkg)
            key = (eco, canon)
            c = candidates.get(key)
            if c is None:
                c = {
                    "ecosystem": eco,
                    "canon": canon,
                    "package": pkg,          # first-seen raw name, for display
                    "internal_repos": {},    # repo → first-seen non-registry row info
                    "bare_repos": {},        # repo → first-seen registry row info
                    "pattern": _match_pattern(eco, canon, pats_by_eco.get(eco, [])),
                }
                candidates[key] = c
            origin = dep.get("origin", "registry") or "registry"
            bucket = c["internal_repos"] if origin != "registry" else c["bare_repos"]
            bucket.setdefault(repo, {
                "file":           dep.get("file", ""),
                "version":        dep.get("version", ""),
                "version_source": dep.get("version_source", ""),
                "origin":         origin,
            })

    stats = {"candidates": 0, "checked": 0, "public": 0, "findings": 0,
             "skipped_unsupported": 0, "skipped_unresolved": 0}

    # Keep only S1 ∪ S2 ∪ S3 (S3 ⊆ S1 by construction: it needs an internal
    # row). Deterministic order for stable progress + output.
    active: list[dict] = []
    for key in sorted(candidates):
        c = candidates[key]
        s1 = bool(c["internal_repos"])
        s2 = c["pattern"] is not None
        if not (s1 or s2):
            continue
        stats["candidates"] += 1
        if (supported_ecosystems is not None
                and c["ecosystem"] not in supported_ecosystems):
            stats["skipped_unsupported"] += 1
            continue
        active.append(c)

    findings: list[dict] = []
    now = datetime.now(timezone.utc)
    total = len(active)

    for i, c in enumerate(active, 1):
        eco = c["ecosystem"]
        if on_progress:
            try:
                on_progress({"phase": "confusion_lookup", "current": i,
                             "total": total, "ecosystem": eco,
                             "package": c["package"]})
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

        s1 = bool(c["internal_repos"])
        s2 = c["pattern"] is not None
        s3 = bool(c["internal_repos"]) and bool(c["bare_repos"])
        signals = [s for s, fired in (("S1", s1), ("S2", s2), ("S3", s3)) if fired]
        high = s2 or s3
        severity = "HIGH" if high else "MEDIUM"
        finding_type = "dependency confusion risk" if high else "namespace exposure"
        suspicion = _suspicion_signals(meta, signals, c["internal_repos"],
                                       c["bare_repos"], now)
        summary = _summary(c["package"], eco, signals, high, c["pattern"],
                           c["internal_repos"], c["bare_repos"], meta)
        vuln_id = f"CONFUSION-{eco}-{c['canon']}"

        # One finding per implicated repo — internal repos (the exposed
        # namespace) and bare repos (where a public install actually bites).
        # A repo present in BOTH buckets keeps its internal row's anchor
        # (the non-registry origin is the more telling evidence).
        implicated = {**c["bare_repos"], **c["internal_repos"]}
        for repo in sorted(implicated):
            info = implicated[repo]
            findings.append({
                "repo":              repo,
                "file":              info["file"],
                "ecosystem":         eco,
                "package":           c["package"],
                "version":           info["version"],
                "version_source":    info["version_source"],
                "origin":            info["origin"],
                "source":            "CONFUSION",
                "vuln_id":           vuln_id,
                "severity":          severity,
                "finding_type":      finding_type,
                "summary":           summary,
                "suspicion_signals": suspicion,
            })
            stats["findings"] += 1

    return {"findings": findings, "stats": stats}
