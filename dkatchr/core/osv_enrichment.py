"""
OSV enrichment workflow — orchestrates batched queries against an OSVClient,
turns the result into CSV-shaped rows.

EXTRACTED FROM: dkatchr/osv_client.py (workflow half).
WHY: osv_client.py was 345 lines mixing HTTP wrapper, on-disk cache, and the
enrichment workflow. The workflow is business logic — it decides what to
query, how to batch, how to pull fields out of vuln records, how to shape
output rows. The client (now clients/osv.py) is just the network layer.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed

from dkatchr.clients.osv import OSVClient
from dkatchr.config import OSV_BATCH_SIZE
from dkatchr.logger import log
from dkatchr.output.schema import empty_row
from dkatchr.parsers import ECOSYSTEM_NAME_FIELD


# ---------------------------------------------------------------------------
# Vuln detail extraction — pull a few useful fields out of an OSV vuln record.
# ---------------------------------------------------------------------------

# Reference URL domains known to host public exploits or PoC code.
# Used in osv_exploit_refs() to surface exploit-adjacent references even when
# the OSV reference type is not explicitly "EVIDENCE".
_EXPLOIT_REF_DOMAINS: frozenset[str] = frozenset({
    "exploit-db.com",
    "exploitdb.com",
    "packetstormsecurity.com",
    "seclists.org",
})


def osv_severity(vuln: dict) -> str:
    """Best-effort severity string. Prefers CVSS score, falls back to label."""
    for sev in vuln.get("severity") or []:
        score = (sev.get("score") or "").strip()
        if score:
            return score
    db_spec = vuln.get("database_specific") or {}
    label = db_spec.get("severity")
    if isinstance(label, str) and label:
        return label
    return ""


def _parse_cvss_base(score: str) -> float | None:
    """Parse a CVSS vector string (or bare numeric score) to a float base score.

    Returns None on ANY failure — unparseable input, an unrecognised version, or
    the `cvss` package not being importable. The import is done lazily inside a
    try/except so this stays import-safe even in an environment where the
    (declared) `cvss` dependency is not installed.
    """
    s = (score or "").strip()
    if not s:
        return None
    # Some OSV entries carry a bare numeric score ("9.8") under a CVSS_Vx type.
    if not s.upper().startswith("CVSS:"):
        try:
            return float(s)
        except (TypeError, ValueError):
            return None
    try:
        from cvss import CVSS2, CVSS3, CVSS4
    except Exception:
        return None
    version = s.split("/", 1)[0].split(":")[-1]   # "3.1" / "2.0" / "4.0"
    major = version.split(".")[0]
    try:
        if major == "3":
            return float(CVSS3(s).base_score)
        if major == "2":
            return float(CVSS2(s).base_score)
        if major == "4":
            return float(CVSS4(s).base_score)
        # Unknown major version — best effort as v3 (the dominant format).
        return float(CVSS3(s).base_score)
    except Exception:
        return None


def osv_cvss_score(vuln: dict) -> float | None:
    """Numeric CVSS base score (0.0–10.0) from an OSV record, or None.

    OSV severity entries look like {"type": "CVSS_V3", "score":
    "CVSS:3.1/AV:N/..."} (occasionally a bare numeric score). This is distinct
    from osv_severity() above, which returns the raw vector/label STRING for
    display: here we want the parsed FLOAT for the composite risk-score formula.

    Preference order: CVSS v3 (incl. 3.1) → v4 → v2 → anything else parseable.
    v3 is preferred because it is the most widely populated modern scoring; v2
    is the documented fallback. Returns None when no severity entry yields a
    parseable score. NEVER raises (see _parse_cvss_base).
    """
    def _rank(entry: dict) -> int:
        t = (entry.get("type") or "").upper()
        if t.startswith("CVSS_V3"):
            return 0
        if t.startswith("CVSS_V4"):
            return 1
        if t.startswith("CVSS_V2"):
            return 2
        return 3

    ordered = sorted(
        (s for s in (vuln.get("severity") or []) if isinstance(s, dict)),
        key=_rank,
    )
    for entry in ordered:
        parsed = _parse_cvss_base(entry.get("score") or "")
        if parsed is not None:
            return parsed
    return None


def osv_fix_versions(vuln: dict) -> str:
    fixes: set[str] = set()
    for affected in vuln.get("affected") or []:
        for r in affected.get("ranges") or []:
            for evt in r.get("events") or []:
                if isinstance(evt, dict) and "fixed" in evt:
                    fixes.add(str(evt["fixed"]))
    return ",".join(sorted(fixes))


def osv_aliases(vuln: dict) -> str:
    aliases = vuln.get("aliases") or []
    return ",".join(str(a) for a in aliases if a)


def osv_summary(vuln: dict) -> str:
    s = (vuln.get("summary") or vuln.get("details") or "").strip()
    return " ".join(s.split())  # collapse whitespace, no truncation — UI truncates if needed


def osv_cwe_ids(vuln: dict) -> str:
    """Comma-separated CWE IDs from database_specific.cwe_ids (GHSA-sourced entries).

    Example output: "CWE-79,CWE-89"
    Not all OSV records carry CWE data — returns empty string when absent.
    """
    db_spec = vuln.get("database_specific") or {}
    cwe_ids = db_spec.get("cwe_ids") or []
    return ",".join(str(c) for c in cwe_ids if c)


def osv_published(vuln: dict) -> str:
    """ISO 8601 publication timestamp from the OSV record.

    Example output: "2021-12-10T00:00:00Z"
    Useful for vulnerability age calculations and triage ordering.
    """
    return (vuln.get("published") or "").strip()


def osv_exploit_refs(vuln: dict) -> str:
    """Comma-separated URLs of references that indicate a known public exploit or PoC.

    Captures two categories:
    - References with type="EVIDENCE" (OSV's explicit exploit-evidence marker)
    - References whose URL domain matches a known exploit-hosting site
      (exploit-db.com, packetstormsecurity.com, seclists.org, etc.)

    Returns empty string when no such references exist.
    """
    refs = vuln.get("references") or []
    urls: list[str] = []
    seen: set[str] = set()
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        url = (ref.get("url") or "").strip()
        if not url or url in seen:
            continue
        ref_type = (ref.get("type") or "").upper()
        if ref_type == "EVIDENCE":
            urls.append(url)
            seen.add(url)
            continue
        for domain in _EXPLOIT_REF_DOMAINS:
            if domain in url:
                urls.append(url)
                seen.add(url)
                break
    return ",".join(urls)


# ---------------------------------------------------------------------------
# Enrichment workflow
# ---------------------------------------------------------------------------

def osv_enrich(
    per_repo_inventory: dict[str, list[dict]],
    client: OSVClient,
    detail_workers: int = 8,
) -> dict[tuple, list[dict]]:
    """
    Given {repo_full_name: [inventory rows]}, query OSV for every unique
    (ecosystem, package, version) tuple and return:
        {(eco, pkg, ver): [vuln_record, ...]}
    """
    osv_ecosystems = set(ECOSYSTEM_NAME_FIELD.keys())  # all our labels match OSV

    # 1. Build the unique tuple set.
    #    Deduplication: for any (ecosystem, package) pair where both a
    #    "resolved" and a "declared" entry exist in a repo's inventory, use
    #    only the resolved version for OSV queries.  Declared versions are
    #    semver ranges that OSV can match even when the pinned resolved version
    #    is already patched, producing false positives.  The full inventory is
    #    NOT modified — this filtering is OSV-query-only.
    unique: set[tuple] = set()
    for inv in per_repo_inventory.values():
        # Build a per-repo set of (ecosystem, package) pairs that have at
        # least one resolved entry so we can skip their declared counterparts.
        # Non-registry rows (origin path/git/workspace/url) are excluded from
        # OSV entirely: their "version" is a raw spec ("file:../x", a git URL)
        # that would leak into batch queries as junk. This exclusion applies
        # regardless of whether the confusion pass is enabled.
        resolved_pairs: set[tuple[str, str]] = {
            (dep["ecosystem"], dep["package"])
            for dep in inv
            if dep.get("version_source") == "resolved"
            and dep.get("package")
            and dep.get("version")
            and dep.get("origin", "registry") == "registry"
            and dep["ecosystem"] in osv_ecosystems
        }
        for dep in inv:
            eco = dep["ecosystem"]
            if eco not in osv_ecosystems:
                continue
            if not dep.get("package") or not dep.get("version"):
                continue
            if dep.get("origin", "registry") != "registry":
                continue
            # Skip declared entry when a resolved pin exists for the same
            # (ecosystem, package) in this repo — prefer the exact version.
            if dep.get("version_source") == "declared" and (eco, dep["package"]) in resolved_pairs:
                continue
            unique.add((eco, dep["package"], dep["version"]))

    log(f"[+] OSV: {len(unique)} unique (ecosystem, package, version) tuples across all repos")

    # 2. Split into cached vs needs-query
    needs_query: list[tuple] = []
    tuple_ids:   dict[tuple, list[str]] = {}
    for tup in unique:
        ids = client.get_cached_ids(*tup)
        if ids is None:
            needs_query.append(tup)
        else:
            tuple_ids[tup] = ids

    log(f"[+] OSV: {len(tuple_ids)} cached, {len(needs_query)} need fresh batch queries")

    # 3. Batch query missing tuples
    for i in range(0, len(needs_query), OSV_BATCH_SIZE):
        chunk = needs_query[i:i + OSV_BATCH_SIZE]
        batch_no = i // OSV_BATCH_SIZE + 1
        total_batches = (len(needs_query) + OSV_BATCH_SIZE - 1) // OSV_BATCH_SIZE
        log(f"    OSV batch {batch_no}/{total_batches} — {len(chunk)} queries")
        try:
            batch_ids = client.query_batch(chunk)
        except Exception as e:
            log(f"[!] OSV batch {batch_no} failed: {e} — leaving these uncached, continuing")
            continue
        for tup, ids in zip(chunk, batch_ids):
            client.set_cached_ids(*tup, ids)
            tuple_ids[tup] = ids

    client.save_index()

    # 4. Collect every unique vuln ID we need full details for
    all_vuln_ids: set[str] = set()
    for ids in tuple_ids.values():
        all_vuln_ids.update(ids)

    log(f"[+] OSV: fetching full details for {len(all_vuln_ids)} unique vuln IDs")

    vuln_details: dict[str, dict] = {}
    if all_vuln_ids:
        with ThreadPoolExecutor(max_workers=detail_workers) as pool:
            futures = {pool.submit(client.get_vuln, vid): vid for vid in all_vuln_ids}
            for fut in as_completed(futures):
                vid = futures[fut]
                try:
                    data = fut.result()
                except Exception as e:
                    log(f"[!] OSV detail {vid}: {e}")
                    continue
                if data:
                    vuln_details[vid] = data

    # 5. Resolve each tuple → list of full vuln records
    tuple_to_vulns: dict[tuple, list[dict]] = {}
    for tup, ids in tuple_ids.items():
        if not ids:
            continue
        records = [vuln_details[i] for i in ids if i in vuln_details]
        if records:
            tuple_to_vulns[tup] = records

    return tuple_to_vulns


def _check_kev(vuln_id: str, aliases: str, kev_cve_set: set[str]) -> str:
    """Check if a vuln is in the KEV set. Returns "true" or "false".

    Checks both the primary ID and each alias for CVE-* prefix + set membership.
    Pure function — no imports of KEV client, preserves core purity.
    """
    if vuln_id.startswith("CVE-") and vuln_id in kev_cve_set:
        return "true"
    for alias in aliases.split(","):
        alias = alias.strip()
        if alias.startswith("CVE-") and alias in kev_cve_set:
            return "true"
    return "false"


def osv_rows_for_repo(
    repo_full_name: str,
    inventory: list[dict],
    tuple_to_vulns: dict[tuple, list[dict]],
    kev_cve_set: set[str] | None = None,
) -> list[dict]:
    """One CSV row per (file, package, vuln_id) found in this repo."""
    rows = []
    for dep in inventory:
        # Non-registry rows never get OSV findings — their tuples were never
        # queried, and a same-named tuple queried for ANOTHER repo's registry
        # row must not attach advisories to a path/git/workspace dep here.
        if dep.get("origin", "registry") != "registry":
            continue
        tup = (dep["ecosystem"], dep["package"], dep["version"])
        vulns = tuple_to_vulns.get(tup)
        if not vulns:
            continue
        for v in vulns:
            row = empty_row(repo_full_name, dep)
            row["source"]       = "OSV"
            row["status"]       = "vulnerable"
            row["vuln_id"]      = v.get("id", "")
            row["aliases"]      = osv_aliases(v)
            row["severity"]     = osv_severity(v)
            row["cvss_score"]   = osv_cvss_score(v)
            row["summary"]      = osv_summary(v)
            row["fix_versions"] = osv_fix_versions(v)
            row["cwe_ids"]      = osv_cwe_ids(v)
            row["published"]    = osv_published(v)
            row["exploit_refs"] = osv_exploit_refs(v)
            if kev_cve_set is not None:
                row["is_kev"] = _check_kev(row["vuln_id"], row["aliases"], kev_cve_set)
            rows.append(row)
    return rows
