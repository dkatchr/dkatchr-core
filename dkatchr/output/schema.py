"""
CSV column model + empty-row builder.

EXTRACTED FROM: dkatchr/output.py (the schema half).
WHY: The old output.py mixed schema with extract_file_inventory (which is
core inventory logic). Schema lives here; the inventory extractor moved to
core/inventory.py.

Single CSV schema covers both Custom Rule and OSV findings. The
`source` column distinguishes the row's origin so downstream tools can
filter cleanly.
"""

# Unified CSV columns:
#   source="CUSTOM" → status, reason (rule reason enum), summary (match evidence)
#   source="OSV"    → vuln_id, aliases, severity, summary, fix_versions,
#                     cwe_ids, published, exploit_refs filled
#
# `reason` for CUSTOM rows is the rule's enum category (INTERNAL_VULNERABLE,
# ORG_BANNED, LICENSE_ISSUE, PRE_CVE) — or empty (treated as CUSTOM in the UI).
# Free-text match evidence (e.g. "exact match on flagged version 1.2.3") lives
# in `summary` for CUSTOM rows, mirroring the OSV advisory summary slot.
# `has_fix` is derived from fix_versions (non-empty → "true"); has_exploitdb /
# has_metasploit are set by the CLI exploit-intel cross-reference. All three are
# "true"/"false" strings like is_kev. The composite "has_exploit" (is_kev OR
# has_exploitdb OR has_metasploit) is intentionally NOT a column — it's derived
# at report time for the totals only.
RESULT_FIELDS = [
    "repo", "file", "ecosystem", "package", "version", "version_source",
    "source", "status", "reason",
    "vuln_id", "aliases", "severity", "cvss_score", "summary", "fix_versions", "has_fix",
    "cwe_ids", "published", "exploit_refs",
    "is_kev", "has_exploitdb", "has_metasploit",
    "reachability", "reachability_evidence",
    "epss_score",
    # Attribution ("Introduced By") — who last touched this package's manifest line.
    "introduced_by_handle", "introduced_by_name", "introduced_by_commit",
    "introduced_by_date", "introduced_by_message", "introduced_by_is_bot",
    # Dependency Confusion Detection (additive, appended so existing column
    # positions never shift). `origin` is populated for ALL inventory-backed
    # rows (registry|path|git|workspace|url); `suspicion_signals` is the
    # finding's JSON signal blob, empty for non-CONFUSION rows.
    "origin", "suspicion_signals",
]


def empty_row(repo_full_name: str, dep: dict) -> dict:
    """Pre-fill the inventory columns; rule/OSV columns left blank."""
    return {
        "repo":           repo_full_name,
        "file":           dep["file"],
        "ecosystem":      dep["ecosystem"],
        "package":        dep["package"],
        "version":        dep["version"],
        "version_source": dep["version_source"],
        "origin":         dep.get("origin", "registry"),
        "source":         "",
        "status":         "",
        "reason":         "",
        "vuln_id":        "",
        "aliases":        "",
        "severity":       "",
        "cvss_score":     "",
        "summary":        "",
        "fix_versions":          "",
        "has_fix":               "",
        "cwe_ids":               "",
        "published":             "",
        "exploit_refs":          "",
        "is_kev":                "",
        "has_exploitdb":         "",
        "has_metasploit":        "",
        "reachability":          "",
        "reachability_evidence": "",
        "epss_score":            "",
        "introduced_by_handle":  "",
        "introduced_by_name":    "",
        "introduced_by_commit":  "",
        "introduced_by_date":    "",
        "introduced_by_message": "",
        "introduced_by_is_bot":  "",
        "suspicion_signals":     "",
    }
