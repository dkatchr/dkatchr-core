"""
argparse builder for the CLI.

EXTRACTED FROM: dkatchr/cli.py (build_arg_parser).
WHY: argparse is pure input parsing — keep it out of orchestration so adding
a flag doesn't risk breaking the runner. Single responsibility.
"""

import argparse

from dkatchr.config import (
    DEFAULT_CACHE_DIR,
    DEFAULT_GITHUB_BURST,
    DEFAULT_GITHUB_RPS,
    DEFAULT_OSV_BURST,
    DEFAULT_OSV_RPS,
    DEFAULT_SUMMARY_EVERY,
    DEFAULT_WORKERS,
    EXPLOITDB_DEFAULT_TTL,
    KEV_DEFAULT_TTL,
    OSV_DEFAULT_TTL,
)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dkatchr",
        description="Multi-ecosystem GitHub dependency scanner with caching + OSV CVE enrichment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-o", "--output",     required=True, help="Output CSV file path")
    p.add_argument("-c", "--config",     help="JSON file with package rules (overrides inline DEFAULT_PACKAGE_CONFIG)")
    p.add_argument("--cache-dir",        default=DEFAULT_CACHE_DIR, help=f"Cache directory (default: {DEFAULT_CACHE_DIR})")
    p.add_argument("--full-rescan",      action="store_true", help="Ignore cache, re-scan all repos")
    p.add_argument("--orgs",             nargs="+", help="GitHub org names to scan (default: auto-discover via /user/orgs)")
    p.add_argument("--repos",            nargs="+", help="Specific repos to scan as owner/name (skips org listing entirely)")
    p.add_argument("--workers",  type=int,   default=DEFAULT_WORKERS,    help=f"Worker threads for per-repo parallelism (default: {DEFAULT_WORKERS})")
    p.add_argument("--rps",      type=float, default=DEFAULT_GITHUB_RPS, help=f"Global GitHub API rate cap, requests/sec (default: {DEFAULT_GITHUB_RPS} — sustainable vs 5000/hr budget)")
    p.add_argument("--burst",    type=float, default=DEFAULT_GITHUB_BURST, help=f"Token-bucket burst capacity (default: {DEFAULT_GITHUB_BURST})")
    p.add_argument("--osv",      action="store_true",      help="Enrich findings with CVE data from OSV.dev (Google's open-source vuln DB)")
    p.add_argument("--osv-ttl",  type=int,   default=OSV_DEFAULT_TTL, help=f"OSV (eco,pkg,ver)→IDs cache TTL in seconds (default: {OSV_DEFAULT_TTL} = 24h)")
    p.add_argument("--osv-rps",  type=float, default=DEFAULT_OSV_RPS, help=f"OSV API rate cap, requests/sec (default: {DEFAULT_OSV_RPS})")
    p.add_argument("--osv-burst", type=float, default=DEFAULT_OSV_BURST, help=f"OSV token-bucket burst capacity (default: {DEFAULT_OSV_BURST})")
    p.add_argument("--no-kev",   action="store_true", help="Disable CISA KEV cross-reference (on by default when --osv is used)")
    p.add_argument("--kev-ttl",  type=int,   default=KEV_DEFAULT_TTL, help=f"KEV catalog cache TTL in seconds (default: {KEV_DEFAULT_TTL} = 24h)")
    p.add_argument("--no-exploit-intel", action="store_true",
                   help="Disable the public-exploit cross-reference (ExploitDB + Metasploit; "
                        "on by default when --osv is used). Drives the has_exploitdb/has_metasploit "
                        "CSV columns and the 'Has Exploit' summary.")
    p.add_argument("--no-confusion", action="store_true",
                   help="Disable the dependency-confusion detection pass (ON by default). "
                        "Checks internal-looking package names (path/git/workspace deps, "
                        "internal namespace patterns, cross-repo mismatches) against the "
                        "public registries and writes source=CONFUSION rows.")
    p.add_argument("--internal-patterns", default=None,
                   help="JSON file of internal namespace patterns for the confusion pass: "
                        "[{\"ecosystem\": \"npm\", \"pattern\": \"@acme/*\"}, ...]. "
                        "Optional — without it, only the manifest-internal (S1) and "
                        "cross-repo (S3) signals run.")
    p.add_argument("--typosquat", action="store_true",
                   help="Enable typosquatting detection (OFF by default — this is a "
                        "POSITIVE opt-in flag, unlike --no-confusion). Measures edit "
                        "distance of each installed registry dependency against the "
                        "ecosystem's top public packages and, on a close match, confirms "
                        "via a registry-metadata gate (recently created OR few downloads) "
                        "before writing source=TYPOSQUAT rows. Coverage: "
                        "npm/PyPI/crates.io/RubyGems/Packagist.")
    p.add_argument("--exploit-ttl", type=int, default=EXPLOITDB_DEFAULT_TTL,
                   help=f"ExploitDB + Metasploit catalog cache TTL in seconds (default: {EXPLOITDB_DEFAULT_TTL} = 24h)")
    p.add_argument("--no-progress",   action="store_true", help="Disable tqdm progress bar (forces verbose per-repo logging)")
    p.add_argument("--summary-every", type=int, default=DEFAULT_SUMMARY_EVERY, help=f"In no-bar mode, print a running summary every N completed repos (default: {DEFAULT_SUMMARY_EVERY})")
    p.add_argument("--dry-run",        action="store_true", help="List repos that would be scanned + estimate cost/wall time, then exit")
    p.add_argument("--reachability",   action="store_true",
                   help="Run Level 1 reachability analysis after vulnerability detection. "
                        "Uses GitHub Code Search API (~1s per unique vulnerable package). "
                        "Requires GITHUB_TOKEN (already required for scanning).")
    p.add_argument("--attribution",    action="store_true",
                   help="Attribute each finding to the commit author who last touched that "
                        "package's manifest line ('Introduced By'). One git-blame call per "
                        "unique manifest file (cached by branch SHA). Requires GITHUB_TOKEN.")
    p.add_argument("--log-file",       default=None,
                   help="Also write all stderr log lines to this file (in addition to the terminal). "
                        "Useful for post-mortem inspection of a long scan.")
    return p
