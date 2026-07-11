"""
CLI scan orchestration — the body of `main()`.

EXTRACTED FROM: dkatchr/cli.py (former main() + _scan_batch).
WHY: The old main() was 100+ lines mixing argparse parsing, batch building,
threading, CSV writing, and OSV pass orchestration. This module owns the
orchestration only — argparse lives in args.py, CSV in output/csv_writer.py,
dry-run in dry_run.py.

This is the CLI's equivalent of web/services/scan_runner.py: same Scanner,
same enrichment, different I/O at the edges (CSV vs SQLite, stdout/tqdm
vs WebSocket).
"""

import json
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from dkatchr.clients.epss import EPSSClient
from dkatchr.clients.exploitdb import ExploitDBClient
from dkatchr.clients.github import GitHubClient
from dkatchr.clients.kev import KEVClient
from dkatchr.clients.metasploit import MetasploitClient
from dkatchr.clients.osv import OSVClient
from dkatchr.clients.registry_meta import RegistryMetaClient
from dkatchr.clients.top_packages import TopPackagesClient
from dkatchr.config import CACHE_SCHEMA
from dkatchr.core.attribution import enrich_attribution
from dkatchr.core.confusion import detect_confusion, load_internal_patterns
from dkatchr.core.typosquat import detect_typosquats
from dkatchr.core.osv_enrichment import osv_enrich, osv_rows_for_repo
from dkatchr.core.reachability import enrich_reachability
from dkatchr.core.rules import compile_rules, load_package_config
from dkatchr.core.scanner import Scanner
from dkatchr.logger import HAS_TQDM, log, reachability_badge, set_log_file, set_quiet_repos, tqdm
from dkatchr.output.csv_writer import open_csv_writer
from dkatchr.output.schema import empty_row
from dkatchr.storage.attribution_cache import AttributionCache
from dkatchr.storage.inventory_cache import InventoryCache
from dkatchr.storage.reachability_cache import ReachabilityCache

from dkatchr.cli.dry_run import print_dry_run_report


def _repo_uses_cache(cache: InventoryCache, full_name: str, full_rescan: bool) -> bool:
    """Cheap check — only consults the index, doesn't hit GitHub."""
    if full_rescan:
        return False
    return bool(cache.get_index_sha(full_name))


def run_cli(args) -> None:
    """Top-level orchestration for the CLI. `args` is the parsed argparse Namespace."""
    # ---- optional file logging -----------------------------------------
    if getattr(args, "log_file", None):
        set_log_file(args.log_file)
        log(f"[+] Logging to file: {args.log_file}")

    # ---- shared infra ---------------------------------------------------
    github   = GitHubClient(rps=args.rps, burst=args.burst)
    cache    = InventoryCache(cache_dir=args.cache_dir)
    rules    = compile_rules(load_package_config(args.config))
    scanner  = Scanner(github=github, cache=cache, package_config=rules)

    # ---- resolve targets ------------------------------------------------
    repo_specs, orgs = _resolve_targets(github, args)
    if not repo_specs and not orgs:
        log("[!] Nothing to scan. Pass --orgs or --repos.")
        sys.exit(1)

    _print_run_header(repo_specs, orgs, rules, args)

    # ---- build the (label, repos) batches -------------------------------
    batches = _build_batches(github, repo_specs, orgs)

    # ---- dry-run --------------------------------------------------------
    if args.dry_run:
        print_dry_run_report(batches, cache, args)
        sys.exit(0)

    # ---- progress bar setup ---------------------------------------------
    use_bar = HAS_TQDM and not args.no_progress
    set_quiet_repos(use_bar)
    if not HAS_TQDM and not args.no_progress:
        log("[!] tqdm not installed — progress bar disabled. `pip install tqdm` for a real bar.")

    # ---- run ------------------------------------------------------------
    totals = {"repos": 0, "rule_hits": 0, "rule_vuln": 0, "osv_hits": 0, "kev_hits": 0,
              "fix_available_hits": 0, "exploitdb_hits": 0, "metasploit_hits": 0,
              "exploit_hits": 0, "confusion_hits": 0, "typosquat_hits": 0}
    inventory_lock = threading.Lock()
    per_repo_inventory: dict[str, list[dict]] = {}

    # When --reachability OR --attribution is active, we buffer all vuln rows
    # per repo and write them to CSV only after the enrichment pass(es) mutate
    # the row dicts in place (reachability adds reachability columns;
    # attribution adds introduced_by_* columns). A single flush writes them.
    buffer_rows = bool(args.reachability or args.attribution)
    per_repo_rule_rows: dict[str, list[dict]] = {}
    per_repo_osv_rows:  dict[str, list[dict]] = {}
    per_repo_sha:       dict[str, str]        = {}

    with open_csv_writer(args.output) as writer:
        for label, repos in batches:
            totals["repos"] += len(repos)
            _scan_batch(
                label=label, repos=repos, scanner=scanner, cache=cache, args=args,
                writer=writer,
                inventory_lock=inventory_lock, per_repo_inventory=per_repo_inventory,
                per_repo_rule_rows=per_repo_rule_rows if buffer_rows else None,
                per_repo_sha=per_repo_sha if buffer_rows else None,
                totals=totals, use_bar=use_bar,
            )

        # ---- OSV pass ---------------------------------------------------
        tuple_to_vulns: dict = {}
        kev_cve_set: set[str] | None = None

        if args.osv and per_repo_inventory:
            log(f"\n===== OSV ENRICHMENT =====")
            osv = OSVClient(
                cache_dir=f"{args.cache_dir}/osv",
                ttl_seconds=args.osv_ttl,
                rps=args.osv_rps,
                burst=args.osv_burst,
            )
            try:
                tuple_to_vulns = osv_enrich(per_repo_inventory, osv, detail_workers=args.workers)
            except Exception as e:
                log(f"[!] OSV enrichment failed: {e}")
                tuple_to_vulns = {}

            if not args.no_kev and tuple_to_vulns:
                kev = KEVClient(cache_dir=f"{args.cache_dir}/kev", ttl_seconds=args.kev_ttl)
                kev_cve_set = kev.load()

            # EPSS exploit-probability enrichment. Fetched once (EPSSClient owns
            # its date-keyed file cache + fail-safe — returns {} on total
            # failure, leaving epss_score blank). Only OSV/CVE rows can match.
            epss_scores = EPSSClient(cache_dir=args.cache_dir).get_scores()

            # Public-exploit catalogs ("Has Exploit"). Same place + posture as
            # KEV: built after enrichment, each owns a TTL'd file cache + fail-
            # safe (returns an empty set on total failure), and the lookup is a
            # Python CVE-token match, not a SQL/DB step. Disabled by
            # --no-exploit-intel.
            exploitdb_set:  set[str] = set()
            metasploit_set: set[str] = set()
            if not args.no_exploit_intel and tuple_to_vulns:
                try:
                    exploitdb_set = ExploitDBClient(
                        cache_dir=f"{args.cache_dir}/exploitdb",
                        ttl_seconds=args.exploit_ttl).load()
                except Exception as e:
                    log(f"[!] Exploit-DB load failed: {e}")
                try:
                    metasploit_set = MetasploitClient(
                        cache_dir=f"{args.cache_dir}/metasploit",
                        ttl_seconds=args.exploit_ttl).load()
                except Exception as e:
                    log(f"[!] Metasploit load failed: {e}")

            for full_name, inv in per_repo_inventory.items():
                osv_rows = osv_rows_for_repo(full_name, inv, tuple_to_vulns,
                                             kev_cve_set=kev_cve_set)
                for row in osv_rows:
                    row["epss_score"] = _epss_pct(epss_scores, row.get("vuln_id"), row.get("aliases"))
                    has_exploit = _finalize_finding_row(row, exploitdb_set, metasploit_set)
                    if row["has_fix"] == "true":         totals["fix_available_hits"] += 1
                    if row["has_exploitdb"] == "true":   totals["exploitdb_hits"] += 1
                    if row["has_metasploit"] == "true":  totals["metasploit_hits"] += 1
                    if has_exploit:                      totals["exploit_hits"] += 1
                totals["osv_hits"]  += len(osv_rows)
                totals["kev_hits"]  += sum(1 for r in osv_rows if r.get("is_kev") == "true")
                if buffer_rows:
                    per_repo_osv_rows[full_name] = osv_rows
                else:
                    writer.write_rows(osv_rows)

            if not buffer_rows:
                log(f"[✓] OSV: wrote {totals['osv_hits']} CVE row(s)")
                if kev_cve_set is not None:
                    log(f"[✓] KEV: {totals['kev_hits']} finding(s) are known exploited vulnerabilities")
                _print_exploit_intel_lines(args, totals)

        # ---- dependency-confusion pass ----------------------------------
        # Runs after the OSV pass (mirrors the web runner's ordering) but is
        # NOT gated on --osv: candidates come from inventory origin + patterns,
        # not OSV data. Confusion rows are written directly — the attribution
        # and reachability passes deliberately ignore them, so they never need
        # buffering. A pass failure never aborts the run.
        if not args.no_confusion and per_repo_inventory:
            _confusion_pass(args, per_repo_inventory, writer, totals)

        # ---- typosquatting pass -----------------------------------------
        # Opt-in (--typosquat, default OFF). Like confusion it writes rows
        # directly (attribution/reachability ignore them) and never aborts the
        # run. Runs after the confusion pass.
        if args.typosquat and per_repo_inventory:
            _typosquat_pass(args, per_repo_inventory, writer, totals)

        # ---- attribution pass -------------------------------------------
        # Runs AFTER the OSV pass so OSV findings (the primary vuln source) get
        # attributed too — they don't exist as rows until the OSV pass builds
        # them. Mirrors osv_enrich: dedups by manifest, one git-blame call per
        # unique manifest file (cached by branch SHA). Merges introduced_by_*
        # into the buffered finding rows in place; the reachability pass or the
        # final flush below writes them.
        if args.attribution:
            _attribution_pass(github, args, per_repo_rule_rows, per_repo_osv_rows,
                              per_repo_sha, totals)

        # ---- reachability pass ------------------------------------------
        if args.reachability:
            log(f"\n===== REACHABILITY ANALYSIS =====")
            all_repos = set(per_repo_rule_rows) | set(per_repo_osv_rows)
            reach_cache = ReachabilityCache(cache_dir=args.cache_dir)
            reach_totals: dict[str, int] = {
                "REACHABLE": 0, "UNUSED": 0, "UNKNOWN": 0, "packages": 0,
            }

            for full_name in all_repos:
                rule_rows = per_repo_rule_rows.get(full_name, [])
                osv_rows  = per_repo_osv_rows.get(full_name, [])
                all_rows  = rule_rows + osv_rows
                if not all_rows:
                    continue

                sha = per_repo_sha.get(full_name)
                if not sha:
                    log(f"[{full_name}] reachability skipped — no SHA available")
                    writer.write_rows(rule_rows)
                    writer.write_rows(osv_rows)
                    continue

                cli_dl_state = {"last_emit_at": 0.0}

                def _cli_reach_progress(payload: dict, _repo=full_name,
                                         _state=cli_dl_state) -> None:
                    phase = payload.get("phase", "")
                    if phase == "cache_hit":
                        log(f"[{_repo}] reachability: cache hit @ {payload.get('sha','')}")
                    elif phase == "tarball_downloading":
                        # Print at most one line per second to keep stdout sane.
                        now = time.monotonic()
                        if now - _state["last_emit_at"] < 1.0:
                            return
                        _state["last_emit_at"] = now
                        done = payload.get("downloaded_bytes", 0)
                        total = payload.get("total_bytes")
                        if total:
                            pct = done * 100 // max(1, total)
                            log(f"[{_repo}] downloading tarball: "
                                f"{done / 1024 / 1024:.1f}/{total / 1024 / 1024:.1f}MB ({pct}%)")
                        else:
                            log(f"[{_repo}] downloading tarball: {done / 1024 / 1024:.1f}MB")
                    elif phase == "tarball_downloaded":
                        log(f"[{_repo}] tarball downloaded: "
                            f"{payload.get('size_bytes', 0) / 1024 / 1024:.1f}MB")
                    elif phase == "tarball_failed":
                        log(f"[{_repo}] tarball download FAILED")
                    elif phase == "building_automaton":
                        log(f"[{_repo}] building automaton: "
                            f"{payload.get('patterns', 0)} pattern(s) across "
                            f"{payload.get('unique_packages', 0)} package(s)")
                    elif phase == "scanning_progress":
                        log(f"[{_repo}] scanning: "
                            f"{payload.get('files_scanned', 0)} source files scanned, "
                            f"{payload.get('patterns_matched', 0)}/"
                            f"{payload.get('patterns_total', 0)} patterns matched")
                    elif phase == "scanning_complete":
                        log(f"[{_repo}] scan done: "
                            f"{payload.get('files_scanned', 0)} files scanned, "
                            f"{payload.get('files_skipped', 0)} skipped")
                    elif phase == "resolving_start":
                        log(f"[{_repo}] resolving import names: "
                            f"{payload.get('total', 0)} unique package(s)")
                    elif phase == "resolved":
                        log(f"[{_repo}] resolved {payload.get('ecosystem','')}"
                            f"/{payload.get('package','')} → "
                            f"{payload.get('names')} (via {payload.get('source','')})")
                    elif phase == "resolution_failed":
                        log(f"[{_repo}] resolution FAILED "
                            f"{payload.get('ecosystem','')}/{payload.get('package','')}: "
                            f"{payload.get('reason','')}")
                    elif phase == "resolving_done":
                        log(f"[{_repo}] import name resolution: "
                            f"{payload.get('resolved',0)} resolved, "
                            f"{payload.get('cached',0)} cached, "
                            f"{payload.get('failed',0)} failed")

                enrich_reachability(
                    all_rows, full_name, sha, github, reach_cache,
                    on_progress=_cli_reach_progress,
                    cache_dir=args.cache_dir,
                )

                seen_pkgs: set[tuple[str, str]] = set()
                for row in all_rows:
                    pkg_key = (row.get("package", ""), row.get("ecosystem", ""))
                    if pkg_key not in seen_pkgs:
                        seen_pkgs.add(pkg_key)
                        r = row.get("reachability", "UNKNOWN") or "UNKNOWN"
                        reach_totals[r] = reach_totals.get(r, 0) + 1
                        reach_totals["packages"] += 1
                    badge = reachability_badge(row.get("reachability", ""))
                    vuln_ref = row.get("vuln_id") or row.get("reason") or ""
                    log(f"[{full_name}] {row.get('package','')}=={row.get('version','')}  {vuln_ref}  {badge}")

                writer.write_rows(rule_rows)
                writer.write_rows(osv_rows)

            if args.osv:
                log(f"[✓] OSV: wrote {totals['osv_hits']} CVE row(s)")
                if kev_cve_set is not None:
                    log(f"[✓] KEV: {totals['kev_hits']} finding(s) are known exploited vulnerabilities")
                _print_exploit_intel_lines(args, totals)

            _print_reachability_summary(reach_totals)

        # ---- flush buffered rows ----------------------------------------
        # When buffering was on for attribution only (no reachability pass that
        # writes the rows itself), emit the enriched rows now — still inside the
        # CSV writer context so the file is closed cleanly afterwards.
        if buffer_rows and not args.reachability:
            for full_name in set(per_repo_rule_rows) | set(per_repo_osv_rows):
                writer.write_rows(per_repo_rule_rows.get(full_name, []))
                writer.write_rows(per_repo_osv_rows.get(full_name, []))

    cache.save_index()
    _print_run_footer(args, totals)


# ---------------------------------------------------------------------------
# Helpers — small, single-purpose, easy to read.
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _cve_tokens(vuln_id: str | None, aliases: str | None) -> set[str]:
    """Uppercased CVE ids from a finding's vuln_id + aliases.

    Shared by the CVE-keyed CLI enrichments (EPSS, exploit-intel). OSV's primary
    `vuln_id` is almost always GHSA-/PYSEC-/GO- with the CVE in the comma-
    separated `aliases`, so both fields are scanned. Mirrors the web repository
    helper of the same name.
    """
    return {c.upper() for c in _CVE_RE.findall(vuln_id or "")} \
        | {c.upper() for c in _CVE_RE.findall(aliases or "")}


def _epss_pct(scores: dict[str, float], vuln_id: str | None, aliases: str | None = "") -> str:
    """EPSS probability for a finding, as a percentage string (e.g. "12.34%").

    EPSS is keyed on CVE, so we extract every CVE token from vuln_id + aliases
    and take the highest matching score. Empty string when no CVE token matches
    the dataset (Custom Rule rows, no coverage, etc).
    """
    vals = [scores[c] for c in _cve_tokens(vuln_id, aliases) if c in scores]
    if not vals:
        return ""
    return f"{max(vals) * 100:.2f}%"


def _finalize_finding_row(row: dict, exploitdb_set: set[str],
                          metasploit_set: set[str]) -> bool:
    """Set has_fix / has_exploitdb / has_metasploit on a finding row, in place.

    Returns True if the row counts as 'has exploit' (is_kev OR ExploitDB OR
    Metasploit) — the composite verdict, reported in totals but never written as
    a CSV column. `has_fix` is derived from fix_versions. Custom Rule rows pass
    empty exploit sets, so they get has_exploitdb/has_metasploit = "false".
    """
    row["has_fix"] = "true" if (row.get("fix_versions") or "").strip() else "false"
    cves = _cve_tokens(row.get("vuln_id"), row.get("aliases"))
    edb = bool(cves) and bool(exploitdb_set) and not cves.isdisjoint(exploitdb_set)
    msf = bool(cves) and bool(metasploit_set) and not cves.isdisjoint(metasploit_set)
    row["has_exploitdb"]  = "true" if edb else "false"
    row["has_metasploit"] = "true" if msf else "false"
    return (row.get("is_kev") == "true") or edb or msf


def _confusion_csv_row(f: dict) -> dict:
    """Turn a core confusion finding dict into a unified CSV row."""
    row = empty_row(f["repo"], {
        "file":           f.get("file", ""),
        "ecosystem":      f.get("ecosystem", ""),
        "package":        f.get("package", ""),
        "version":        f.get("version", ""),
        "version_source": f.get("version_source", ""),
        "origin":         f.get("origin", "registry"),
    })
    row["source"]            = "CONFUSION"
    row["status"]            = "vulnerable"
    row["vuln_id"]           = f.get("vuln_id", "")
    row["severity"]          = f.get("severity", "")
    row["summary"]           = f.get("summary", "")
    row["suspicion_signals"] = json.dumps(f.get("suspicion_signals") or {}, sort_keys=True)
    # No CVE, no fix list — but keep the boolean columns uniform ("false").
    _finalize_finding_row(row, set(), set())
    return row


def _confusion_pass(args, per_repo_inventory: dict, writer, totals: dict) -> None:
    """CLI dependency-confusion pass — patterns + registry lookups + CSV rows.

    Wrapped end-to-end: a pass failure logs and the run continues (same
    isolation contract as the OSV/KEV/exploit-intel passes).
    """
    log("\n===== DEPENDENCY CONFUSION DETECTION =====")
    try:
        patterns = load_internal_patterns(args.internal_patterns)
        client = RegistryMetaClient(cache_dir=f"{args.cache_dir}/registry_meta")

        state = {"last_emit_at": 0.0}

        def _progress(payload: dict, _state=state) -> None:
            # Throttle the per-candidate firehose to ~1 line/sec.
            now = time.monotonic()
            if now - _state["last_emit_at"] < 1.0:
                return
            _state["last_emit_at"] = now
            log(f"[confusion] checking candidate {payload.get('current', 0)}"
                f"/{payload.get('total', 0)} — "
                f"{payload.get('ecosystem', '')}/{payload.get('package', '')}")

        result = detect_confusion(
            per_repo_inventory, patterns, client.get_package_meta,
            on_progress=_progress,
            supported_ecosystems=RegistryMetaClient.SUPPORTED_ECOSYSTEMS,
        )
        rows = [_confusion_csv_row(f) for f in result["findings"]]
        writer.write_rows(rows)
        totals["confusion_hits"] = len(rows)
        s = result["stats"]
        log(f"[✓] Confusion: {len(rows)} finding(s) — {s['checked']} candidate(s) "
            f"checked, {s['public']} exist publicly"
            + (f", {s['skipped_unsupported']} skipped (unsupported registry)"
               if s["skipped_unsupported"] else "")
            + (f", {s['skipped_unresolved']} lookup failure(s)"
               if s["skipped_unresolved"] else ""))
    except Exception as e:
        log(f"[!] Dependency-confusion pass failed: {e} — continuing")


def _typosquat_csv_row(f: dict) -> dict:
    """Turn a core typosquat finding dict into a unified CSV row (mirror of
    _confusion_csv_row — reuses the same origin + suspicion_signals columns)."""
    row = empty_row(f["repo"], {
        "file":           f.get("file", ""),
        "ecosystem":      f.get("ecosystem", ""),
        "package":        f.get("package", ""),
        "version":        f.get("version", ""),
        "version_source": f.get("version_source", ""),
        "origin":         f.get("origin", "registry"),
    })
    row["source"]            = "TYPOSQUAT"
    row["status"]            = "vulnerable"
    row["vuln_id"]           = f.get("vuln_id", "")
    row["severity"]          = f.get("severity", "")
    row["summary"]           = f.get("summary", "")
    row["suspicion_signals"] = json.dumps(f.get("suspicion_signals") or {}, sort_keys=True)
    _finalize_finding_row(row, set(), set())
    return row


def _typosquat_pass(args, per_repo_inventory: dict, writer, totals: dict) -> None:
    """CLI typosquatting pass — top-package feeds + edit distance + metadata gate.

    Wrapped end-to-end: a pass failure logs and the run continues (same isolation
    contract as the OSV/confusion passes). The metadata gate reuses
    RegistryMetaClient (no second registry client).
    """
    log("\n===== TYPOSQUATTING DETECTION =====")
    try:
        top_client = TopPackagesClient(cache_dir=f"{args.cache_dir}/top_packages")
        meta_client = RegistryMetaClient(cache_dir=f"{args.cache_dir}/registry_meta")

        present_ecos = {
            dep.get("ecosystem")
            for inv in per_repo_inventory.values() for dep in (inv or [])
            if dep.get("ecosystem")
        }
        feed_state = {"last_emit_at": 0.0}

        def _feed_progress(payload: dict, _state=feed_state) -> None:
            now = time.monotonic()
            if now - _state["last_emit_at"] < 1.0:
                return
            _state["last_emit_at"] = now
            log(f"[typosquat] fetching {payload.get('ecosystem', '')} top packages "
                f"({payload.get('fetched', 0)} so far)")

        top_sets = {
            eco: top_client.get_top(eco, on_progress=_feed_progress)
            for eco in present_ecos
            if eco in top_client.SUPPORTED_ECOSYSTEMS
        }

        lk_state = {"last_emit_at": 0.0}

        def _progress(payload: dict, _state=lk_state) -> None:
            if payload.get("phase") != "typosquat_lookup":
                return
            now = time.monotonic()
            if now - _state["last_emit_at"] < 1.0:
                return
            _state["last_emit_at"] = now
            log(f"[typosquat] checking candidate {payload.get('current', 0)}"
                f"/{payload.get('total', 0)} — "
                f"{payload.get('ecosystem', '')}/{payload.get('package', '')}")

        result = detect_typosquats(
            per_repo_inventory, top_sets, meta_client.get_package_meta,
            on_progress=_progress,
            supported_ecosystems=TopPackagesClient.SUPPORTED_ECOSYSTEMS,
        )
        rows = [_typosquat_csv_row(f) for f in result["findings"]]
        writer.write_rows(rows)
        totals["typosquat_hits"] = len(rows)
        s = result["stats"]
        log(f"[✓] Typosquat: {len(rows)} finding(s) — {s['candidates']} candidate(s) "
            f"evaluated, {s['distance_hits']} close-name match(es), {s['public']} "
            f"confirmed on the public registry"
            + (f", {s['skipped_unsupported']} skipped (unsupported ecosystem)"
               if s["skipped_unsupported"] else "")
            + (f", {s['skipped_unresolved']} lookup failure(s)"
               if s["skipped_unresolved"] else ""))
    except Exception as e:
        log(f"[!] Typosquatting pass failed: {e} — continuing")


def _print_exploit_intel_lines(args, totals: dict) -> None:
    """Mid-run '[✓]' summary lines for the public-exploit cross-reference,
    mirroring the KEV summary line's format. No-op when --no-exploit-intel."""
    if args.no_exploit_intel:
        return
    log(f"[✓] Exploit-DB: {totals['exploitdb_hits']} finding(s) have known public exploit code")
    log(f"[✓] Metasploit: {totals['metasploit_hits']} finding(s) have a Metasploit module")
    log(f"[✓] Has Exploit: {totals['exploit_hits']} finding(s) (KEV/ExploitDB/Metasploit)")


def _merge_attribution(rows: list[dict], attr_map: dict) -> int:
    """Write introduced_by_* CSV columns onto finding rows from attr_map.

    Keyed on (repo, file, package, version) — the same manifest line a finding
    points at. Returns the count of rows that received a real commit. Only
    RESULT_FIELDS keys are written, so the rows stay DictWriter-safe.
    """
    n = 0
    for r in rows:
        a = attr_map.get((r.get("repo"), r.get("file"), r.get("package"), r.get("version")))
        if not a:
            continue
        sha = a.get("commit_sha")
        r["introduced_by_handle"]  = a.get("author_handle") or ""
        r["introduced_by_name"]    = a.get("author_name") or ""
        r["introduced_by_commit"]  = sha or ""
        r["introduced_by_date"]    = a.get("commit_date") or ""
        r["introduced_by_message"] = a.get("commit_message") or ""
        r["introduced_by_is_bot"]  = ("true" if a.get("is_bot") else "false") if sha else ""
        if sha:
            n += 1
    return n


def _attribution_pass(github: GitHubClient, args, per_repo_rule_rows: dict,
                      per_repo_osv_rows: dict, per_repo_sha: dict, totals: dict) -> None:
    """CLI attribution pass — the direct call into core enrich_attribution().

    Builds deduped attribution inputs from the buffered finding rows (+ each
    repo's branch SHA), runs enrich_attribution, and merges introduced_by_*
    columns back into the buffered rows by (repo, file, package, version).
    """
    log("\n===== ATTRIBUTION (Introduced By) =====")
    attr_cache = AttributionCache(cache_dir=args.cache_dir)

    all_finding_rows: list[dict] = []
    for rows in per_repo_rule_rows.values():
        all_finding_rows.extend(rows)
    for rows in per_repo_osv_rows.values():
        all_finding_rows.extend(rows)

    if not all_finding_rows:
        log("[attribution] no findings to attribute — skipping")
        return

    # One attribution input per unique (repo, file, package, version) finding.
    seen_keys: set = set()
    attr_input: list[dict] = []
    for r in all_finding_rows:
        key = (r.get("repo"), r.get("file"), r.get("package"), r.get("version"))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        attr_input.append({
            "repo_full_name": r.get("repo"),
            "file":           r.get("file"),
            "sha":            per_repo_sha.get(r.get("repo")),
            "ecosystem":      r.get("ecosystem"),
            "package":        r.get("package"),
            "version":        r.get("version"),
        })

    manifests = len({(i["repo_full_name"], i["file"], i["sha"]) for i in attr_input})
    state = {"last_emit_at": 0.0}

    def _attr_progress(payload: dict, _state=state) -> None:
        # Throttle the per-manifest firehose to ~1 line/sec for readable stdout.
        if payload.get("phase") != "attribution_progress":
            return
        now = time.monotonic()
        if now - _state["last_emit_at"] < 1.0:
            return
        _state["last_emit_at"] = now
        log(f"[attribution] {payload.get('current', 0)}/{payload.get('total', 0)} "
            f"manifests — {payload.get('repo', '')}:{payload.get('path', '')}")

    enriched = enrich_attribution(attr_input, github, attr_cache, on_progress=_attr_progress)

    attr_map = {
        (e.get("repo_full_name"), e.get("file"), e.get("package"), e.get("version")): e.get("attribution")
        for e in enriched
    }
    attributed = _merge_attribution(all_finding_rows, attr_map)
    totals["attributed"] = attributed
    log(f"[✓] Attribution complete: {manifests} manifests queried, {attributed} findings attributed")


def _resolve_targets(github: GitHubClient, args) -> tuple[list[str], list[str]]:
    """Targeting precedence: --repos > --orgs > /user/orgs auto-discover."""
    if args.repos:
        return args.repos, []
    if args.orgs:
        return [], args.orgs
    try:
        return [], github.list_user_orgs()
    except Exception as e:
        log(f"[!] Could not auto-discover orgs via /user/orgs: {e}")
        log("[!] Pass --orgs <org> [...] or --repos owner/name [...] to target explicitly.")
        sys.exit(1)


def _print_run_header(repo_specs: list[str], orgs: list[str], rules: dict, args) -> None:
    if repo_specs:
        log(f"[+] Repos:       {repo_specs}")
    else:
        log(f"[+] Orgs:        {orgs}")
    log(f"[+] Output:      {args.output}")
    log(f"[+] Cache:       {args.cache_dir} (schema v{CACHE_SCHEMA})    Rules: {len(rules)}")
    log(f"[+] Workers:     {args.workers}    Rate cap: {args.rps} req/s    Burst: {args.burst}")
    log(f"[+] OSV mode:    {'ON' if args.osv else 'off'}"
        + (f"    TTL: {args.osv_ttl}s    Rate cap: {args.osv_rps} req/s" if args.osv else ""))
    if args.osv:
        log(f"[+] KEV mode:    {'off (--no-kev)' if args.no_kev else 'ON'}    TTL: {args.kev_ttl}s")
        log(f"[+] Exploit:     {'off (--no-exploit-intel)' if args.no_exploit_intel else 'ON'}    TTL: {args.exploit_ttl}s")
    log(f"[+] Confusion:   {'off (--no-confusion)' if args.no_confusion else 'ON'}"
        + (f"    Patterns: {args.internal_patterns}" if args.internal_patterns else ""))
    log(f"[+] Typosquat:   {'ON' if args.typosquat else 'off'}")
    if not rules and not args.osv:
        log("[!] No rules and no --osv. Inventory will be cached but no CSV rows will be written.")


def _print_run_footer(args, totals: dict) -> None:
    log(f"\n[✓] Done. repos={totals['repos']}")
    log(f"    Rule rows: {totals['rule_hits']} (vulnerable: {totals['rule_vuln']})")
    if args.osv:
        log(f"    OSV rows:  {totals['osv_hits']}")
        if not args.no_kev:
            log(f"    KEV:       {totals['kev_hits']} finding(s) are known exploited vulnerabilities")
        if not args.no_exploit_intel:
            log(f"    Exploit-DB:  {totals['exploitdb_hits']} finding(s) have known public exploit code")
            log(f"    Metasploit:  {totals['metasploit_hits']} finding(s) have a Metasploit module")
            log(f"    Has Exploit: {totals['exploit_hits']} finding(s) (KEV/ExploitDB/Metasploit)")
        log(f"    Fix avail: {totals['fix_available_hits']} finding(s) have a fix version available")
    if not args.no_confusion:
        log(f"    Confusion: {totals['confusion_hits']} dependency-confusion finding(s)")
    if args.typosquat:
        log(f"    Typosquat: {totals['typosquat_hits']} typosquatting finding(s)")
    log(f"    Output:    {args.output}")


def _print_reachability_summary(reach_totals: dict) -> None:
    sep = "─" * 36
    log(f"\n{sep}")
    log("Reachability Summary")
    log(sep)
    log(f"REACHABLE  {reach_totals.get('REACHABLE', 0):4d}   (fix these)")
    log(f"UNUSED     {reach_totals.get('UNUSED', 0):4d}   (deprioritise)")
    log(f"UNKNOWN    {reach_totals.get('UNKNOWN', 0):4d}   (verify manually)")
    log(sep)


def _build_batches(github: GitHubClient, repo_specs: list[str],
                   orgs: list[str]) -> list[tuple[str, list[dict]]]:
    """Group target repos by label for per-batch progress reporting."""
    batches: list[tuple[str, list[dict]]] = []
    if repo_specs:
        repos: list[dict] = []
        for spec in repo_specs:
            spec = spec.strip().strip("/")   # zsh/fish can prepend a slash on tab-complete
            if "/" not in spec:
                log(f"[!] Bad --repos value '{spec}' — expected owner/name. Skipping.")
                continue
            owner, name = spec.split("/", 1)
            try:
                repos.append(github.get_repo_meta(owner, name))
            except Exception as e:
                log(f"[!] Could not fetch repo {spec}: {e}")
        if repos:
            batches.append(("--repos targets", repos))
    else:
        for org in orgs:
            log(f"\n===== ORG: {org} =====")
            try:
                batches.append((org, github.list_org_repos(org)))
            except Exception as e:
                log(f"[!] Failed to list repos for '{org}': {e}")
                continue
    return batches


def _scan_batch(
    label: str, repos: list[dict], scanner: Scanner, cache: InventoryCache, args,
    writer, inventory_lock: threading.Lock, per_repo_inventory: dict,
    totals: dict, use_bar: bool,
    per_repo_rule_rows: dict | None = None,
    per_repo_sha: dict | None = None,
) -> None:
    """Submit a batch of repos to the thread pool and drain results."""
    n = len(repos)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(
                scanner.scan_repo,
                repo,
                f"[{idx}/{n}]",
                args.full_rescan or not _repo_uses_cache(cache, repo["full_name"], args.full_rescan),
            ): repo["full_name"]
            for idx, repo in enumerate(repos, 1)
        }

        completed_iter = as_completed(futures)
        bar = None
        if use_bar:
            bar = tqdm(
                completed_iter,
                total=len(futures),
                desc=f"Scanning [{label}]",
                unit="repo",
                dynamic_ncols=True,
            )
            completed_iter = bar

        done_count = 0
        batch_inv  = 0

        for fut in completed_iter:
            done_count += 1
            full_name = futures[fut]
            try:
                result = fut.result()
            except Exception as e:
                log(f"[!] {full_name}: worker crashed: {e}")
                continue

            if result["skipped"] or result.get("error"):
                if bar:
                    bar.set_postfix(rule_hits=totals["rule_hits"], vuln=totals["rule_vuln"], inv=batch_inv)
                continue

            rows = result["rows"]
            vuln = sum(1 for r in rows if r.get("status") == "vulnerable")
            batch_inv += len(result["inventory"])

            # Custom Rule rows carry no CVE, so they never match the exploit
            # catalogs (empty sets) — but they still need the has_* columns set
            # uniformly ("false") and has_fix derived from fix_versions.
            for r in rows:
                _finalize_finding_row(r, set(), set())
            totals["fix_available_hits"] += sum(1 for r in rows if r.get("has_fix") == "true")

            totals["rule_hits"] += len(rows)
            totals["rule_vuln"] += vuln

            if per_repo_rule_rows is not None:
                with inventory_lock:
                    per_repo_rule_rows[full_name] = rows
            else:
                writer.write_rows(rows)

            # Inventory feeds the OSV pass, the confusion pass AND the typosquat
            # pass — collect it when any is active.
            if args.osv or not args.no_confusion or args.typosquat:
                with inventory_lock:
                    per_repo_inventory[full_name] = result["inventory"]

            if result["sha"]:
                cache.update_index(full_name, result["sha"])
                if per_repo_sha is not None:
                    with inventory_lock:
                        per_repo_sha[full_name] = result["sha"]

            if bar:
                bar.set_postfix(rule_hits=totals["rule_hits"], vuln=totals["rule_vuln"], inv=batch_inv)
            elif args.summary_every > 0 and done_count % args.summary_every == 0:
                log(f"[~] [{label}] {done_count}/{n} repos done — inv={batch_inv}, rule_hits={totals['rule_hits']}, vuln={totals['rule_vuln']}")

        if bar:
            bar.close()
