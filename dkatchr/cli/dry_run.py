"""
Dry-run report — estimate API cost + wall time without making any scan calls.

EXTRACTED FROM: dkatchr/cli.py (_dry_run_report).
WHY: It's a self-contained reporting feature. Pulling it out keeps the
orchestration runner small and lets us evolve the estimate model without
touching the scan path.
"""

from dkatchr.logger import log
from dkatchr.storage.inventory_cache import InventoryCache


def _repo_uses_cache(cache: InventoryCache, full_name: str, full_rescan: bool) -> bool:
    """Cheap check — only consults the index, doesn't hit GitHub."""
    if full_rescan:
        return False
    return bool(cache.get_index_sha(full_name))


def print_dry_run_report(batches, cache: InventoryCache, args) -> None:
    """Estimate cost + wall time without making any scan API calls."""
    all_repos      = [r for _, batch in batches for r in batch]
    n_total        = len(all_repos)
    n_archived     = sum(1 for r in all_repos if r.get("archived"))
    n_no_branch    = sum(1 for r in all_repos if not r.get("default_branch"))
    n_active       = n_total - n_archived - n_no_branch
    n_warm         = sum(1 for r in all_repos if _repo_uses_cache(cache, r["full_name"], args.full_rescan))
    n_cold         = n_active - n_warm

    cold_cost      = n_cold * 5
    warm_cost      = n_warm * 1
    total_cost     = cold_cost + warm_cost
    wall_seconds   = total_cost / max(args.rps, 0.001)
    budget_pct     = total_cost / 5000 * 100

    log(f"\n===== DRY RUN =====")
    log(f"  Repos discovered:     {n_total}")
    log(f"    archived (skipped): {n_archived}")
    log(f"    no default branch:  {n_no_branch}")
    log(f"    active to scan:     {n_active}")
    log(f"      warm cache hits:  {n_warm}")
    log(f"      cold (full scan): {n_cold}")
    log(f"")
    log(f"  Estimated GitHub API calls: ~{total_cost} ({cold_cost} cold + {warm_cost} warm)")
    log(f"  Hourly budget usage:        ~{budget_pct:.1f}% of 5000 req/hr")
    log(f"  Wall time at {args.rps:.2f} req/s: ~{wall_seconds/60:.1f} min ({wall_seconds/3600:.2f} h)")
    if budget_pct > 100:
        extra_hours = (budget_pct - 100) / 100 + 1
        log(f"  [!] Over hourly budget — will pause for rate-limit reset(s); add ~{extra_hours:.1f}h")
    if args.osv:
        log(f"")
        log(f"  OSV enrichment: enabled (separate budget, ~1-5 min added regardless of repo count)")

    sample = all_repos[:10]
    if sample:
        log(f"")
        log(f"  First {len(sample)} repos:")
        for r in sample:
            tag = (
                "[archived]" if r.get("archived")
                else "[no-branch]" if not r.get("default_branch")
                else "[cached]" if _repo_uses_cache(cache, r["full_name"], args.full_rescan)
                else "[cold]"
            )
            log(f"    {tag:<12} {r['full_name']}")
        if n_total > len(sample):
            log(f"    ... and {n_total - len(sample)} more")
