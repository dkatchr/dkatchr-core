"""
Level 1 reachability analysis: import presence check via tarball + Aho-Corasick.

WHY: Reduces alert noise by filtering vulnerabilities where the affected package
is not imported anywhere in the repository source code. A package present in a
lockfile but never imported is not reachable from application code.

APPROACH: Resolve import names via the package registry for each (package,
ecosystem) pair (see dkatchr/clients/resolvers/). Download a gzipped tarball
of the repo at the scanned SHA, then run a single-pass Aho-Corasick search
across all source files for the union of language-specific patterns generated
from those resolved import names. Replaces the prior GitHub Code Search
implementation, which had a 10 req/min cap and an indexing delay that made
it unusable in production.

ACCURACY NOTES:
- Import name ≠ install name in some ecosystems (PyPI especially). The
  ImportNameResolver queries the package registry at scan time and caches
  the answer. When resolution fails, the package is marked UNKNOWN —
  never UNUSED.
- Maven reachability is artifact-level: we read the JAR's exported packages
  (OSGi MANIFEST.MF when present, .class paths otherwise), so a match means
  "the vulnerable artifact's package is imported".
- Dynamic imports (Python importlib, JS dynamic import()) are not detected. These
  are a source of false negatives. Level 2 LLM analysis addresses this.
- Test files are excluded by default (configurable). A package used only in tests
  is labelled UNUSED with no evidence.
- Minified bundles, generated protobufs, and other files over
  REACHABILITY_MAX_FILE_BYTES are skipped — they will not contain readable import
  statements anyway and would dominate scan time.

EXTRA PATTERNS (tier-neutral mechanics): enrich_reachability() optionally
accepts caller-supplied literal strings (`extra_patterns`) that ride along in
the same automaton and the same single tarball pass, and returns the complete
per-pattern → files match map via `match_map_out`. This module neither
generates nor interprets those patterns — it has zero knowledge of what they
mean. (The web layer's paid Level 2 feature is one such caller; its advisory
parsing, LLM calls, pattern generation, and labeling all live in web/.)

Does NOT: perform function-level call graph analysis (that is Level 2), access
the filesystem outside the cache dir, write to any DB or CSV, or know about
CLI/web concerns.
"""

import tarfile
from typing import Callable, IO

import ahocorasick

from dkatchr.clients.github import GitHubClient, TarballSizeExceeded
from dkatchr.clients.resolvers import ImportNameResolver
from dkatchr.config import (
    REACHABILITY_MAX_FILE_BYTES,
    REACHABILITY_SCAN_PROGRESS_EVERY,
    REACHABILITY_SNIPPET_MAX_CHARS,
    REACHABILITY_SOURCE_EXTENSIONS,
    REACHABILITY_TEST_FILE_PATTERNS,
    REGISTRY_RESOLVER_WORKERS,
)
from dkatchr.logger import log
from dkatchr.storage.reachability_cache import ReachabilityCache

ProgressCb = Callable[[dict], None] | None

REACHABLE = "REACHABLE"
UNUSED    = "UNUSED"
UNKNOWN   = "UNKNOWN"


# ---- file classification ---------------------------------------------------

def _is_test_file(path: str) -> bool:
    lower = path.lower()
    return any(pat in lower for pat in REACHABILITY_TEST_FILE_PATTERNS)


def _is_source_file(path: str) -> bool:
    lower = path.lower()
    for ext in REACHABILITY_SOURCE_EXTENSIONS:
        if lower.endswith(ext):
            return True
    return False


# ---- pattern construction ---------------------------------------------------

def _build_patterns(import_names: list[str], ecosystem: str) -> list[str]:
    """Generate language-specific search patterns from resolved import names.

    Receives already-resolved import names from the registry resolver and
    only turns them into source-text patterns the Aho-Corasick automaton
    will look for. Returns an empty list when ``import_names`` is empty —
    callers must emit UNKNOWN in that case rather than guessing.
    """
    if not import_names:
        return []

    eco = ecosystem.lower()

    if eco == "pypi":
        patterns: list[str] = []
        seen: set[str] = set()
        for raw in import_names:
            # PyPI top_level.txt entries are sometimes given with a `.py`
            # suffix or as a directory path. Normalize before emitting.
            n = raw.strip().replace("/", ".").rstrip(".")
            if n.endswith(".py"):
                n = n[:-3]
            if not n or n in seen:
                continue
            seen.add(n)
            patterns += [
                f"import {n}",         # `import requests` / `import requests as r`
                f"from {n} import",    # `from requests import x`
                f"from {n}.",          # `from requests.adapters import HTTPAdapter`
                # Dynamic import — uncommon but real (plugins, lazy loading)
                f"import_module('{n}'",
                f'import_module("{n}"',
                f"__import__('{n}'",
                f'__import__("{n}"',
            ]
        return patterns

    if eco == "npm":
        patterns = []
        for n in import_names:
            if not n:
                continue
            patterns += [
                # CommonJS
                f"require('{n}')",
                f'require("{n}")',
                f"require('{n}/",
                f'require("{n}/',
                # ES module: bare + subpath + side-effect
                f"from '{n}'",
                f'from "{n}"',
                f"from '{n}/",
                f'from "{n}/',
                f"import '{n}'",
                f'import "{n}"',
                # Dynamic ES import
                f"import('{n}')",
                f'import("{n}")',
                f"import('{n}/",
                f'import("{n}/',
            ]
        return patterns

    if eco == "rubygems":
        patterns = []
        for require_name in import_names:
            if not require_name:
                continue
            patterns += [
                f"require '{require_name}'",
                f'require "{require_name}"',
            ]
            # The require name `nokogiri` corresponds to the constant
            # `Nokogiri`, `active_record` → `ActiveRecord`, `rest_client`
            # → `RestClient`, `pg` → `PG`. Derive the module candidates
            # deterministically from the resolved require name (which is
            # itself authoritative because it came from the gem's lib/).
            for mod in _ruby_module_candidates_from_require(require_name):
                patterns.append(f"{mod}::")  # namespace: `Rails::Application`
                patterns.append(f"{mod}.")   # method:    `Rails.application`
        return patterns

    if eco == "go":
        patterns: list[str] = []
        for n in import_names:
            if not n:
                continue
            patterns.append(f'"{n}"')
            for suffix in ("/v2", "/v3", "/v4", "/v5"):
                if n.endswith(suffix):
                    patterns.append(f'"{n[:-len(suffix)]}"')
                    break
        return patterns

    if eco == "crates.io":
        patterns = []
        seen: set[str] = set()
        for n in import_names:
            if not n or n in seen:
                continue
            seen.add(n)
            patterns += [
                f"use {n}::",
                f"use {n};",
                f"extern crate {n}",
                f"{n}::",
            ]
        return patterns

    if eco == "maven":
        # Resolved import names ARE Java packages (e.g. `com.fasterxml.jackson.core`).
        # `import` / `import static` are unambiguous; bare FQN matches like
        # `org.apache.` collide with URLs and license headers — do not emit.
        patterns = []
        for ns in import_names:
            if not ns:
                continue
            patterns += [
                f"import {ns}.",
                f"import static {ns}.",
                f"import {ns};",        # `import com.example.Foo;` where Foo == package
            ]
        return patterns

    if eco == "nuget":
        # Resolved import names are .NET namespaces from the package's DLLs.
        patterns = []
        for ns in import_names:
            if not ns:
                continue
            patterns += [
                f"using {ns}",          # `using Newtonsoft.Json;` and `using Newtonsoft.Json.Linq;`
                f"using static {ns}.",  # `using static Newtonsoft.Json.JsonConvert;`
                f"{ns}.",               # inline FQN
            ]
        return patterns

    if eco == "packagist":
        # Resolved import names are PHP namespace roots (e.g. `Symfony\Component`).
        patterns = []
        for ns in import_names:
            if not ns:
                continue
            patterns += [
                f"use {ns}\\",
                f"use {ns};",
                f"new {ns}\\",
                f"\\{ns}\\",
            ]
        return patterns

    return []  # unknown ecosystem


def build_import_patterns(import_names: list[str], ecosystem: str) -> list[str]:
    """Public alias for orchestrators that need the exact import-pattern
    strings the grep searched (e.g. to interpret a returned match map by
    package). Same pure function; the underscore name stays for module
    internals and existing API contracts."""
    return _build_patterns(import_names, ecosystem)


def ruby_module_candidates(require_name: str) -> list[str]:
    """Public alias of _ruby_module_candidates_from_require — see above."""
    return _ruby_module_candidates_from_require(require_name)


def _ruby_module_candidates_from_require(require_name: str) -> list[str]:
    """
    Translate a Ruby require name into the canonical top-level constant(s).

    The require name comes from the gem's own lib/ directory so it is
    already authoritative — this function only applies Ruby's deterministic
    `require → constant` casing rules:
    - acronym names (<= 4 chars) → uppercase + PascalCase (`pg` → `PG`, `Pg`)
    - snake_case  → PascalCase  (`active_record` → `ActiveRecord`)
    - kebab-case  → both Namespace:: and PascalCase (`omniauth-oauth2` →
      `OmniauthOauth2`, `Omniauth::Oauth2`)
    - simple lowercase → Capitalized (`rails` → `Rails`)
    """
    if not require_name:
        return []

    cands: set[str] = set()
    cands.add(require_name[:1].upper() + require_name[1:].lower())

    if len(require_name) <= 4:
        cands.add(require_name.upper())

    if "_" in require_name:
        parts = [p for p in require_name.split("_") if p]
        cands.add("".join(p[:1].upper() + p[1:].lower() for p in parts))

    if "-" in require_name:
        parts = [p for p in require_name.split("-") if p]
        camel = [p[:1].upper() + p[1:].lower() for p in parts]
        cands.add("".join(camel))
        cands.add("::".join(camel))

    return sorted(cands)


# ---- the scan --------------------------------------------------------------

def _grep_tar_stream(
    stream: IO[bytes],
    automaton: "ahocorasick.Automaton",
    all_patterns: list[str],
    exclude_test_files: bool,
    on_progress: ProgressCb = None,
    allow_early_exit: bool = True,
    detail_patterns: set[str] | frozenset[str] | None = None,
    detail_hits_out: dict[str, list[dict]] | None = None,
) -> dict[str, list[str]]:
    """
    Stream a gzipped tarball through tarfile in r|gz mode, applying
    Aho-Corasick to each source file as it appears. Memory usage is bounded
    by the largest single file (capped at REACHABILITY_MAX_FILE_BYTES), NOT
    by the tarball size — a 1GB tarball never lands in RAM.

    Returns {pattern: [file_paths_where_found]}.

    `allow_early_exit` controls the "stop once every pattern has matched at
    least once" optimization. When False, the whole stream is scanned so the
    returned map is a COMPLETE per-pattern file inventory — callers that need
    per-file co-occurrence (did patterns A and B hit the same file?) must
    disable early exit, because an early-exited map only proves first
    occurrence, not co-occurrence.

    `detail_patterns` + `detail_hits_out`: for the listed patterns, the FIRST
    occurrence in each file is captured with its location —
    {pattern: [{"file", "line", "snippet"}]} — where `line` is 1-based and
    `snippet` is the whitespace-collapsed source line, bounded by
    REACHABILITY_SNIPPET_MAX_CHARS. Pure capture mechanics for callers that
    need call-site anchors; the file paths are tar member names (which carry
    the archive's root directory prefix — callers strip it for display).

    `on_progress` (optional) is called every REACHABILITY_SCAN_PROGRESS_EVERY
    tar members with a dict:
      {"phase": "scanning_progress", "members_seen": N,
       "files_scanned": M, "files_skipped": S,
       "patterns_matched": P, "patterns_remaining": R,
       "current_file": "..."}
    """
    matches: dict[str, list[str]] = {p: [] for p in all_patterns}
    remaining: set[str] = set(all_patterns)
    total_patterns = len(all_patterns)
    detail_patterns = detail_patterns or frozenset()
    capture_details = detail_hits_out is not None and bool(detail_patterns)

    members_seen  = 0
    files_scanned = 0
    files_skipped = 0
    last_file: str = ""

    def _tick(final: bool = False) -> None:
        if on_progress is None:
            return
        try:
            on_progress({
                "phase":              "scanning_complete" if final else "scanning_progress",
                "members_seen":       members_seen,
                "files_scanned":      files_scanned,
                "files_skipped":      files_skipped,
                "patterns_matched":   total_patterns - len(remaining),
                "patterns_total":     total_patterns,
                "patterns_remaining": len(remaining),
                "current_file":       last_file,
            })
        except Exception:
            pass

    # Streaming mode: r|gz. tarfile reads members forward without seeking;
    # `tar` is iterable, yielding TarInfo objects one at a time. We MUST
    # extract each member's content before advancing.
    with tarfile.open(fileobj=stream, mode="r|gz") as tar:
        for member in tar:
            members_seen += 1

            # Early exit: every pattern already has a match — reading more
            # files cannot improve the result. Skipped when the caller needs
            # the complete per-file map (see allow_early_exit above).
            if allow_early_exit and not remaining:
                break

            if not member.isfile():
                if members_seen % REACHABILITY_SCAN_PROGRESS_EVERY == 0:
                    _tick()
                continue
            if not _is_source_file(member.name):
                if members_seen % REACHABILITY_SCAN_PROGRESS_EVERY == 0:
                    _tick()
                continue
            if exclude_test_files and _is_test_file(member.name):
                files_skipped += 1
                if members_seen % REACHABILITY_SCAN_PROGRESS_EVERY == 0:
                    _tick()
                continue

            # Per-file size cap: skip minified / generated / vendor blobs.
            if member.size > REACHABILITY_MAX_FILE_BYTES:
                files_skipped += 1
                log(
                    f"[reachability] skipping oversized file "
                    f"{member.name} ({member.size / 1024:.0f}KB)"
                )
                if members_seen % REACHABILITY_SCAN_PROGRESS_EVERY == 0:
                    _tick()
                continue

            try:
                f = tar.extractfile(member)
                if f is None:
                    continue
                content = f.read().decode("utf-8", errors="ignore")
            except Exception as e:
                log(f"[reachability] could not read {member.name}: {e}")
                continue

            files_scanned += 1
            last_file = member.name

            found_in_file: set[str] = set()
            detailed_in_file: set[str] = set()
            for end_idx, pattern in automaton.iter(content):
                found_in_file.add(pattern)
                if (capture_details and pattern in detail_patterns
                        and pattern not in detailed_in_file):
                    # First occurrence per (pattern, file) — enough for a
                    # call-site anchor, and bounds memory to the same order
                    # as the matches map itself.
                    detailed_in_file.add(pattern)
                    start = end_idx - len(pattern) + 1
                    line_start = content.rfind("\n", 0, start) + 1
                    line_end = content.find("\n", line_start)
                    if line_end == -1:
                        line_end = len(content)
                    snippet = " ".join(
                        content[line_start:line_end].split()
                    )[:REACHABILITY_SNIPPET_MAX_CHARS]
                    detail_hits_out.setdefault(pattern, []).append({
                        "file":    member.name,
                        "line":    content.count("\n", 0, start) + 1,
                        "snippet": snippet,
                    })

            for pattern in found_in_file:
                matches[pattern].append(member.name)
                remaining.discard(pattern)

            if files_scanned % REACHABILITY_SCAN_PROGRESS_EVERY == 0:
                _tick()

    _tick(final=True)
    return matches


def enrich_reachability(
    vuln_rows: list[dict],
    repo_full_name: str,
    sha: str,
    github_client: GitHubClient,
    cache: ReachabilityCache,
    cache_dir: str,
    exclude_test_files: bool = True,
    on_progress: ProgressCb = None,
    extra_patterns: list[str] | None = None,
    match_map_out: dict[str, list[str]] | None = None,
    extra_hits_out: dict[str, list[dict]] | None = None,
) -> list[dict]:
    """
    For each vuln row, decide REACHABLE / UNUSED / UNKNOWN by searching
    the repo source for import statements that would pull the vulnerable
    package in. Mutates and returns the rows with `reachability` and
    `reachability_evidence` populated.

    Pipeline:
      1. Cache check (keyed by SHA). On hit, apply cached results and return.
      2. Resolve import names for every unique (package, ecosystem) pair via
         the registry resolver (cached by ecosystem+package).
      3. Build pattern set from resolved import names.
      4. Download tarball. On failure, mark every row UNKNOWN and return.
      5. Build a single Aho-Corasick automaton over the union of all patterns.
      6. Single-pass grep across all source files with early exit once every
         pattern has been matched at least once.
      7. Resolve labels per (package, ecosystem) pair.
      8. Write cache (best-effort).
      9. Apply to rows.

    `extra_patterns` (optional) are caller-supplied literal strings added to
    the same automaton and searched in the same single tarball pass. They are
    pure search mechanics: they never influence the reachability labels this
    function assigns, and they are not persisted to the reachability cache.
    Passing a non-empty list changes two behaviors, both required for the
    caller to interpret the results safely:
      - The SHA-keyed cache shortcut is skipped (a cached match map does not
        cover the extra patterns, and lacks the complete per-file inventory),
        so a fresh download + grep always happens.
      - The grep's early exit is disabled, so the resulting map is a complete
        per-pattern file inventory and per-file co-occurrence between any two
        patterns can be derived from it.

    `match_map_out` (optional) is an out-param dict the caller provides; after
    a successful grep it is filled with the full {pattern: [files]} map for
    every searched pattern (import patterns + extra patterns). Left untouched
    when the grep never ran (cache hit, no patterns, tarball failure) — an
    empty dict therefore means "no fresh match data".

    `extra_hits_out` (optional) is a second out-param: for each extra pattern,
    the first occurrence per file is captured with its location —
    {pattern: [{"file", "line", "snippet"}]} (see _grep_tar_stream). Pure
    capture mechanics; this function attaches no meaning to the hits.

    `on_progress` (optional) emits phase events so orchestrators (CLI, web
    runner) can surface what's happening to humans waiting on a slow scan.
    Phases: cache_hit, cache_hit_partial_retry, resolving_start,
    resolving_package, resolved, resolution_failed, resolving_done,
    tarball_downloading, tarball_downloaded, building_automaton,
    scanning_progress, scanning_complete, resolving, cached,
    tarball_failed, no_patterns.
    """
    if not vuln_rows:
        return vuln_rows

    extras: list[str] = [p for p in (extra_patterns or []) if p]

    def _emit(payload: dict) -> None:
        if on_progress is None:
            return
        try:
            on_progress(payload)
        except Exception:
            pass

    # ---- 1. cache check ------------------------------------------------
    # Skipped when extra patterns are present: the cached match map covers
    # only the import patterns of the original run and was (potentially)
    # early-exited, so it can neither answer the extra patterns nor provide
    # the complete per-file inventory the caller needs. Callers gate their
    # own extra-pattern requests, so this only forces a download when one
    # is genuinely required.
    cached_results, cached_matches = (None, None) if extras else cache.read(repo_full_name, sha)
    if cached_results is not None:
        # Identify packages from current vuln_rows that are absent from the
        # cached results dict. Per v2, packages with failed resolution are
        # omitted from results (not stored as UNKNOWN), so on a cache hit
        # they still need a decision. Retry resolution for just those
        # packages and decide their label against the stored match index —
        # no tarball download required, since the AC search already happened.
        missing_pairs: list[tuple[str, str]] = []
        seen_missing: set[tuple[str, str]] = set()
        retry_versions: dict[tuple[str, str], str] = {}
        for row in vuln_rows:
            pkg = row.get("package", "")
            eco = row.get("ecosystem", "")
            if f"{pkg}::{eco}" in cached_results:
                continue
            pair = (pkg, eco)
            if pair in seen_missing:
                continue
            seen_missing.add(pair)
            missing_pairs.append(pair)
            v = row.get("version") or ""
            if v and pair not in retry_versions:
                retry_versions[pair] = v

        if missing_pairs:
            _emit({
                "phase":   "cache_hit_partial_retry",
                "sha":     sha[:8],
                "missing": len(missing_pairs),
            })
            resolver = ImportNameResolver(
                cache_dir=cache_dir,
                max_workers=REGISTRY_RESOLVER_WORKERS,
            )
            retry_resolved = resolver.resolve_batch(
                missing_pairs,
                on_progress=on_progress,
                versions=retry_versions,
            )
            updated = False
            for (package, ecosystem) in missing_pairs:
                names = retry_resolved.get((package, ecosystem), [])
                patterns = _build_patterns(names, ecosystem)
                if not patterns:
                    # Resolution failed again. Leave the package out of
                    # results so _apply_results_to_rows falls back to
                    # UNKNOWN, and so a future scan retries again.
                    continue
                # The stored match index distinguishes "searched, no match"
                # (key present, empty list) from "never searched" (key
                # absent). Deciding from absent keys would stamp UNUSED on a
                # package whose patterns were never in the original
                # automaton — a false UNUSED, persisted forever for this
                # SHA. Any hit is trustworthy evidence (REACHABLE); UNUSED
                # is only safe when EVERY pattern was actually searched.
                found = [f for p in patterns for f in cached_matches.get(p, [])]
                if found:
                    label    = REACHABLE
                    evidence = list(dict.fromkeys(found))[:5]
                elif all(p in cached_matches for p in patterns):
                    label, evidence = UNUSED, []
                else:
                    # Not all patterns were searched in the original run —
                    # leave the package out of results (→ UNKNOWN this scan;
                    # a fresh-SHA scan will search it for real).
                    continue
                cached_results[f"{package}::{ecosystem}"] = {
                    "label":    label,
                    "evidence": evidence,
                }
                updated = True
            if updated:
                cache.write(repo_full_name, sha, cached_results, cached_matches)
        else:
            _emit({"phase": "cache_hit", "sha": sha[:8]})

        _apply_results_to_rows(vuln_rows, cached_results)
        return vuln_rows

    def _dl_progress(downloaded: int, total: int | None) -> None:
        _emit({
            "phase":            "tarball_downloading",
            "downloaded_bytes": downloaded,
            "total_bytes":      total,
        })

    # ---- 2. resolve import names for every unique (package, ecosystem) -
    # Built BEFORE opening the stream so we don't hold an HTTP connection
    # open while doing CPU work that has nothing to do with bytes.
    unique_pairs: list[tuple[str, str]] = []
    seen_pairs: set[tuple[str, str]] = set()
    pair_versions: dict[tuple[str, str], str] = {}
    for row in vuln_rows:
        key = (row.get("package", ""), row.get("ecosystem", ""))
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        unique_pairs.append(key)
        v = row.get("version") or ""
        if v and key not in pair_versions:
            pair_versions[key] = v

    resolver = ImportNameResolver(
        cache_dir=cache_dir,
        max_workers=REGISTRY_RESOLVER_WORKERS,
    )
    resolved = resolver.resolve_batch(
        unique_pairs,
        on_progress=on_progress,
        versions=pair_versions,
    )

    # ---- 3. build patterns from resolved names ------------------------
    pair_patterns: dict[tuple[str, str], list[str]] = {}
    for key in unique_pairs:
        names = resolved.get(key, [])
        pair_patterns[key] = _build_patterns(names, key[1])

    all_patterns = sorted({p for patterns in pair_patterns.values() for p in patterns})

    if not all_patterns:
        # No import patterns means resolution failed for every package, so
        # every label is UNKNOWN regardless of what the extra patterns might
        # find — don't pay for a download that can't change any outcome.
        _emit({"phase": "no_patterns", "unique_packages": len(pair_patterns)})
        results = {
            f"{pkg}::{eco}": {"label": UNKNOWN, "evidence": []}
            for (pkg, eco) in pair_patterns
        }
        # Do NOT write to cache here. Empty patterns means resolution failed
        # for every package (missing resolver, network error, etc). Caching
        # this would poison future scans of the same SHA even after the
        # underlying problem is fixed. Only cache successful resolution runs.
        _apply_results_to_rows(vuln_rows, results)
        return vuln_rows

    search_patterns = sorted(set(all_patterns) | set(extras))

    _emit({
        "phase":           "building_automaton",
        "unique_packages": len(pair_patterns),
        "patterns":        len(search_patterns),
    })
    automaton = ahocorasick.Automaton()
    for pattern in search_patterns:
        automaton.add_word(pattern, pattern)
    automaton.make_automaton()

    # ---- 4+6. open streaming tarball + scan in one pass --------------
    _emit({"phase": "tarball_downloading", "downloaded_bytes": 0, "total_bytes": None})
    stream, dl_reason = github_client.open_repo_tarball_stream(
        repo_full_name, ref=sha, on_progress=_dl_progress,
    )
    if stream is None:
        _emit({"phase": "tarball_failed", "reason": dl_reason})
        evidence = f"tarball_unavailable: {dl_reason}"
        for row in vuln_rows:
            row["reachability"]          = UNKNOWN
            row["reachability_evidence"] = evidence
        return vuln_rows

    log(f"[reachability] {repo_full_name} streaming tarball...")
    matches: dict[str, list[str]] = {}
    stream_reason: str | None = None
    try:
        with stream:
            try:
                matches = _grep_tar_stream(
                    stream, automaton, search_patterns, exclude_test_files,
                    on_progress=on_progress,
                    # Extra patterns need the complete per-file map (their
                    # consumers derive per-file co-occurrence from it) — an
                    # early-exited map would silently under-report.
                    allow_early_exit=not extras,
                    detail_patterns=frozenset(extras),
                    detail_hits_out=extra_hits_out,
                )
            except TarballSizeExceeded as e:
                stream_reason = e.reason
            except Exception as e:
                stream_reason = (
                    stream.failure_reason
                    or f"stream_error: {type(e).__name__}: {e}"[:200]
                )
                log(f"[reachability] {repo_full_name} stream aborted: {stream_reason}")
    except Exception as e:
        stream_reason = stream_reason or f"stream_error: {type(e).__name__}: {e}"[:200]

    if stream_reason is not None:
        _emit({"phase": "tarball_failed", "reason": stream_reason,
               "bytes_read": getattr(stream, "bytes_read", 0)})
        evidence = f"tarball_unavailable: {stream_reason}"
        for row in vuln_rows:
            row["reachability"]          = UNKNOWN
            row["reachability_evidence"] = evidence
        return vuln_rows

    _emit({
        "phase":      "tarball_downloaded",
        "size_bytes": getattr(stream, "bytes_read", 0),
    })

    if match_map_out is not None:
        match_map_out.update(matches)

    # ---- 7. resolve labels per (package, ecosystem) pair --------------
    _emit({"phase": "resolving", "pairs": len(pair_patterns)})
    results: dict[str, dict] = {}
    for (package, ecosystem), patterns in pair_patterns.items():
        if not patterns:
            # Resolution failed for this package (empty import names from
            # registry). Do NOT include in cache — the cache would lie by
            # treating a resolver error as a legitimate UNKNOWN result,
            # preventing any retry on the next same-SHA scan even after the
            # underlying problem (missing lib, network, bad registry response)
            # is fixed. _apply_results_to_rows handles missing keys as UNKNOWN,
            # so the current scan still surfaces the correct label.
            continue

        found = [f for p in patterns for f in matches.get(p, [])]
        if found:
            label    = REACHABLE
            evidence = list(dict.fromkeys(found))[:5]  # dedupe preserving order, cap 5
        else:
            label, evidence = UNUSED, []

        results[f"{package}::{ecosystem}"] = {"label": label, "evidence": evidence}

    # ---- 8. write cache -----------------------------------------------
    # Persist the raw AC matches alongside results so that a future cache hit
    # can decide labels for packages whose resolution failed this run (and
    # were therefore omitted from `results`) without re-downloading the tarball.
    # Only the import-pattern matches are persisted — extra patterns are
    # caller-owned mechanics with their own caching story, and storing them
    # here would bloat the cache and confuse the partial-retry lookup.
    write_results, write_matches = results, matches
    if extras:
        write_matches = {p: matches.get(p, []) for p in all_patterns}
        # Extras skipped the cache shortcut, so an entry for this SHA may
        # already exist (and may know packages/patterns this run didn't
        # cover — different vuln rows, transient resolution failure).
        # Same SHA ⇒ old data is still valid: merge instead of clobbering,
        # with this run's fresher entries winning per key.
        prev_results, prev_matches = cache.read(repo_full_name, sha)
        if prev_results is not None:
            write_results = {**prev_results, **results}
            write_matches = {**prev_matches, **write_matches}
    cache.write(repo_full_name, sha, write_results, write_matches)

    # ---- 9. apply to rows ---------------------------------------------
    _apply_results_to_rows(vuln_rows, results)
    return vuln_rows


def _apply_results_to_rows(vuln_rows: list[dict], results: dict) -> None:
    """Apply a results dict (as produced or as cached) onto vuln rows in place."""
    for row in vuln_rows:
        key = f"{row.get('package', '')}::{row.get('ecosystem', '')}"
        entry = results.get(key)
        if entry is None:
            row["reachability"]          = UNKNOWN
            row["reachability_evidence"] = ""
            continue
        row["reachability"]          = entry.get("label", UNKNOWN)
        row["reachability_evidence"] = "|".join(entry.get("evidence") or [])
