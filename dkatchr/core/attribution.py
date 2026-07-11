"""
Commit attribution ("Introduced By") — find which commit author last touched a
vulnerable package's line in its manifest, and attach that to each finding.

This is the attribution equivalent of dkatchr/core/osv_enrichment.py: a pure
core module that owns the full workflow. find_package_line() and
resolve_attribution() are pure string functions; enrich_attribution() is the
orchestration entry point — the analogue of osv_enrich() — called identically by
the CLI runner and (through the engine seam) by the web runner. Neither runner
reimplements the loop; the only runner-specific code is output binding (CSV vs
DB).

What this module does NOT do:
  - No HTTP, no file reads, no DB, no threading. All I/O is delegated to the
    injected `github_client` (network) and `cache` (filesystem) — exactly like
    osv_enrich delegates to OSVClient. The module itself performs no I/O.
  - No knowledge of web/, cli/, argparse, SQLite, or CSV.
  - No bot-pattern table: the GitHub client tags each blame range with `is_bot`
    using ATTRIBUTION_BOT_PATTERNS from config. We just carry the flag through.
"""

import re
from typing import Callable, TypedDict

from dkatchr.clients.github import GitHubClient
from dkatchr.logger import log
from dkatchr.storage.attribution_cache import AttributionCache


# ---------------------------------------------------------------------------
# Result shape
# ---------------------------------------------------------------------------

class AttributionResult(TypedDict):
    commit_sha:     str | None
    commit_message: str | None
    commit_date:    str | None
    author_name:    str | None
    author_email:   str | None
    author_handle:  str | None
    is_bot:         bool


def empty_attribution() -> AttributionResult:
    """The 'no attribution' result — every field null, is_bot False.

    Used whenever the package line can't be found, the blame has no covering
    range, or a manifest fetch fails. Never means '0%'-style data; it means
    'unknown', and the UI renders it as "Unknown".
    """
    return {
        "commit_sha":     None,
        "commit_message": None,
        "commit_date":    None,
        "author_name":    None,
        "author_email":   None,
        "author_handle":  None,
        "is_bot":         False,
    }


# ---------------------------------------------------------------------------
# Package → line resolution (pure)
# ---------------------------------------------------------------------------

# Inventory ecosystem labels (parsers/__init__.ECOSYSTEM_NAME_FIELD) → the
# matching strategy below. Accepts either the canonical label ("crates.io",
# "Packagist") or the lowercase short name a caller might pass ("cargo").
_ECO_KEY: dict[str, str] = {
    "npm":       "npm",
    "rubygems":  "rubygems",
    "maven":     "maven",
    "nuget":     "nuget",
    "pypi":      "pypi",
    "go":        "go",
    "crates.io": "cargo",
    "cargo":     "cargo",
    "packagist": "packagist",
    "composer":  "packagist",
}


def _norm_pypi(name: str) -> str:
    """PEP 503 normalization: lowercase, collapse runs of -_. to a single -."""
    return re.sub(r"[-_.]+", "-", (name or "").strip()).lower()


def _find_quoted_key(lines: list[str], pkg: str, *, case_insensitive: bool = False) -> int | None:
    """First 1-indexed line containing the package name as a quoted JSON key."""
    target = f'"{pkg}"'
    if case_insensitive:
        target = target.lower()
        for i, line in enumerate(lines, 1):
            if target in line.lower():
                return i
        return None
    for i, line in enumerate(lines, 1):
        if target in line:
            return i
    return None


def _advance_to_version(lines: list[str], header_1indexed: int,
                        version_re: "re.Pattern", max_scan: int = 40) -> int | None:
    """From the line AFTER a stanza header, return the 1-indexed line that
    records the resolved version, stopping at a blank line / next stanza.

    Lockfile entries pin the version on a line INSIDE the entry block
    (`  version "0.8.5"` / `"version": "0.8.5"`), not on the key line. Blaming
    that inner line attributes to whoever last bumped the version — which is the
    meaningful "introduced/last-touched" author — rather than to whoever first
    added the dependency key. Returns None if no version line is found nearby
    (caller falls back to the header line).
    """
    start = header_1indexed  # lines[start] (0-indexed) is the line after the header
    for j in range(start, min(len(lines), start + max_scan)):
        line = lines[j]
        if line.strip() == "":
            break
        if version_re.search(line):
            return j + 1
    return None


def _find_npm(lines: list[str], pkg: str) -> int | None:
    # npm ships four manifest shapes and they declare a package four different
    # ways. The quoted-JSON-key form only covers package.json / package-lock.json;
    # yarn.lock and pnpm-lock.yaml use unquoted `pkg@range:` headers, so a
    # transitive-only dep (e.g. shelljs, never present in package.json) would
    # otherwise resolve to "Unknown". Try each shape in order; for lockfiles
    # where the version sits on a separate line, advance to it (see
    # _advance_to_version) so blame reflects the version bump.
    esc = re.escape(pkg)

    # 1. package.json: "pkg": "^1.2.3"  (value is a string on the same line)
    pkg_json = re.compile(r'"' + esc + r'"\s*:\s*"')
    for i, line in enumerate(lines, 1):
        if pkg_json.search(line):
            return i

    # 2. package-lock.json: "pkg": {  or  "node_modules/pkg": {  (incl. nested
    #    node_modules paths). Advance into the object to its "version": line.
    lock_key = re.compile(r'"(?:[^"]*/)?' + esc + r'"\s*:\s*\{')
    lock_ver = re.compile(r'"version"\s*:\s*"')
    for i, line in enumerate(lines, 1):
        if lock_key.search(line):
            return _advance_to_version(lines, i, lock_ver) or i

    # 3. yarn.lock (classic + Berry): stanza header ending in ':', e.g.
    #    shelljs@^0.8.5:  /  "shelljs@^0.8.4", "shelljs@^0.8.5":  /  "shelljs@npm:^0.8.5":
    #    Then advance to the inner version line (classic: `version "x"`,
    #    Berry: `version: x`).
    yarn_hdr = re.compile(r'(?:^|,)\s*"?' + esc + r'@')
    yarn_ver = re.compile(r"^\s+version[:\s]")
    for i, line in enumerate(lines, 1):
        if line.rstrip().endswith(":") and yarn_hdr.search(line):
            return _advance_to_version(lines, i, yarn_ver) or i

    # 4. pnpm-lock.yaml package keys — the version is IN the key itself, so the
    #    header line is the right blame target:
    #    v5 `/pkg/1.2.3:`  v6 `/pkg@1.2.3:`  (leading-slash, line-start)
    pnpm_path = re.compile(r"^\s*/" + esc + r"[/@]")
    for i, line in enumerate(lines, 1):
        if line.rstrip().endswith(":") and pnpm_path.search(line):
            return i
    #    v9 packages section (no leading slash): `  pkg@1.2.3:`
    pnpm_v9 = re.compile(r'^\s+"?' + esc + r"@")
    for i, line in enumerate(lines, 1):
        if line.rstrip().endswith(":") and pnpm_v9.search(line):
            return i
    #    pnpm importers bare key: `  pkg:` (specifier/version on following lines)
    pnpm_bare = re.compile(r'^\s+"?' + esc + r'"?:\s*$')
    for i, line in enumerate(lines, 1):
        if pnpm_bare.match(line):
            return i

    return None


def _find_packagist(lines: list[str], pkg: str) -> int | None:
    # composer.json/lock keys are "vendor/name". Composer treats names
    # case-insensitively, so fall back to a case-insensitive scan.
    return _find_quoted_key(lines, pkg) or _find_quoted_key(lines, pkg, case_insensitive=True)


def _find_pypi(lines: list[str], pkg: str) -> int | None:
    npkg = _norm_pypi(pkg)
    # requirements.txt style: leading name token, then ==/>=/~=/extras/markers.
    for i, line in enumerate(lines, 1):
        s = line.split("#", 1)[0].strip()
        if not s or s.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)", s)
        if m and _norm_pypi(m.group(1)) == npkg:
            return i
    # lockfile style (poetry.lock / Pipfile.lock): name = "x" or "x" key.
    for i, line in enumerate(lines, 1):
        m = re.match(r'\s*name\s*=\s*"([^"]+)"', line)
        if m and _norm_pypi(m.group(1)) == npkg:
            return i
    return _find_quoted_key(lines, pkg, case_insensitive=True)


def _find_rubygems(lines: list[str], pkg: str) -> int | None:
    esc = re.escape(pkg)
    # Gemfile: gem 'name' / gem "name"
    gemfile = re.compile(r"""^\s*gem\s+['"]""" + esc + r"""['"]""")
    for i, line in enumerate(lines, 1):
        if gemfile.match(line):
            return i
    # Gemfile.lock specs section: "    name (1.2.3)"
    lockline = re.compile(r"^\s+" + esc + r"\s*\(")
    for i, line in enumerate(lines, 1):
        if lockline.match(line):
            return i
    return None


def _find_go(lines: list[str], pkg: str) -> int | None:
    esc = re.escape(pkg)
    # go.mod (require <path> v..) or go.sum (<path> v.. h1:..) — path at line
    # start, optionally prefixed by "require ".
    pat = re.compile(r"^\s*(require\s+)?" + esc + r"(\s|$)")
    for i, line in enumerate(lines, 1):
        if pat.match(line):
            return i
    for i, line in enumerate(lines, 1):
        if pkg in line:  # fallback: substring (covers inline require lists)
            return i
    return None


def _find_cargo(lines: list[str], pkg: str) -> int | None:
    esc = re.escape(pkg)
    # Cargo.lock: name = "pkg"
    lockname = re.compile(r'^\s*name\s*=\s*"' + esc + r'"\s*$')
    for i, line in enumerate(lines, 1):
        if lockname.match(line):
            return i
    # Cargo.toml: pkg = "..", pkg.version = "..", or [dependencies.pkg]
    tomldep = re.compile(r"^\s*" + esc + r"\s*[=.]")
    tomltbl = re.compile(r"^\s*\[[^\]]*dependencies\.\s*" + esc + r"\s*\]")
    for i, line in enumerate(lines, 1):
        if tomldep.match(line) or tomltbl.match(line):
            return i
    return None


def _find_maven(lines: list[str], pkg: str) -> int | None:
    # Inventory package is "groupId:artifactId"; the manifest line we want is
    # <artifactId>artifactId</artifactId>. groupId appears in URLs/licenses
    # everywhere, so we anchor on the artifactId tag only.
    artifact = pkg.split(":")[-1].strip()
    if not artifact:
        return None
    pat = re.compile(r"<artifactId>\s*" + re.escape(artifact) + r"\s*</artifactId>")
    for i, line in enumerate(lines, 1):
        if pat.search(line):
            return i
    # gradle.lockfile: "group:artifact:version=..." — match the full coordinate.
    for i, line in enumerate(lines, 1):
        if pkg in line:
            return i
    return None


def _find_nuget(lines: list[str], pkg: str) -> int | None:
    esc = re.escape(pkg)
    # csproj PackageReference Include="x" / packages.config id="x" (case-insens).
    pat = re.compile(r'(?:Include|id)\s*=\s*"' + esc + r'"', re.IGNORECASE)
    for i, line in enumerate(lines, 1):
        if pat.search(line):
            return i
    # packages.lock.json: "x": { ... } — quoted key, case-insensitive.
    return _find_quoted_key(lines, pkg, case_insensitive=True)


_ECO_FINDERS: dict[str, Callable[[list[str], str], int | None]] = {
    "npm":       _find_npm,
    "rubygems":  _find_rubygems,
    "maven":     _find_maven,
    "nuget":     _find_nuget,
    "pypi":      _find_pypi,
    "go":        _find_go,
    "cargo":     _find_cargo,
    "packagist": _find_packagist,
}


def find_package_line(manifest_content: str, ecosystem: str, package_name: str) -> int | None:
    """1-indexed line where `package_name` appears in `manifest_content`.

    Dispatches on `ecosystem` (accepts the canonical inventory label like
    "crates.io"/"Packagist" or a short alias like "cargo"/"composer"). Returns
    None if the package isn't found or the ecosystem is unknown. NEVER raises —
    a malformed manifest just yields None (→ empty AttributionResult).
    """
    if not manifest_content or not package_name:
        return None
    key = _ECO_KEY.get((ecosystem or "").strip().lower())
    if key is None:
        return None
    finder = _ECO_FINDERS.get(key)
    if finder is None:
        return None
    try:
        lines = manifest_content.splitlines()
        return finder(lines, package_name)
    except Exception:
        return None


def resolve_attribution(blame_ranges: list[dict], line_number: int) -> dict | None:
    """Return the blame range covering `line_number` (start_line ≤ n ≤ end_line).

    Returns the range's full dict, or None when no range covers the line (or the
    blame is empty / malformed). Never raises.
    """
    if not blame_ranges or line_number is None:
        return None
    for rng in blame_ranges:
        try:
            start = rng.get("start_line")
            end = rng.get("end_line")
            if start is None or end is None:
                continue
            if int(start) <= line_number <= int(end):
                return rng
        except (TypeError, ValueError):
            continue
    return None


def _clean_message(msg: str | None) -> str | None:
    """First line of a commit message, whitespace-collapsed, capped at 200 chars."""
    if not msg:
        return None
    first = msg.splitlines()[0].strip() if msg.strip() else ""
    first = " ".join(first.split())
    return first[:200] or None


def _result_from_range(rng: dict | None) -> AttributionResult:
    """Build an AttributionResult from a blame range dict (or empty if None)."""
    if not rng:
        return empty_attribution()
    return {
        "commit_sha":     rng.get("sha"),
        "commit_message": _clean_message(rng.get("message")),
        "commit_date":    rng.get("date"),
        "author_name":    rng.get("author_name"),
        "author_email":   rng.get("author_email"),
        "author_handle":  rng.get("author_handle"),
        "is_bot":         bool(rng.get("is_bot")),
    }


# ---------------------------------------------------------------------------
# Row field accessors — inventory rows (file/repo) and CSV rows (file/repo)
# both work; we tolerate either key name so the same core serves both edges.
# ---------------------------------------------------------------------------

def _row_repo(row: dict) -> str | None:
    return row.get("repo_full_name") or row.get("repo")


def _row_path(row: dict) -> str | None:
    return row.get("manifest_path") or row.get("file")


# ---------------------------------------------------------------------------
# Orchestration — the osv_enrich() analogue
# ---------------------------------------------------------------------------

def _emit(on_progress: Callable[[dict], None] | None, payload: dict) -> None:
    """Fire a progress callback, swallowing any error (progress must never break work)."""
    if on_progress is None:
        return
    try:
        on_progress(payload)
    except Exception:
        pass


def enrich_attribution(
    inventory_rows: list[dict],
    github_client: GitHubClient,
    cache: AttributionCache,
    on_progress: Callable[[dict], None] | None = None,
) -> list[dict]:
    """Attach an AttributionResult to every input row. Returns a NEW list.

    Workflow (the attribution analogue of osv_enrich):
      1. Group rows by unique manifest (repo_full_name, manifest_path, sha) so we
         make at most ONE pair of API calls per manifest file, no matter how many
         packages or findings reference it. This dedup is non-negotiable.
      2. Per manifest: cache.read() first; on a hit, skip BOTH get_file_contents
         and get_file_blame. On a miss, fetch the file text then blame it, and
         write both to the cache.
      3. Per row: find_package_line() → resolve_attribution() → attach the
         result under row["attribution"].

    Failure isolation: a manifest whose content fetch fails (404, network, etc)
    logs and attaches empty attribution to its rows, then continues — one bad
    manifest never aborts the pass. Input rows are not mutated (each output row
    is a shallow copy).

    Required row keys: repo_full_name|repo, manifest_path|file, sha, ecosystem,
    package. Rows missing repo/path/sha get an empty AttributionResult.
    """
    enriched = [dict(r) for r in inventory_rows]

    # 1. Group row indices by unique manifest file.
    groups: dict[tuple, list[int]] = {}
    for idx, row in enumerate(enriched):
        key = (_row_repo(row), _row_path(row), row.get("sha"))
        groups.setdefault(key, []).append(idx)

    total = len(groups)
    log(f"[+] Attribution: {total} unique manifest file(s) across {len(enriched)} finding(s)")

    n = 0
    attributed = 0
    for (repo, path, sha), idxs in groups.items():
        n += 1
        _emit(on_progress, {
            "phase":   "attribution_progress",
            "current": n,
            "total":   total,
            "repo":    repo,
            "path":    path,
        })

        # Can't attribute without a full (repo, path, sha) triple.
        if not repo or not path or not sha or "/" not in repo:
            for i in idxs:
                enriched[i]["attribution"] = empty_attribution()
            continue

        owner, name = repo.split("/", 1)
        try:
            content, ranges = cache.read(repo, path, sha)
            if content is None:
                content = github_client.get_file_contents(owner, name, path, sha)
                ranges = github_client.get_file_blame(owner, name, path, sha)
                cache.write(repo, path, sha, content, ranges)
        except Exception as e:
            log(f"[!] Attribution: {repo}:{path} failed: {e} — leaving these findings unattributed")
            for i in idxs:
                enriched[i]["attribution"] = empty_attribution()
            continue

        for i in idxs:
            row = enriched[i]
            line = find_package_line(content, row.get("ecosystem", ""), row.get("package", ""))
            rng = resolve_attribution(ranges, line)
            result = _result_from_range(rng)
            enriched[i]["attribution"] = result
            if result["commit_sha"]:
                attributed += 1

    _emit(on_progress, {"phase": "attribution_done", "manifests": total, "attributed": attributed})
    log(f"[+] Attribution complete: {total} manifest(s) queried, {attributed} finding(s) attributed")
    return enriched
