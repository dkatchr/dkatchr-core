<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="assets/logo-light.png">
    <img alt="dKatchr" src="assets/logo-light.png" width="360">
  </picture>
</p>

# dKatchr

Multi-ecosystem Software Composition Analysis (SCA) scanner for GitHub. Point it at one or more GitHub orgs (or a specific list of repos), and it discovers every dependency manifest across 8 package ecosystems, enriches findings against multiple vulnerability intelligence sources, and flags supply-chain risks that plain CVE scanning misses - dependency confusion, typosquatting, and unauthenticated internal-name exposure.

No CI pipeline changes, no agents, no per-repo setup. Connect a GitHub token, point at an org, get a CSV.

## Why this exists

Most free SCA tools stop at "does this version have a CVE." dKatchr adds the layers that actually decide whether you should care:

- **Exploitability, not just severity** - CVSS alone tells you how bad a bug *could* be. EPSS tells you the probability it's *actually* being exploited. CISA KEV tells you it already has been. dKatchr surfaces all three per finding, plus cross-references against ExploitDB and Metasploit for known public exploit code.
- **Supply-chain attack surface, not just known CVEs** - dependency confusion (an internal package name that also exists, unclaimed, on the public registry) and typosquatting (a close-name lookalike of a popular package) are both live attack vectors with no CVE assigned. dKatchr detects both.
- **Reachability** - a vulnerable package sitting unused in a lockfile is a different risk than one your code actually imports. Level 1 reachability checks import-presence across the source tree before you spend time triaging.
- **Attribution** - every finding can be traced back to the commit and author who introduced that dependency line, so "who do I ask about this" isn't a separate investigation.

## Features

- **8 package ecosystems**: npm, PyPI, Maven (incl. Gradle lockfiles), RubyGems, Go, NuGet, crates.io, Packagist (PHP/Composer) - see the full manifest table below.
- **OSV.dev enrichment** - batch CVE/advisory lookups against Google's open-source vulnerability database, with a two-tier cache to keep re-scans fast.
- **CISA KEV overlay** - flags findings with a documented history of active exploitation in the wild.
- **EPSS scoring** - attaches the daily-updated exploit-probability percentage from FIRST.org to every CVE-bearing finding.
- **Exploit intelligence** - cross-references ExploitDB and Metasploit module coverage per CVE, surfaced as a single "Has Exploit" signal.
- **Custom rules engine** - define your own package/version bans (exact match or regex) independent of OSV, with an optional reason code (`INTERNAL_VULNERABLE`, `ORG_BANNED`, `LICENSE_ISSUE`, `PRE_CVE`) for internal tracking.
- **Dependency confusion detection** - flags internal-looking package names (path/git/workspace dependencies, declared internal namespace patterns, or cross-repo mismatches) that also resolve on a public registry. On by default.
- **Typosquatting detection** - Damerau-Levenshtein distance against per-ecosystem top-package lists, gated by a mandatory registry-metadata check (recent creation / low downloads) to suppress false positives. Opt-in (fetches large feed data).
- **Level 1 reachability** - Aho-Corasick grep across a streamed repo tarball for import statements and ecosystem-idiomatic usage patterns (e.g. Bundler autoload conventions, `Rails::`, `JSON.parse`), so you know a flagged package is actually imported somewhere.
- **Commit attribution ("Introduced By")** - one git-blame call per unique manifest file (GraphQL, cached by branch SHA) resolves each finding to the commit and author that introduced it.
- **SHA-keyed caching everywhere** - inventory, reachability, and attribution are all cached per repo branch SHA, so re-scanning an unchanged branch costs nothing.
- **Progress streaming** - every long-running phase (tarball download, per-repo scanning, confusion/typosquat lookups) reports structured progress, not silence.
- **Parallel, fault-isolated scanning** - one malformed manifest or one dead repo never aborts the run; it's logged, marked, and the scan continues.

## Supported manifests

| Ecosystem | Files |
|---|---|
| npm | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| PyPI | `requirements.txt`, `Pipfile.lock`, `poetry.lock` |
| Maven | `pom.xml`, `gradle.lockfile` |
| RubyGems | `Gemfile`, `Gemfile.lock` |
| Go | `go.mod`, `go.sum` |
| NuGet | `packages.config`, `packages.lock.json`, `*.csproj`, `*.fsproj`, `*.vbproj` |
| crates.io | `Cargo.lock` |
| Packagist (PHP) | `composer.json`, `composer.lock` |

## Install

Requires Python 3.10+.

```bash
pip install dkatchr
```

Or, if you prefer CLI tools installed in their own isolated environment (recommended, avoids clashing with whatever's in your project virtualenvs):

```bash
pipx install dkatchr
```

### Install from source (latest, unreleased changes)

```bash
pip install git+https://github.com/dkatchr/dkatchr-core.git
```

Or clone and install locally for development:

```bash
git clone https://github.com/dkatchr/dkatchr-core.git
cd dkatchr-core
python3 -m venv venv && source venv/bin/activate
pip install -e .
```

`pyahocorasick` and `rapidfuzz` are C-extension dependencies. PyPI ships manylinux wheels for common platforms, so most installs get a prebuilt binary - if pip builds from source, you'll need a C toolchain (`gcc`/`clang`).

## Quick start

1. Create a GitHub Personal Access Token with read access to the repos/orgs you want to scan.
2. Copy the example env file and fill it in:

```bash
cp dkatchr/.env.example .env
# edit .env, set GITHUB_TOKEN=ghp_...
```

3. Run a scan:

```bash
dkatchr -o results.csv --orgs my-github-org --osv
```

(`python -m dkatchr` works identically if you prefer that form.)

That scans every repo in `my-github-org`, extracts all dependency manifests, enriches every finding against OSV + KEV + EPSS + exploit intel, and writes the results to `results.csv`. Dependency confusion detection runs by default; nothing else extra needs to be turned on to get a meaningful first scan.

### Common variations

```bash
# Scan specific repos instead of a whole org
python -m dkatchr -o results.csv --repos my-org/repo-one my-org/repo-two --osv

# See what would be scanned (repo count, cache hit/miss estimate) without scanning
python -m dkatchr -o results.csv --orgs my-github-org --dry-run

# Add reachability + commit attribution
python -m dkatchr -o results.csv --orgs my-github-org --osv --reachability --attribution

# Supply your own internal namespace patterns for confusion detection
python -m dkatchr -o results.csv --orgs my-github-org --internal-patterns patterns.json

# Turn on typosquat detection (off by default - fetches per-ecosystem top-package feeds)
python -m dkatchr -o results.csv --orgs my-github-org --typosquat

# Use custom package/version rules instead of (or alongside) OSV
python -m dkatchr -o results.csv --orgs my-github-org -c rules.json
```

Run `python -m dkatchr --help` for the full flag reference - every flag is self-documented, including defaults and rate-limit behavior.

### Custom rules format

```json
{
  "lodash_rule": {
    "description": "Track lodash, flag versions below 4.17.21",
    "reason": "INTERNAL_VULNERABLE",
    "npm_names": ["lodash"],
    "vulnerable_versions": ["4.17.20", "4.17.19"],
    "vulnerable_version_patterns": ["^[123]\\."]
  }
}
```

Supported name fields: `npm_names`, `pypi_names`, `maven_names`, `rubygems_names`, `go_names`, `nuget_names`, `cargo_names`, `composer_names`.

### Internal namespace patterns (for confusion detection)

```json
[
  { "ecosystem": "npm", "pattern": "@my-org/*" },
  { "ecosystem": "PyPI", "pattern": "myorg-*" }
]
```

## Configuration

All tunables (rate limits, cache TTLs, worker counts, reachability limits) are environment variables - see `dkatchr/.env.example` for the full list with defaults and explanations. Nothing is hardcoded that you'd need to patch the source to change.

Key ones to know:

| Variable | Purpose |
|---|---|
| `GITHUB_TOKEN` | Required for anything beyond a handful of unauthenticated requests. |
| `DKATCHR_GITHUB_RPS` / `DKATCHR_GITHUB_BURST` | GitHub API rate cap (default tuned for the 5,000 req/hr authenticated budget). |
| `DKATCHR_OSV_RPS` / `DKATCHR_OSV_BURST` | OSV.dev API rate cap. |
| `DKATCHR_WORKERS` | Per-repo parallelism. |
| `DKATCHR_OSV_TTL` / `DKATCHR_KEV_TTL` | Cache freshness windows for the respective data sources. |

## Caching

Every external data source (OSV, KEV, EPSS, ExploitDB, Metasploit, registry metadata, top-package feeds, per-repo inventory) is cached to disk under `--cache-dir` (default `./data/cache`). If you suspect stale data or change parser logic locally:

```bash
# Force a full re-scan of everything
rm -rf data/cache/

# Force just a fresh CVE dataset
rm -rf data/cache/osv data/cache/kev data/cache/epss

# Force a fresh registry check for confusion/typosquat candidates
rm -rf data/cache/registry_meta/
```

## Architecture

```
dkatchr/
├── cli/        # argparse glue + orchestration (ThreadPoolExecutor for per-repo parallelism)
├── clients/    # one client per external system: GitHub, OSV, KEV, EPSS, ExploitDB,
│               # Metasploit, registry metadata, top-package feeds - each owns its own
│               # rate limiter and cache
├── core/       # pure logic, no I/O: scanning orchestration, rule matching, confusion
│               # detection, typosquat detection, reachability grep, attribution resolution
├── parsers/    # one module per ecosystem, each returning a plain list of dependency dicts
├── output/     # CSV schema + writer
└── storage/    # per-repo SHA-keyed JSON caches (inventory, reachability, attribution)
```

`core/` has zero knowledge of argparse, CSV, or threading - it's the part safe to reuse if you want to embed dKatchr's detection logic in something other than the bundled CLI.

## Known limitations

- No formal automated test suite yet (contributions welcome - `dkatchr/core/` and `dkatchr/parsers/` are pure functions with no I/O, the natural place to start).
- Reachability is import-presence + usage-pattern detection, not full call-graph analysis - it won't catch reflection-based or dynamically-constructed import paths.
- Typosquat/confusion registry checks cover npm, PyPI, crates.io, RubyGems, and Packagist. Go, Maven, and NuGet aren't covered yet (different naming/ownership models per ecosystem).
- PyPI download counts are unavailable upstream (the JSON API's count field is deprecated), so the typosquat metadata gate falls back to creation-date-only on PyPI.

## Contributing

Issues and PRs welcome. If you're adding a new ecosystem, see the docstring at the top of `dkatchr/parsers/__init__.py` for the four-step registration process. If you're touching `core/`, keep it pure - no argparse, no direct file I/O beyond what's passed in, no threading assumptions; parallelism belongs in `cli/`.

## License

MIT - see [LICENSE](LICENSE).
