"""All module-level constants in one place. Edit here, not scattered."""

import os

# ---- GitHub API ------------------------------------------------------------
GITHUB_API_BASE = "https://api.github.com"
# For GitHub Enterprise: GITHUB_API_BASE = "https://github.yourcompany.com/api/v3"

# GraphQL v4 endpoint — used by the attribution pass (git blame). REST has no
# blame endpoint, so commit-line attribution requires GraphQL. For GitHub
# Enterprise this is "https://github.yourcompany.com/api/graphql".
GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"

# Default per-page size for GitHub list endpoints (max allowed = 100).
GITHUB_PAGE_SIZE = 100

# ---- Attribution ("Introduced By") -----------------------------------------
# Optional pass that attributes each vulnerable dependency to the commit author
# who last touched that package's line in its manifest. See
# dkatchr/core/attribution.py + dkatchr/storage/attribution_cache.py.
#
# Substrings (case-insensitive) on a commit's author handle/name that mark the
# author as an automated bot rather than a human. Used by GitHubClient to set
# the `is_bot` flag on blame ranges so the UI can badge bot-introduced deps.
# Any handle ending in "[bot]" is also treated as a bot regardless of this list.
ATTRIBUTION_BOT_PATTERNS: list[str] = [
    "dependabot",
    "renovate",
    "snyk-bot",
    "github-actions",
]

# Bumped when the on-disk attribution cache value shape changes. Old files that
# don't match are silently treated as misses and rebuilt (see attribution_cache).
ATTRIBUTION_CACHE_SCHEMA: int = 1

# ---- Cache -----------------------------------------------------------------
# Bumped when the inventory schema or parser semantics change in a way that
# should invalidate existing on-disk caches.
# v3: dedupe_inventory() now collapses on (ecosystem, package, version) instead
#     of (file, ...), so a dep pinned in both go.mod (declared) and go.sum
#     (resolved) is inventoried once, not twice.
# v4: parsers capture dependency `origin` (registry|path|git|workspace|url) for
#     the dependency-confusion pass; requirements.txt now keeps git+/URL/-e
#     lines it used to skip, and Gemfile.lock is section-aware (GEM/GIT/PATH).
# v5: lockfile parsers capture an optional `resolved_url` (the registry/source
#     URL the lockfile records) for the Dependency Confusion Exposure audit
#     check; poetry.lock is now [package.source]-aware (git/directory/url
#     sources get a non-registry origin, legacy sources carry their index URL,
#     and an ABSENT source materializes the implicit default-PyPI index URL).
#     ALSO fixes a pre-existing pnpm v9 misparse: scoped keys are YAML-quoted
#     ('@scope/pkg@1.0.0':) because '@' is a reserved indicator, and the v9
#     regex now strips the quote — every scoped dep in a pnpm v9 lockfile was
#     previously dropped from inventory (live scan AND historical walk).
# v6: lockfile parsers attach `depends_on` (dependency edges) for
#     dependency-graph reachability; ALSO fixes pnpm v5/v6 lockfiles, whose
#     2-space-indented keys never matched (they parsed to zero rows), keys with
#     a peer suffix "(debug@4.3.4)", and truncated git-URL versions.
# v7: Gemfile.lock platform suffixes stripped from versions
#     ("1.18.10-arm64-darwin" -> "1.18.10"); dedupe marks a declared row
#     "resolved" when a lockfile pins the same version; >1 MB manifests are
#     fetched via the Git blobs API (they were cached as empty before).
# v8: new manifests (requirements*.txt variants, setup.py, setup.cfg,
#     pyproject.toml, *.deps.json), Maven poms resolved per project (parent
#     properties + dependencyManagement), and a `scope` ("dev") on rows that a
#     manifest marks development/test-only.
# v9: transitive rows (version_source "transitive") for lockfile-less
#     manifests, resolved via deps.dev / the NuGet registry.
# v10: transitive rows and "already pinned" decided per directory (monorepo
#      sub-projects), `pinned` on requirements `==` rows.
# v11: dev scope propagated through yarn.lock / pnpm-lock / Gemfile.lock edges;
#      Gemfile.lock DEPENDENCIES rows flagged `direct`.
CACHE_SCHEMA = 13   # v13: runtime rows skip vendored dirs, carry spec precision

# Bundler group names that mean "not installed in production" — the
# conventional names (`bundle config set without development test`), not a
# per-package map. A gem counts as dev-only when ALL its groups are in here.
GEMFILE_DEV_GROUPS = frozenset({"development", "test", "dev", "ci", "lint", "rubocop"})

# ---- Manifest fetching -----------------------------------------------------
# Manifests are fetched one contents-API call each. A monorepo with hundreds of
# modules (486 pom.xml, 339 .csproj) burns minutes and most of the 5,000/h API
# budget that way, so above this many manifests the scan reads them all out of
# ONE repo tarball instead — when the repo is small enough (GitHub's `size`,
# KB) that downloading it is cheaper. Anything the tarball does not deliver
# falls back to per-file calls.
SCAN_TARBALL_MIN_MANIFESTS = int(os.environ.get("DKATCHR_SCAN_TARBALL_MIN_MANIFESTS", "30"))
SCAN_TARBALL_MAX_REPO_KB = int(os.environ.get("DKATCHR_SCAN_TARBALL_MAX_REPO_KB", str(2 * 1024 * 1024)))
# Per-member read cap while extracting manifests from the tarball.
SCAN_TARBALL_MAX_MANIFEST_BYTES = 100 * 1024 * 1024

# Reachability cache (per repo + SHA) stores the matched import patterns, so a
# change to pattern generation must invalidate it. v2: Go subpackage-import
# patterns ('"module/').
REACHABILITY_CACHE_SCHEMA = 3   # v3: executed-program (command) patterns

# Cache directory — anchored to CWD by default. Override via --cache-dir.
# Lives under data/cache to match the web layer (web/settings.py CACHE_DIR) and
# the documented convention ("caches under data/cache/"). Was ".cache" before the
# migration to data/; a stray .cache/ next to data/ means something is still
# falling through to a pre-migration default — that's a bug, not a second cache.
DEFAULT_CACHE_DIR = os.path.abspath(os.path.join(os.getcwd(), "data", "cache"))

# ---- OSV.dev ---------------------------------------------------------------
OSV_API_BASE     = "https://api.osv.dev/v1"
OSV_BATCH_SIZE   = 1000
OSV_DEFAULT_TTL  = 24 * 3600  # seconds — TTL for (eco, pkg, ver) → IDs map

# ---- CISA KEV (Known Exploited Vulnerabilities) ----------------------------
KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_DEFAULT_TTL = 24 * 3600  # seconds — how long to cache the KEV catalog

# ---- Exploit-availability signals ("Has Exploit") --------------------------
# Two public-exploit catalogs, both cross-referenced by CVE alongside KEV to
# answer "does a working public exploit exist for this finding?". Each is a
# single bulk file GET wrapped in a TTL'd file cache (same role as KEV), never
# blocking a scan — see dkatchr/clients/exploitdb.py + metasploit.py. OSV itself
# carries no exploit-availability data (no EXPLOIT reference type), so these are
# the only free path to the signal.
#
# ExploitDB: the live GitLab repo. The legacy github.com/offensive-security
# mirror was ARCHIVED Nov 2022 and is frozen — do NOT use it. NOTE: the CSV has
# no dedicated CVE column; CVE IDs live in the semicolon-separated `codes` field
# (e.g. "CVE-2009-3699;OSVDB-58726"), so the client regex-extracts CVE-\d+-\d+
# tokens from `codes` (verified against the live ~10MB file_exploits.csv).
EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
EXPLOITDB_DEFAULT_TTL = 24 * 3600  # seconds — how long to cache the ExploitDB CSV

# Metasploit: a community-maintained daily export of every CVE that has a
# Metasploit module (the rapid7/metasploit-framework tree has no machine-readable
# CVE index). NOTE: the `cves` key is a DICT keyed by CVE id (not an array), so
# the client takes its keys (verified against the live ~5MB metasploit_cves.json).
METASPLOIT_CVES_URL = "https://raw.githubusercontent.com/dogasantos/msfcve/main/metasploit_cves.json"
METASPLOIT_DEFAULT_TTL = 24 * 3600  # seconds — how long to cache the Metasploit CVE list

# ---- NVD (National Vulnerability Database) ---------------------------------
# CVE → CWE lookup used by the credential-risk classification pass when OSV
# carries no usable CWE data. See dkatchr/clients/nvd.py +
# web/services/classification_service.py.
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD's documented rolling-window budget is 5 requests / 30s without an API key
# and 50 / 30s with one. We sit just under each. NOTE: these are *per-30-seconds*
# figures — NVDClient converts them to the per-second rate TokenBucket expects
# (value / 30.0), so don't pass them to TokenBucket raw.
NVD_RATE_NO_KEY   = 4    # requests per 30s (NVD limit is 5, stay under)
NVD_RATE_WITH_KEY = 45   # requests per 30s (NVD limit is 50, stay under)

# ---- Credential-risk CVE classification ------------------------------------
# CWE IDs whose presence on a finding means the vulnerability class can expose
# credentials/secrets — so the user should ROTATE SECRETS, not just patch. This
# frozenset is the ONLY thing that sets is_credential_risk=1 for CWE-based
# classification; nothing outside this list qualifies. See
# web/services/classification_service.py.
CREDENTIAL_RISK_CWES = frozenset({
    # malicious / embedded code
    "CWE-506", "CWE-507", "CWE-509",
    # cleartext storage and transmission of credentials
    "CWE-312", "CWE-319", "CWE-256", "CWE-260", "CWE-522",
    # secrets leaking into logs, debug output, env vars
    "CWE-532", "CWE-215", "CWE-214",
    # credential management failures
    "CWE-255", "CWE-549",
    # sensitive info inserted into sent data (CWE-201 only — CWE-200 is too broad;
    # "Exposure of Sensitive Information" matches RCE, deserialization, and CSRF
    # vulns that have no direct credential exposure, causing false positives)
    "CWE-201",
})

# Subset of CREDENTIAL_RISK_CWES that indicate the package itself is malicious
# (embedded/trojan code). A match here additionally sets is_malicious=1.
MALICIOUS_CODE_CWES = frozenset({"CWE-506", "CWE-507", "CWE-509"})

# CWE placeholders NVD/OSV emit when no real weakness was assigned. Treated as
# "no usable CWE data" — discarded before matching so they never count as a
# resolved classification (they fall through to NVD enrichment / UNRESOLVED).
NVD_USELESS_CWES = frozenset({"NVD-CWE-noinfo", "NVD-CWE-Other"})

# Advisory-title phrases that mark the PACKAGE ITSELF as malware. A safety net
# for malware advisories that reach us as GHSA- ids (not MAL-) and whose CWE
# isn't in MALICIOUS_CODE_CWES — e.g. ctx (GHSA-4g82-3jcr-q52w, "Malware in
# ctx") carries only CWE-912 (Hidden Functionality), so neither the MAL- prefix
# nor the CWE check fires. Matched (case-insensitively, substring) against the
# OSV `summary` ONLY — the short advisory title, where GHSA uses a consistent
# "Malware in <pkg>" / "Malicious code in <pkg>" convention.
#
# Phrases are deliberately "in"-anchored ("malicious code in ", not bare
# "malicious code") so they match "the package IS the malware" titles without
# false-positiving on RCE advisories that merely describe an attack — e.g.
# "Babel ... when compiling specifically crafted malicious code" (a real GHSA
# title) must NOT be flagged. "trojan" is intentionally excluded for the same
# reason (it would catch the legitimate "Trojan Source" bidi advisory).
MALWARE_SUMMARY_MARKERS = frozenset({
    "malware in ",
    "malicious code in ",
    # "Malicious Package in <pkg>" (older npm advisories). The trailing " in "
    # keeps titles like "... Malicious Package Injection" (nltk) out.
    "malicious package in ",
})

# ---- Historical Exposure (supply-chain forensics) --------------------------
# Default look-back window, in days, for the deliberately-triggered "Deep Audit"
# that walks a manifest's full commit history checking every version ever
# resolved against the malicious-package signals. 730d (2 years) covers
# event-stream (2018), the XZ backdoor (2024), the Shai-Hulud npm worm (2025)
# and most other named incidents. This is ONLY the default — the audit-trigger
# UI offers 2y / 5y / full history and the backend takes lookback_days as a
# per-request parameter (see web/services/historical_exposure.py). The feature
# itself is a premium, web-only differentiator (all logic in web/services/);
# this constant lives here per the "all constants in config.py" rule, and is a
# pure value imported by the web layer under the stateless-value carve-out.
HISTORICAL_EXPOSURE_LOOKBACK_DAYS_DEFAULT = 730

# ---- Dependency Confusion Detection -----------------------------------------
# Live registry-metadata lookups ("does this internal-looking name exist on the
# PUBLIC registry?") for the confusion pass. One client, one seam:
# dkatchr/clients/registry_meta.py. Pure detection logic: dkatchr/core/confusion.py.
#
# Identifying User-Agent sent on EVERY registry-metadata request. crates.io's
# crawler policy REQUIRES an identifying UA (its rate limit is also a hard
# 1 req/s — see REGISTRY_META_RPS); the other registries just log it.
DKATCHR_USER_AGENT = os.environ.get(
    "DKATCHR_USER_AGENT",
    "dkatchr-sca/1.0 (dependency-confusion check; +https://github.com/dkatchr/dkatchr)",
)

# Registry metadata endpoints. `{package}` is substituted (URL-encoded where the
# name can contain '/': npm scopes, Packagist vendor/name). This is ENDPOINT
# config, not package knowledge — the "no static data maps" rule doesn't apply.
# Coverage v1 is npm/PyPI/crates.io/RubyGems/Packagist; Go, Maven and NuGet have
# different confusion models and are deferred (see CLAUDE.md Known limitations).
NPM_REGISTRY_META_URL   = "https://registry.npmjs.org/{package}"
NPM_DOWNLOADS_URL       = "https://api.npmjs.org/downloads/point/last-month/{package}"
PYPI_META_URL           = "https://pypi.org/pypi/{package}/json"
CRATESIO_META_URL       = "https://crates.io/api/v1/crates/{package}"
RUBYGEMS_META_URL       = "https://rubygems.org/api/v1/gems/{package}.json"
RUBYGEMS_VERSIONS_URL   = "https://rubygems.org/api/v1/versions/{package}.json"
PACKAGIST_META_URL      = "https://repo.packagist.org/p2/{package}.json"
PACKAGIST_DOWNLOADS_URL = "https://packagist.org/packages/{package}.json"

# Per-registry request rate caps (requests/second) for the metadata client.
# crates.io's published crawler policy is a HARD 1 req/s — do not raise it.
# The rest are conservative good-citizen defaults for anonymous API use.
REGISTRY_META_RPS: dict[str, float] = {
    "npm":       8.0,
    "PyPI":      8.0,
    "crates.io": 1.0,   # HARD limit per crates.io policy — never raise
    "RubyGems":  5.0,
    "Packagist": 5.0,
}
REGISTRY_META_TIMEOUT = 15  # seconds — per metadata HTTP request

# TTL'd file cache at {CACHE_DIR}/registry_meta/, keyed (ecosystem, name).
# Deliberately TTL'd like EPSS/KEV, NOT permanent like the NVD/OSV-verdict
# caches: a squatted package can appear tomorrow, and a 404 cached as
# exists=false can become a claimed name. 7 days default, env-tunable.
DEFAULT_REGISTRY_META_TTL = int(
    os.environ.get("DKATCHR_REGISTRY_META_TTL", str(7 * 24 * 3600))
)

# Suspicion-signal thresholds for the confusion pass (core/confusion.py). These
# annotate findings (rendered highlighted in the UI when exceeded) — they never
# gate whether a finding is emitted.
CONFUSION_RECENT_CREATION_DAYS   = 180    # public package created within N days → suspicious
CONFUSION_LOW_DOWNLOADS          = 1000   # fewer downloads than this → suspicious
CONFUSION_INFLATED_MAJOR_VERSION = 100    # major version ≥ N (classic 99.99.99 squat) → suspicious

# ---- Dependency Confusion Exposure (historical source-flip detection) ------
# Per-ecosystem hosts of the DEFAULT PUBLIC registry, matched against the
# `resolved_url` lockfiles record. A lockfile resolution whose URL host is NOT
# in its ecosystem's set (and isn't a path/git source) came from a PRIVATE /
# non-default source — the signal the historical confusion check keys on.
#
# This is PROTOCOL knowledge expressed as constants (which host each package
# manager's default registry lives on — same class of fact as
# MALWARE_SUMMARY_MARKERS or the *_META_URL endpoints above), NOT a forbidden
# domain-knowledge map about individual packages: it cannot rot per-package,
# only if a registry itself moves hosts.
#
# Entries containing "/" match host + path prefix (needed for crates.io's
# classic git index, which lives under github.com — host alone would misread
# every github-hosted private cargo index as public).
DEFAULT_PUBLIC_REGISTRY_HOSTS: dict[str, frozenset[str]] = {
    "npm":       frozenset({"registry.npmjs.org", "registry.yarnpkg.com"}),
    "PyPI":      frozenset({"pypi.org", "files.pythonhosted.org"}),
    "crates.io": frozenset({"index.crates.io", "static.crates.io",
                            "github.com/rust-lang/crates.io-index"}),
    "RubyGems":  frozenset({"rubygems.org", "index.rubygems.org"}),
    "Packagist": frozenset({"packagist.org", "repo.packagist.org"}),
}

# poetry.lock records the DEFAULT index by OMISSION — an absent [package.source]
# table means "resolved from pypi.org". The poetry parser materializes that
# implicit default as this explicit resolved_url so source timelines can see
# the PUBLIC side of a resolution flip (endpoint config, not package knowledge).
PYPI_DEFAULT_INDEX_URL = "https://pypi.org/simple"

# ---- Typosquatting Detection ------------------------------------------------
# Detects dependencies whose names closely resemble a TOP public package — the
# attacker registers "reqeusts" hoping someone typos "requests". A DIFFERENT
# attack from dependency confusion (there the squat resembles YOUR INTERNAL
# name; here it resembles a POPULAR public name). Open core, opt-in per scan.
# Detection logic: dkatchr/core/typosquat.py (pure); top-packages feed client:
# dkatchr/clients/top_packages.py (a NEW seam). The mandatory metadata gate
# REUSES the confusion pass's RegistryMetaClient — no second registry client.
#
# Top-packages feed endpoints, one per ecosystem. This is ENDPOINT config, not
# a static package-name map (the "no static data maps" rule) — the actual name
# lists are ALWAYS fetched from these sources at run time and cached, never
# vendored into the repo. Coverage matches RegistryMetaClient.SUPPORTED_ECOSYSTEMS
# (npm/PyPI/crates.io/RubyGems/Packagist): the metadata gate is mandatory and
# only those five can be gated. Go/Maven have no public download rankings; NuGet
# HAS a download-rankable search API but RegistryMetaClient can't gate NuGet, so
# it stays unsupported until that client gains NuGet (see CLAUDE.md).
#
# PyPI: hugovk/top-pypi-packages — the stable latest-release JSON on the repo's
#   main branch (~15k names, shape {"rows":[{"project","download_count"}]},
#   already download-ranked). Verified live.
TOP_PACKAGES_PYPI_URL = (
    "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json"
)
# crates.io: the official API, paginated by download rank. MUST go through the
#   crates.io TokenBucket (HARD 1 req/s) + DKATCHR_USER_AGENT, same policy as
#   registry_meta. {page} is substituted; per_page maxes at 100. Verified live.
TOP_PACKAGES_CRATES_URL = "https://crates.io/api/v1/crates?sort=downloads&per_page=100&page={page}"
# Packagist: the popular-packages explorer, paginated ({"packages":[{"name"}]},
#   vendor/name). Verified live.
TOP_PACKAGES_PACKAGIST_URL = "https://packagist.org/explore/popular.json?per_page=100&page={page}"
# RubyGems: the official "most downloaded" endpoint. Returns ONLY ~top 50
#   ([[gem_dict, count], ...]; the gem name is derived from full_name + number —
#   RubyGems omits a bare `name` here). NEAR-ZERO coverage by design; included
#   for completeness. Verified live.
TOP_PACKAGES_RUBYGEMS_URL = "https://rubygems.org/api/v1/downloads/all.json"
# npm: NO official ranking feed exists. We use the community-maintained
#   npm-high-impact package's download-ranked list (`topDownload`), fetched from
#   the jsDelivr CDN for the CURRENTLY-PUBLISHED version and freshness-gated via
#   the npm registry's publish timestamp (rejected if older than
#   TOP_PACKAGES_MAX_AGE_DAYS). {version} is substituted. Verified live.
TOP_PACKAGES_NPM_REGISTRY_URL = "https://registry.npmjs.org/npm-high-impact"
TOP_PACKAGES_NPM_DATA_URL = (
    "https://cdn.jsdelivr.net/npm/npm-high-impact@{version}/lib/top-download.js"
)

# How many top names to rank per ecosystem (the feed is truncated to this).
TOP_PACKAGES_COUNT = int(os.environ.get("DKATCHR_TOP_PACKAGES_COUNT", "5000"))
# Reject a community-maintained feed (npm) whose data is older than this — a
# stale ranking would compare against packages that are no longer "top" and miss
# ones that now are. Only the npm feed is freshness-gated (the others are
# first-party/official and refreshed server-side).
TOP_PACKAGES_MAX_AGE_DAYS = int(os.environ.get("DKATCHR_TOP_PACKAGES_MAX_AGE_DAYS", "90"))
# TTL'd file cache at {CACHE_DIR}/top_packages/ per ecosystem. Like registry_meta
# (NOT permanent): the top-N set shifts over time. 7 days default, env-tunable.
DEFAULT_TOP_PACKAGES_TTL = int(
    os.environ.get("DKATCHR_TOP_PACKAGES_TTL", str(7 * 24 * 3600))
)
TOP_PACKAGES_TIMEOUT = 60  # seconds — per feed HTTP request (some feeds are MBs)

# Length-scaled Damerau-Levenshtein thresholds for the typosquat pass
# (core/typosquat.py). Names shorter than MIN_NAME_LEN are never checked (too
# many legitimate short collisions); length MIN..(LONG-1) allow edit distance 1;
# LONG_NAME_LEN and above allow edit distance 2. Heuristic constants pending
# real-org tuning (see CLAUDE.md Known limitations).
TYPOSQUAT_MIN_NAME_LEN  = 5
TYPOSQUAT_LONG_NAME_LEN = 8

# ---- EPSS (Exploit Prediction Scoring System, FIRST.org) -------------------
# Daily-refreshed gzipped CSV mapping each CVE to a 0–1 probability of
# exploitation in the next 30 days. Free, no auth. The on-disk cache is keyed
# on calendar date (one download per day max — no retry storm), so the TTL
# below is the *web-layer* staleness threshold for the epss_scores DB table,
# not the file-cache freshness check (which is purely date-based).
EPSS_SCORES_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
EPSS_DEFAULT_TTL = 24 * 3600  # seconds — DB-side staleness window before refetch

# ---- Rate limit defaults ---------------------------------------------------
# 5,000 req/hour authenticated GitHub budget = 1.39 sustained req/s.
# 1.3 leaves a small safety margin.
DEFAULT_GITHUB_RPS   = 1.3
DEFAULT_GITHUB_BURST = 5.0

DEFAULT_OSV_RPS    = 5.0
DEFAULT_OSV_BURST  = 10.0

# ---- Scan defaults ---------------------------------------------------------
DEFAULT_WORKERS       = 8
DEFAULT_SUMMARY_EVERY = 50

# ---- Reachability ----------------------------------------------------------
# Tarball-based source scanning. We download the repo archive, then run a
# single-pass Aho-Corasick search across all source files for the union of
# import patterns produced for each (package, ecosystem) pair.
REACHABILITY_TARBALL_MAX_BYTES: int = int(
    os.environ.get("DKATCHR_REACHABILITY_TARBALL_MAX_BYTES", str(1024 * 1024 * 1024 * 5))
)  # 1GB default. The tarball is streamed through tarfile without ever being
   # held in memory, so this cap is a safety belt against runaway streams,
   # not a RAM budget. Override via env if you scan even bigger monorepos.
REACHABILITY_MAX_FILE_BYTES:    int = 2 * 1024 * 1024    # 2MB — skip individual files

# Streaming progress tuning. Big chunks keep event volume low; small chunks
# give the UI smoother updates. 1MB strikes a balance — a 50MB tarball ticks
# ~50 progress events, one per second on a typical home connection.
REACHABILITY_DOWNLOAD_CHUNK_BYTES: int = 1024 * 1024
REACHABILITY_SCAN_PROGRESS_EVERY:  int = 50  # emit a scan-progress event every N tar members

# Memory-safety bound on the source-line snippet captured per detailed
# pattern hit (extra-pattern mechanics in core/reachability.py). A minified
# file under the 2MB cap can still be one multi-hundred-KB line; never hold
# more than this per hit. Consumers apply their own (smaller) display trim.
REACHABILITY_SNIPPET_MAX_CHARS: int = 500

# Inclusive by design: extension match is a cheap pre-filter, then per-file
# AC scan does the real work. A false positive costs one wasted scan of a
# template; a false negative lets a vulnerable import slip past silently.
# ---- Executed programs ("command" reachability) ----------------------------
# A package can be used by RUNNING its program rather than importing it
# (`subprocess.run(["ocrmypdf", ...])`, `RUN celery worker` in a Dockerfile,
# `web: gunicorn app:app` in a Procfile). Its command names come from the
# package itself (PyPI console/gui scripts, gem executables — read by the
# import-name resolvers). Where invocations are searched:
#   * quoted forms ("ocrmypdf", 'ocrmypdf ') in source files and in these
#     command files;
#   * bare forms (` ocrmypdf `, line-start `ocrmypdf `) ONLY in these command
#     files — in source code a bare word is usually prose.
# Manifests never count (a dependency declaration is not an invocation).
REACHABILITY_COMMAND_FILE_NAMES: frozenset[str] = frozenset({
    "Dockerfile", "Containerfile", "Procfile", "Makefile", "Jenkinsfile", "Rakefile",
})
REACHABILITY_COMMAND_FILE_PREFIXES: tuple[str, ...] = ("Dockerfile.", "Procfile.")
REACHABILITY_COMMAND_FILE_SUFFIXES: tuple[str, ...] = (
    ".sh", ".bash", ".zsh", ".dockerfile", ".mk", ".yml", ".yaml", ".service", ".cfg", ".ini", ".toml",
)
# Shorter command names (`tox`, `pip`) collide with ordinary words too often.
REACHABILITY_COMMAND_MIN_LEN = 4

REACHABILITY_SOURCE_EXTENSIONS: frozenset[str] = frozenset({
    # Python (PyPI)
    ".py", ".pyx", ".pxd", ".pyi", ".pyw",
    # JavaScript / TypeScript (npm)
    ".js", ".mjs", ".cjs", ".jsx",
    ".ts", ".tsx", ".mts", ".cts",
    # Web-framework single-file components — contain <script> import blocks
    ".vue", ".svelte", ".astro",
    # Ruby (RubyGems)
    ".rb", ".rbw", ".rake", ".gemspec", ".ru", ".erb",
    # Go
    ".go",
    # Rust (crates.io)
    ".rs",
    # JVM (Maven)
    ".java",
    ".kt", ".kts",                       # Kotlin + script (covers *.gradle.kts)
    ".scala", ".sc",                     # Scala + script
    ".groovy", ".gradle",                # Groovy + Gradle build DSL
    ".clj", ".cljs", ".cljc",            # Clojure family
    # .NET (NuGet)
    ".cs", ".csx",                       # C# + script
    ".fs", ".fsx", ".fsi",               # F# + script + signature
    ".vb",                               # VB.NET
    ".razor", ".cshtml", ".vbhtml",      # Razor templates use @using directives
    # PHP (Composer) — includes historical versioned extensions still in the wild
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8",
    # Swift — kept for parity with prior list; no Swift ecosystem yet
    ".swift",
})

# ---- Registry resolver -----------------------------------------------------
# Import names are resolved dynamically by querying package registries at scan
# time (see dkatchr/clients/resolvers/). Results are cached in
# {CACHE_DIR}/registry/{ecosystem}__{package}.json keyed on (eco, pkg) only —
# import names are version-stable in practice.
REGISTRY_RESOLVER_WORKERS:      int = int(os.environ.get("DKATCHR_REGISTRY_RESOLVER_WORKERS", "6"))
REGISTRY_RESOLVER_CACHE_SCHEMA: int = 2   # v2: entries carry "commands" (installed programs)

# File path substrings (case-insensitive) that indicate a test file.
# Conservative: only patterns whose presence in a path is a strong signal
# of test code in widely-used frameworks. False positives here silently
# downgrade real production files to UNUSED — worse than missing
# a few exotic test patterns.
REACHABILITY_TEST_FILE_PATTERNS: tuple[str, ...] = (
    # Directory conventions
    "/test/", "/tests/", "/__tests__/",
    "/spec/", "/specs/",
    "/fixtures/", "/mocks/", "__mocks__/",
    "/e2e/", "/integration/",
    "/cypress/", "/playwright/",
    # Filename conventions
    "test_",              # Python: test_foo.py
    "_test.",             # Go: foo_test.go; also Python
    "_spec.",             # RSpec: user_spec.rb
    ".test.", ".spec.",   # JS/TS: foo.test.ts, foo.spec.ts
    "conftest",           # pytest conftest.py / shared fixtures
)

# ---- Dependency-graph reachability ------------------------------------------
# A vulnerable package that your code never imports can still be loaded by a
# package that IS imported (certifi via requests). The graph comes from
# lockfile edges (`depends_on` on inventory rows) and, for formats that record
# none (requirements.txt, Pipfile.lock, go.mod/go.sum), from registry metadata
# via dkatchr/clients/dependency_meta.py. Pure propagation lives in
# dkatchr/core/dependency_graph.py.
#
# Registry endpoints for package-version dependency metadata (ENDPOINT config,
# not package knowledge). PyPI: the release JSON lists the version's files; a
# wheel's core metadata is served on its own at "<wheel-url>.metadata" (PEP 658)
# — a few KB instead of downloading the wheel. Go: the module proxy serves each
# module version's go.mod; uppercase path letters are escaped as "!" + lower.
PYPI_RELEASE_JSON_URL = "https://pypi.org/pypi/{package}/{version}/json"
PYPI_PROJECT_JSON_URL = "https://pypi.org/pypi/{package}/json"   # current version (info.version)
GO_PROXY_MOD_URL      = os.environ.get("GOPROXY_MOD_URL", "https://proxy.golang.org/{module}/@v/{version}.mod")
GO_PROXY_LATEST_URL   = os.environ.get("GOPROXY_LATEST_URL", "https://proxy.golang.org/{module}/@latest")
DEPENDENCY_META_RPS: dict[str, float] = {"PyPI": 8.0, "Go": 8.0}
DEPENDENCY_META_TIMEOUT = 20  # seconds per request
# Permanent cache at {CACHE_DIR}/dependency_meta/ keyed (ecosystem, package,
# version): a published version's dependency list never changes. Bump the
# schema to invalidate after a parsing change.
DEPENDENCY_META_CACHE_SCHEMA = 3   # v2: (name, conditional) pairs; v3: sdist-only releases read (were cached unknown)
# ---- Transitive resolution (manifests without a lockfile) --------------------
# A pom.xml, .csproj or top-level requirements.txt names only DIRECT
# dependencies; what they pull in is installed but written nowhere in the repo.
# dkatchr/clients/transitive_resolver.py asks the registry ecosystem for each
# direct dependency's resolved tree; dkatchr/core/transitive.py adds the
# packages as version_source "transitive" rows. ENDPOINT config only.
#   deps.dev (Google Open Source Insights): resolved graph for Maven/PyPI/npm.
#     Ranges resolve to today's newest match (what a fresh install would get);
#     Maven pins exact versions, so Maven trees are exact.
#   NuGet: deps.dev has no NuGet graphs, so package .nuspec files (the
#     flat-container CDN) are walked directly, taking each range's LOWEST
#     version (NuGet's own rule).
DEPS_DEV_DEPENDENCIES_URL = os.environ.get(
    "DKATCHR_DEPS_DEV_DEPENDENCIES_URL",
    "https://api.deps.dev/v3/systems/{system}/packages/{package}/versions/{version}:dependencies")
NUGET_NUSPEC_URL = os.environ.get(
    "DKATCHR_NUGET_NUSPEC_URL",
    "https://api.nuget.org/v3-flatcontainer/{package}/{version}/{package}.nuspec")
TRANSITIVE_RPS: dict[str, float] = {"deps.dev": 10.0, "NuGet": 20.0}
TRANSITIVE_TIMEOUT = 20            # seconds per request
TRANSITIVE_CACHE_SCHEMA = 1        # {CACHE_DIR}/transitive/, permanent per (eco, package, version)
# Per-repo bound on direct dependencies resolved (each is one cached lookup).
TRANSITIVE_MAX_ROOTS_PER_REPO = int(os.environ.get("DKATCHR_TRANSITIVE_MAX_ROOTS", "1500"))
# Per-root bound on a NuGet tree walk (deps.dev returns whole trees itself).
TRANSITIVE_NUGET_MAX_NODES = int(os.environ.get("DKATCHR_TRANSITIVE_NUGET_MAX_NODES", "400"))

# Per-repo bounds. More registry lookups than this (edge-less formats only)
# or more packages to probe for imports than this => the graph is skipped for
# that repo and reachability falls back to plain import presence.
GRAPH_MAX_META_LOOKUPS   = int(os.environ.get("DKATCHR_GRAPH_MAX_META_LOOKUPS", "800"))
GRAPH_MAX_PROBE_PACKAGES = int(os.environ.get("DKATCHR_GRAPH_MAX_PROBE_PACKAGES", "600"))


# ---------------------------------------------------------------------------
# Runtime & base-image scanning (dkatchr>=0.8.0)
# ---------------------------------------------------------------------------
# Identity facts about each language RUNTIME — the same constant class as
# DEFAULT_PUBLIC_REGISTRY_HOSTS / the PURL type map: what each runtime is
# called by each data source, never per-package domain data.
#   osv          (ecosystem, package) pairs whose OSV advisories cover the runtime
#   cpe          NVD CPE vendor:product (version-aware virtualMatchString queries)
#   cve_products (vendor, product) names CNAs use in CVE.org "affected" entries
#                (matched case-insensitively)
#   eol          endoflife.date product slug
#   images       official image repository names that ship this runtime
#   env          image ENV variables that carry the runtime version
#   asdf         .tool-versions / CI tool names
#   cve_listed_is_max  the CNA lists the highest affected version per line
#                (plain "version" entries mean "this and older on that line")
#   bakes_stdlib the toolchain compiles its standard library INTO the shipped
#                binary, so a build-stage version still ships
RUNTIMES: dict[str, dict] = {
    "ruby":   {"osv": [("Bitnami", "ruby")], "cpe": "ruby-lang:ruby",
               "cve_products": [("ruby-lang", "ruby"), ("ruby", "ruby")], "eol": "ruby",
               "images": ["ruby"], "env": ["RUBY_VERSION"], "asdf": ["ruby"], "bakes_stdlib": False},
    "node":   {"osv": [("Bitnami", "node")], "cpe": "nodejs:node.js",
               "cve_products": [("nodejs", "node"), ("nodejs", "node.js"), ("node.js", "node.js")],
               "eol": "nodejs", "images": ["node"], "env": ["NODE_VERSION"],
               "asdf": ["nodejs", "node"], "bakes_stdlib": False},
    "python": {"osv": [("Bitnami", "python")], "cpe": "python:python",
               "cve_products": [("python software foundation", "cpython"), ("python", "python"),
                                ("python", "cpython")], "eol": "python",
               "images": ["python"], "env": ["PYTHON_VERSION"], "asdf": ["python"], "bakes_stdlib": False},
    "php":    {"osv": [("Bitnami", "php")], "cpe": "php:php",
               "cve_products": [("php group", "php"), ("php", "php")], "eol": "php",
               "images": ["php"], "env": ["PHP_VERSION"], "asdf": ["php"], "bakes_stdlib": False},
    "go":     {"osv": [("Go", "stdlib"), ("Go", "toolchain")], "cpe": "golang:go",
               "cve_products": [("go standard library", "*"), ("go toolchain", "*"), ("golang", "go")],
               "eol": "go", "images": ["golang"], "env": ["GOLANG_VERSION"],
               "asdf": ["golang", "go"], "bakes_stdlib": True},
    "java":   {"osv": [("Bitnami", "java")], "cpe": "oracle:openjdk",
               "cve_products": [("oracle", "java se*"), ("oracle corporation", "java se*"),
                                ("oracle corporation", "oracle java se*"),
                                ("oracle", "openjdk"), ("eclipse foundation", "temurin")],
               # Oracle's CVE records list the HIGHEST affected version per
               # release line ("17.0.14" = 17.0.14 and earlier on 17).
               "cve_listed_is_max": True,
               "eol": "eclipse-temurin",
               "images": ["eclipse-temurin", "openjdk", "amazoncorretto", "ibm-semeru-runtimes", "sapmachine"],
               "env": ["JAVA_VERSION"], "asdf": ["java"], "bakes_stdlib": False},
    "dotnet": {"osv": [("Bitnami", "dotnet"), ("Bitnami", "aspnet-core")], "cpe": "microsoft:.net",
               "cve_products": [("microsoft", ".net*"), ("microsoft", "asp.net core*")],
               "cve_exclude": ["framework"],
               "eol": "dotnet",
               "images": ["dotnet/runtime", "dotnet/aspnet", "dotnet/sdk", "dotnet/runtime-deps"],
               "env": ["DOTNET_VERSION", "ASPNET_VERSION"], "asdf": ["dotnet", "dotnet-core"],
               "bakes_stdlib": False},
    "rust":   {"osv": [], "cpe": "rust-lang:rust", "cve_products": [("rust-lang", "rust")],
               "eol": "rust", "images": ["rust"], "env": ["RUST_VERSION"], "asdf": ["rust"],
               "bakes_stdlib": True},
    "elixir": {"osv": [], "cpe": "elixir-lang:elixir",
               "cve_products": [("elixir-lang", "elixir"), ("elixir", "elixir")], "eol": "elixir",
               "images": ["elixir"], "env": ["ELIXIR_VERSION"], "asdf": ["elixir"], "bakes_stdlib": False},
    "erlang": {"osv": [], "cpe": "erlang:erlang\\/otp",
               "cve_products": [("erlang", "otp"), ("erlang", "erlang/otp")], "eol": "erlang",
               "images": ["erlang"], "env": ["OTP_VERSION"], "asdf": ["erlang"], "bakes_stdlib": False},
}

# Linux base-image distributions: endoflife.date slug per image repository.
DISTRO_EOL_PRODUCTS: dict[str, str] = {
    "debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine-linux",
}

ENDOFLIFE_API_URL = os.environ.get("DKATCHR_ENDOFLIFE_URL", "https://endoflife.date/api/{product}.json")
DEFAULT_ENDOFLIFE_TTL = int(os.environ.get("DKATCHR_ENDOFLIFE_TTL", str(7 * 24 * 3600)))
ENDOFLIFE_TIMEOUT = 20

# Public registries whose images resolve anonymously (docker.io is the
# default when an image reference names no registry).
IMAGE_REGISTRY_DEFAULT = "docker.io"
# Only these PUBLIC registries are ever contacted to resolve an image tag, over
# https, and a token realm must be one of the registry's own auth hosts. Any
# other host named in a repo's Dockerfile / manifest (a private or internal
# registry) is never contacted — it is a repo-controlled URL (SSRF). Private
# registries arrive with stored credentials in release C.
PUBLIC_IMAGE_REGISTRIES: dict[str, dict] = {
    "docker.io":         {"api": "registry-1.docker.io", "auth": ("auth.docker.io",)},
    "ghcr.io":           {"api": "ghcr.io", "auth": ("ghcr.io",)},
    "quay.io":           {"api": "quay.io", "auth": ("quay.io",)},
    "mcr.microsoft.com": {"api": "mcr.microsoft.com", "auth": ("mcr.microsoft.com",)},
    "gcr.io":            {"api": "gcr.io", "auth": ("gcr.io",)},
    "registry.k8s.io":   {"api": "registry.k8s.io", "auth": ("registry.k8s.io",)},
    "public.ecr.aws":    {"api": "public.ecr.aws", "auth": ("public.ecr.aws",)},
    # SUSE Linux Enterprise / BCI base images; anonymous tokens from SUSE's
    # own auth host.
    "registry.suse.com": {"api": "registry.suse.com", "auth": ("scc.suse.com",)},
}
IMAGE_REGISTRY_RATE_LIMIT_BACKOFF = 900   # seconds to stop calling a registry after HTTP 429
# Inventory ecosystems produced by runtime scanning, and the vuln_id prefix of
# end-of-life findings — shared by dkatchr-core and dkatchr-web.
RUNTIME_ECOSYSTEMS = ("Runtime", "ContainerImage", "OS")
EOL_VULN_PREFIX = "EOL-"
DEFAULT_IMAGE_TAG_TTL = int(os.environ.get("DKATCHR_IMAGE_TAG_TTL", str(24 * 3600)))
IMAGE_REGISTRY_TIMEOUT = 20
IMAGE_TAG_CACHE_SCHEMA = 1

# Official CVE List (CVE.org, CVE JSON 5): runtime CVEs NVD has not analysed
# yet carry their affected versions only here. One full baseline download,
# then each day's delta release; a local index keeps runtime records only.
CVELIST_RELEASES_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=100&page={page}"
CVELIST_RECORD_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
CVELIST_BASELINE_MAX_AGE_DAYS = int(os.environ.get("DKATCHR_CVELIST_BASELINE_MAX_AGE_DAYS", "25"))
CVELIST_SYNC_TTL = int(os.environ.get("DKATCHR_CVELIST_SYNC_TTL", str(6 * 3600)))
CVELIST_TIMEOUT = 120
CVELIST_INDEX_SCHEMA = 2   # v2: Oracle 'Oracle Java SE' product + max-affected convention

# NVD version-aware CPE lookups for runtimes (per runtime+version, TTL'd:
# NVD analyses CVEs late, a re-check picks newly analysed ranges up).
DEFAULT_NVD_CPE_TTL = int(os.environ.get("DKATCHR_NVD_CPE_TTL", str(24 * 3600)))

# Files that can name a runtime version or a container image (see
# dkatchr/parsers/runtime.py). YAML deployment manifests are only read when
# their path looks like deployment config, to avoid pulling every YAML file.
RUNTIME_VERSION_FILES = frozenset({
    ".ruby-version", ".nvmrc", ".node-version", ".python-version", ".tool-versions",
    ".java-version", ".sdkmanrc", "global.json", "rust-toolchain", "rust-toolchain.toml",
    "mix.exs", "go.mod", "package.json", "Gemfile", "composer.json", "pyproject.toml",
    "pom.xml", "build.gradle", "build.gradle.kts",
})
RUNTIME_DEPLOY_PATH_HINTS = ("k8s", "kube", "kubernetes", "helm", "chart", "deploy",
                             "manifests", "argocd", "kustomize", "openshift")
