"""RubyGems: Gemfile (declared), Gemfile.lock (resolved).

Dependency `origin` (dependency-confusion signal): Gemfile.lock is parsed
section-aware — specs under a GIT section get origin="git", under PATH
origin="path", under GEM the registry default (no origin key). Gemfile lines
with `path:`/`git:`/`github:` options are captured even without a version
requirement (the option value stands in as the version when none is given).

Dependency `resolved_url` (Dependency Confusion Exposure signal): each
Gemfile.lock section's `remote:` line applies to every spec in that section
(GEM remote = the registry URL that served the gems; GIT/PATH remotes carried
as-is). A GEM section with MULTIPLE remote lines (legacy global-source
lockfiles) is ambiguous per spec — no resolved_url is attributed there.
"""

import re

from dkatchr.config import GEMFILE_DEV_GROUPS
from dkatchr.parsers._common import clean_declared_version

# `gem 'name'` line with everything after the name captured for option scanning.
_GEM_LINE = re.compile(r"""^\s*gem\s+["']([^"']+)["'](.*)$""", re.MULTILINE)
# First positional argument after the name, when it's a plain quoted string
# (a version requirement) — `, '1.2.3'`. Keyword options don't match.
_VER_ARG = re.compile(r"""^\s*,\s*["']([^"']+)["']""")
# Non-registry source options: `path:`/`git:`/`github:` (new-style) and the
# hash-rocket `:path =>` forms. Captures the option value for the version slot.
_ORIGIN_OPT = re.compile(
    r"""(?:\b(path|git|github)\s*:|:(path|git|github)\s*=>)\s*["']([^"']+)["']"""
)


# `group :development, :test do` … `end` blocks, and inline `group: :test` /
# `groups: [:development, :test]` options.
_GROUP_OPEN = re.compile(r"^\s*group\s+(.+?)\s+do\b")
_INLINE_GROUP = re.compile(r"\bgroups?\s*(?::|=>)\s*(\[[^\]]*\]|:\w+|['\"]\w+['\"])")
_BLOCK_KEYWORD = re.compile(r"^\s*(?:if|unless|case|begin|while|until)\b")


def _is_dev_groups(spec: str) -> bool:
    names = set(re.findall(r"\w+", spec))
    return bool(names) and names <= GEMFILE_DEV_GROUPS


def _dev_lines(text: str) -> set[int]:
    """Line numbers inside a `group … do` block made only of dev/test groups."""
    dev: set[int] = set()
    stack: list[bool] = []
    for i, line in enumerate(text.splitlines()):
        m = _GROUP_OPEN.match(line)
        if m:
            stack.append(_is_dev_groups(m.group(1)))
            continue
        if _BLOCK_KEYWORD.match(line) or re.match(r"^\s*(?:\w+.*\bdo\b(?:\s*\|.*\|)?\s*$)", line):
            stack.append(stack[-1] if stack else False)   # nested block: same scope
            continue
        if re.match(r"^\s*end\b", line) and stack:
            stack.pop()
            continue
        if stack and stack[-1]:
            dev.add(i)
    return dev


def from_gemfile(text: str) -> list[dict]:
    """Best-effort Gemfile parser — `gem 'name', 'version'` plus
    `gem 'name', path:/git:/github: '…'` source options. Gems declared only
    in development/test groups get scope "dev"."""
    deps = []
    dev_lines = _dev_lines(text)
    for m in _GEM_LINE.finditer(text):
        name = m.group(1)
        rest = m.group(2) or ""
        # Strip trailing Ruby comments so "# path: '…'" prose never reads as a
        # source option. Splitting on space-hash keeps '#' inside values safe.
        rest = re.split(r"\s#", rest, maxsplit=1)[0]

        ver_m = _VER_ARG.match(rest)
        ver = clean_declared_version(ver_m.group(1)) if ver_m else ""

        origin = None
        spec = ""
        opt = _ORIGIN_OPT.search(rest)
        if opt:
            key = opt.group(1) or opt.group(2)
            spec = opt.group(3)
            origin = "path" if key == "path" else "git"

        line_no = text.count("\n", 0, m.start())
        inline = _INLINE_GROUP.search(rest)
        is_dev = _is_dev_groups(inline.group(1)) if inline else line_no in dev_lines
        if origin:
            # No version requirement needed for path/git gems — the source
            # spec stands in when no version was declared.
            dep = {"package": name, "version": ver or spec,
                   "version_source": "declared", "origin": origin}
        elif name and ver:
            dep = {"package": name, "version": ver, "version_source": "declared"}
        else:
            continue
        if is_dev:
            dep["scope"] = "dev"
        deps.append(dep)
    return deps


# Top-level gem specs are 4-space indented: "    name (version)".
# Sub-deps are 6+ space indented and ignored.
_LOCK_SPEC = re.compile(r"^    ([A-Za-z0-9_.\-]+) \(([^()]+)\)\s*$")

# Gemfile.lock section headers sit at column 0 (GEM / GIT / PATH / PLUGIN
# SOURCE / DEPENDENCIES / PLATFORMS / …). Only GIT and PATH mark their specs
# as non-registry.
_SECTION_ORIGIN = {"GIT": "git", "PATH": "path"}

# Indented "remote: <value>" line inside a section — the registry URL (GEM),
# git URL (GIT) or local path (PATH) every spec in the section resolved from.
_REMOTE_LINE = re.compile(r"^\s+remote:\s+(\S+)")
# A spec's own dependencies: 6-space-indented `name` or `name (constraints)`
# lines directly under its 4-space spec line.
_LOCK_SPEC_DEP = re.compile(r"^      ([A-Za-z0-9_.\-]+)(?:\s|$)")
# Platform-specific gems are locked as "<version>-<platform>"
# ("1.18.10-arm64-darwin", "1.16.0-java", "2.6.0-x64-mingw-ucrt"). Advisories
# are keyed on the bare version, so the platform must be stripped or the gem
# matches nothing. The pattern follows Gem::Platform's cpu/os grammar; a
# hyphenated prerelease ("1.0.0-rc1") does not match it and is left alone.
_PLATFORM_SUFFIX = re.compile(
    r"^(?P<ver>[0-9][^-]*)-(?:java|jruby|dalvik\w*|mswin\w*|mingw\w*|"
    r"(?:x86_64|x86|x64|i[3-6]86|arm\w*|aarch64|universal|powerpc\w*|ppc\w*|"
    r"s390x?|sparc\w*|wasm\w*|riscv\w*|loongarch\w*)(?:-[A-Za-z0-9_.]+)*)$"
)


def _strip_platform(ver: str) -> str:
    m = _PLATFORM_SUFFIX.match(ver)
    return m.group("ver") if m else ver


def from_gemfile_lock(text: str) -> list[dict]:
    """Section-aware Gemfile.lock parser.

    Specs are read from GEM (registry), GIT (origin="git") and PATH
    (origin="path") sections; the spec regex itself is unchanged from the
    pre-section-aware parser. The section's `remote:` line is carried as each
    spec's resolved_url — unless the section declares several remotes (legacy
    multi-remote GEM blocks), where per-spec attribution is ambiguous.
    """
    deps = []
    seen = set()
    section: str | None = None
    remotes: list[str] = []
    # `depends_on` (dependency-graph reachability): Gemfile.lock lists every
    # resolved spec's own dependencies under it, so edges are known.
    edges: dict[str, set[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        if line and not line[0].isspace():
            section = line.strip()
            remotes = []
            current = None
            continue
        dm = _LOCK_SPEC_DEP.match(line)
        if dm and current is not None:
            edges[current].add(dm.group(1))
            continue
        rm = _REMOTE_LINE.match(line)
        if rm:
            remotes.append(rm.group(1))
            continue
        m = _LOCK_SPEC.match(line)
        if not m:
            continue
        name = m.group(1)
        ver  = m.group(2).strip()
        current = name
        edges.setdefault(name, set())
        # Skip platform/range qualifiers like "= 7.0.0" — they contain spaces
        if " " in ver:
            continue
        # One gem locked for several platforms collapses to one row here.
        ver = _strip_platform(ver)
        key = (name, ver)
        if key in seen:
            continue
        seen.add(key)
        dep = {"package": name, "version": ver, "version_source": "resolved"}
        origin = _SECTION_ORIGIN.get(section or "")
        if origin:
            dep["origin"] = origin
        if len(remotes) == 1:
            dep["resolved_url"] = remotes[0]
        deps.append(dep)
    for dep in deps:
        dep["depends_on"] = sorted(edges.get(dep["package"], set()))
    return deps
