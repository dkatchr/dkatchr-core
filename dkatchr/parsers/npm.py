"""npm: package.json, package-lock.json (v1+v2/v3), yarn.lock (v1+Berry), pnpm-lock.yaml (v5/v6/v9).

Dependency `origin` (dependency-confusion signal): parsers set an optional
"origin" key on dep dicts — "path" | "git" | "workspace" | "url" — when the
declared spec / lockfile resolution points somewhere other than a registry.
Absent origin means "registry" (the default the inventory layer materializes).
Non-registry rows keep the RAW spec as their version (there is no meaningful
semver to clean), and are excluded from OSV queries by the enrichment layer.

Dependency `resolved_url` (Dependency Confusion Exposure signal): lockfile
parsers additionally carry the URL the lockfile RECORDS the dependency as
resolving from, when the format records one — package-lock.json's `resolved`
field (v1 and v2/v3) and yarn v1's per-stanza `resolved "…"` line. Absent means
the format doesn't record it: yarn Berry (`resolution: "pkg@npm:ver"`) and pnpm
(`resolution: {integrity: …}`) carry a resolution PROTOCOL but no URL (verified
against real lockfiles), so their coverage is protocol-level only — the
historical confusion check cannot see which registry host served them.

Dependency `depends_on` (dependency-graph reachability): every LOCKFILE parser
attaches the names each package depends on (dependencies + optional + peer —
over-approximated edges can only over-flag). Edges are collected per package
NAME across all entries/versions of that name, matching the name-level graph
the reachability core builds. package.json is a declaration, not a resolved
graph, so its rows carry no `depends_on` (= edges unknown).
"""

import json
import re

from dkatchr.parsers._common import clean_declared_version

# Known registry-tarball hosts seen in yarn.lock resolution URLs. Used only to
# AVOID mislabeling a registry tarball URL as origin="url" — endpoint config,
# not package knowledge.
_REGISTRY_URL_HOSTS = ("registry.npmjs.org", "registry.yarnpkg.com", "npm.pkg.github.com")


def _declared_spec_origin(spec: str) -> str | None:
    """Classify a package.json / yarn descriptor spec string.

    Returns "path" | "workspace" | "git" | "url", or None for a plain registry
    semver spec (or anything ambiguous — ambiguity defaults to registry)."""
    s = (spec or "").strip()
    if s.startswith(("file:", "link:", "portal:")):
        return "path"
    if s.startswith("workspace:"):
        return "workspace"
    if s.startswith(("git+", "git://", "git@", "github:", "gitlab:", "bitbucket:")):
        return "git"
    if s.startswith(("http://", "https://")):
        if any(host in s for host in _REGISTRY_URL_HOSTS):
            return None
        return "git" if ("github.com" in s or s.endswith(".git")) else "url"
    return None


def from_package_json(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except Exception:
        return []
    deps = []
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, ver in (data.get(section) or {}).items():
            if not isinstance(ver, str) or not ver:
                continue
            origin = _declared_spec_origin(ver)
            if origin:
                # Keep the raw spec as the version — "file:../pkg" has no
                # cleanable semver, and the spec IS the useful information.
                deps.append({"package": name, "version": ver,
                             "version_source": "declared", "origin": origin})
                continue
            cleaned = clean_declared_version(ver)
            if cleaned:
                deps.append({"package": name, "version": cleaned, "version_source": "declared"})
    return deps


_EDGE_SECTIONS = ("dependencies", "optionalDependencies", "peerDependencies")


def _attach_edges(deps: list[dict], edges: dict[str, set[str]]) -> list[dict]:
    """Set `depends_on` on every row from the per-name edge map (known = [])."""
    for dep in deps:
        dep["depends_on"] = sorted(edges.get(dep["package"], set()))
    return deps


def from_package_lock(text: str) -> list[dict]:
    """Handle package-lock.json v1 (npm 5/6) and v2/v3 (npm 7+)."""
    try:
        data = json.loads(text)
    except Exception:
        return []

    deps: list[dict] = []
    edges: dict[str, set[str]] = {}
    lock_version = data.get("lockfileVersion", 1)

    if lock_version >= 2 and "packages" in data:
        # v2/v3: keys are "" (root), "node_modules/pkg",
        # "node_modules/a/node_modules/b" for nested packages, or a bare
        # in-repo path like "packages/foo" for workspace members.
        for key, meta in data["packages"].items():
            if not key or not isinstance(meta, dict):
                continue
            origin = None
            if "node_modules/" not in key:
                # Workspace member — an in-repo package, not a registry install.
                # Its real name lives in meta["name"] (the key is its path).
                origin = "workspace"
                name = meta.get("name") or key
            else:
                parts = key.split("node_modules/")
                name = parts[-1].strip("/") if parts else key
                # Origin from the entry's `resolved` field: file:/git+ prefixes
                # are non-registry; a registry tarball URL (or absent) is not.
                resolved = meta.get("resolved")
                if isinstance(resolved, str):
                    if resolved.startswith("file:"):
                        origin = "path"
                    elif resolved.startswith(("git+", "git://")):
                        origin = "git"
                if meta.get("link") is True:
                    origin = "workspace"
            ver = meta.get("version", "")
            if name:
                bucket = edges.setdefault(name, set())
                for sec in _EDGE_SECTIONS:
                    if isinstance(meta.get(sec), dict):
                        bucket.update(meta[sec].keys())
            if name and (ver or origin):
                # Version-less non-registry entries keep their raw spec: the
                # resolved URL when one exists, else the workspace path (key).
                resolved = meta.get("resolved")
                fallback = resolved if (isinstance(resolved, str) and resolved) else key
                dep = {"package": name, "version": ver or fallback,
                       "version_source": "resolved"}
                if origin:
                    dep["origin"] = origin
                if isinstance(resolved, str) and resolved:
                    dep["resolved_url"] = resolved
                deps.append(dep)
    else:
        # v1: flat "dependencies" dict, may have nested "dependencies" inside each entry.
        def _walk(obj: dict) -> None:
            for name, meta in obj.items():
                if not isinstance(meta, dict):
                    continue
                ver = meta.get("version", "")
                bucket = edges.setdefault(name, set())
                if isinstance(meta.get("requires"), dict):
                    bucket.update(meta["requires"].keys())
                if ver:
                    dep = {"package": name, "version": ver, "version_source": "resolved"}
                    resolved = meta.get("resolved")
                    if isinstance(resolved, str) and resolved:
                        dep["resolved_url"] = resolved
                    deps.append(dep)
                nested = meta.get("dependencies")
                if isinstance(nested, dict):
                    _walk(nested)
        _walk(data.get("dependencies") or {})

    return _attach_edges(deps, edges)


def _yarn_key_origin(spec: str) -> str | None:
    """Best-effort protocol detection on the part of a yarn.lock entry key
    after `name@`. Berry keys carry an explicit protocol ("npm:^1.0.0",
    "workspace:packages/foo", "portal:../x"); classic keys carry the raw
    declared spec. Ambiguous specs return None (treated as registry)."""
    s = (spec or "").strip().strip('"')
    if s.startswith("npm:"):
        return None                       # explicit registry protocol (Berry)
    if s.startswith(("workspace:",)):
        return "workspace"
    if s.startswith(("file:", "link:", "portal:")):
        return "path"
    if s.startswith(("git+", "git://", "git@", "github:", "gitlab:", "bitbucket:")):
        return "git"
    if s.startswith(("http://", "https://")):
        if any(host in s for host in _REGISTRY_URL_HOSTS):
            return None
        return "git" if ("github.com" in s or s.endswith(".git")) else "url"
    return None


# Inside a yarn.lock entry: a `dependencies:` / `optionalDependencies:` /
# `peerDependencies:` header, then deeper-indented `name "range"` (v1) or
# `name: range` (Berry) lines. The name may be quoted ("@scope/pkg").
_YARN_EDGE_HEADER = re.compile(r"^(\s+)(dependencies|optionalDependencies|peerDependencies):\s*$")
_YARN_EDGE_LINE = re.compile(r'^\s+"?(@?[^"\s:]+)"?:?\s')


def _yarn_entry_names(header: str) -> list[str]:
    names = []
    for part in header.rstrip(":").split(","):
        spec = part.strip().strip('"')
        if not spec:
            continue
        at = spec.find("@", 1)   # skip a leading scope '@'
        name = spec[:at] if at > 0 else spec
        if name and name not in names:
            names.append(name)
    return names


def _yarn_edges(text: str) -> dict[str, set[str]]:
    """Per-package-name dependency edges for both yarn.lock formats."""
    edges: dict[str, set[str]] = {}
    for stanza in re.split(r"\n{2,}", text):
        lines = stanza.strip("\n").splitlines()
        if not lines or lines[0].startswith(("#", "__metadata")) or lines[0][:1].isspace():
            continue
        owners = _yarn_entry_names(lines[0])
        found: set[str] = set()
        in_section_indent = None
        for line in lines[1:]:
            h = _YARN_EDGE_HEADER.match(line)
            if h:
                in_section_indent = len(h.group(1))
                continue
            if in_section_indent is None:
                continue
            indent = len(line) - len(line.lstrip())
            if indent <= in_section_indent:
                in_section_indent = None
                continue
            m = _YARN_EDGE_LINE.match(line)
            if m:
                found.add(m.group(1))
        for owner in owners:
            edges.setdefault(owner, set()).update(found)
    return edges


def from_yarn_lock(text: str) -> list[dict]:
    """Handles both classic (v1) and Berry (v2+) formats."""
    return _attach_edges(_from_yarn_lock_rows(text), _yarn_edges(text))


def _from_yarn_lock_rows(text: str) -> list[dict]:
    deps: list[dict] = []

    if "__metadata:" in text:
        # Berry (v2+) format:
        #   "@babel/core@npm:^7.0.0":
        #     version: 7.20.0
        entry_re = re.compile(
            r'^"?(@?[^@"\n]+)@([^"\n]+?)"?:\n\s+version:\s+([^\n]+)',
            re.MULTILINE,
        )
        for m in entry_re.finditer(text):
            name = m.group(1).strip().strip('"')
            ver  = m.group(3).strip().strip('"')
            if name and ver:
                dep = {"package": name, "version": ver, "version_source": "resolved"}
                origin = _yarn_key_origin(m.group(2))
                if origin:
                    dep["origin"] = origin
                deps.append(dep)
        return deps

    # Classic v1 format:
    #   "lodash@^4.17.4", "lodash@^4.17.11":
    #     version "4.17.21"
    #     resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#…"
    name_re     = re.compile(r'"?(@?[^@",\s]+)@([^",]*)')
    version_re  = re.compile(r'^\s+version\s+"([^"]+)"')
    resolved_re = re.compile(r'^\s+resolved\s+"([^"]+)"')

    for stanza in re.split(r"\n{2,}", text):
        lines = stanza.strip().splitlines()
        if len(lines) < 2:
            continue
        header = lines[0]
        if header.startswith("#") or header.startswith("__metadata"):
            continue
        ver = None
        resolved_url = None
        for line in lines[1:]:
            m = version_re.match(line)
            if m and ver is None:
                ver = m.group(1)
                continue
            rm = resolved_re.match(line)
            if rm and resolved_url is None:
                resolved_url = rm.group(1)
        if not ver:
            continue
        seen_in_stanza: set[str] = set()
        for nm in name_re.finditer(header):
            name = nm.group(1).strip('"').strip()
            if name and name not in seen_in_stanza:
                seen_in_stanza.add(name)
                dep = {"package": name, "version": ver, "version_source": "resolved"}
                origin = _yarn_key_origin(nm.group(2))
                if origin:
                    dep["origin"] = origin
                if resolved_url:
                    dep["resolved_url"] = resolved_url
                deps.append(dep)
    return deps


def _pnpm_key_name(key: str) -> str | None:
    """Package name from a pnpm packages/snapshots key across v5/v6/v9:
    '/lodash/4.17.21', '/@s/p/1.0.0' (v5); '/lodash@4.17.21', '@s/p@1.0.0',
    "'@s/p@1.0.0(peer@2.0.0)'" (v6/v9)."""
    k = key.strip().strip("'\"").split("(", 1)[0].lstrip("/")
    if not k:
        return None
    at = k.rfind("@")
    if at > 0:                       # v6/v9: name@version
        return k[:at]
    parts = k.split("/")             # v5: name/version or @scope/name/version
    if len(parts) >= 2:
        return "/".join(parts[:-1])
    return None


def _pnpm_edges(text: str) -> dict[str, set[str]]:
    edges: dict[str, set[str]] = {}
    section = None
    owner = None
    in_deps = False
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            section = line.rstrip(":").strip()
            owner, in_deps = None, False
            continue
        if section not in ("packages", "snapshots"):
            continue
        if indent == 2 and line.rstrip().endswith(":"):
            owner = _pnpm_key_name(line.strip()[:-1])
            if owner:
                edges.setdefault(owner, set())
            in_deps = False
            continue
        if indent == 4:
            in_deps = line.strip().rstrip(":") in _EDGE_SECTIONS
            continue
        if indent >= 6 and in_deps and owner:
            name = line.strip().split(":", 1)[0].strip().strip("'\"")
            if name:
                edges[owner].add(name)
    return edges


def from_pnpm_lock(text: str) -> list[dict]:
    """Supports v5 (pnpm 6), v6 (pnpm 7/8), v9 (pnpm 9)."""
    return _attach_edges(_from_pnpm_lock_rows(text), _pnpm_edges(text))


def _from_pnpm_lock_rows(text: str) -> list[dict]:
    deps: list[dict] = []
    seen: set[tuple] = set()

    def _add(name: str, ver: str) -> None:
        key = (name, ver)
        if key not in seen:
            seen.add(key)
            deps.append({"package": name, "version": ver, "version_source": "resolved"})

    # v5: /lodash/4.17.21:  or  /@scope/pkg/1.0.0:
    # Keys sit under `packages:` indented by 2 spaces in real lockfiles; the
    # old `^/` anchor never matched them (every v5/v6 lockfile parsed empty).
    v5 = re.compile(r"^[ \t]*/(@?[^/\n]+(?:/@?[^/\n]+)?)/(\d[^:\s(]*)(?:\([^\n]*\))?:", re.MULTILINE)
    for m in v5.finditer(text):
        _add(m.group(1), m.group(2))

    # v6: /lodash@4.17.21:  or  /@scope/pkg@1.0.0:
    # A trailing peer-dependency suffix "(debug@4.3.4)" may sit before the ':'.
    v6 = re.compile(r"^[ \t]*/(@?[^@/\n]+(?:/@?[^@/\n]+)?)@(\d[^:\s(]*)(?:\([^\n]*\))?:", re.MULTILINE)
    for m in v6.finditer(text):
        _add(m.group(1), m.group(2))

    # v9 packages section: entries like "  lodash@4.17.21:" — and SCOPED keys,
    # which pnpm/js-yaml single-quotes because '@' is a reserved YAML indicator:
    # "  '@scope/pkg@1.0.0':". Mirror the v9_url regex's leading `'?` + `'`-excluded
    # char classes + trailing `'?` so quoted scoped keys are parsed (without it,
    # every scoped dep in a pnpm v9 lockfile was silently dropped).
    # Literal two-space indent: `\s{2}` also matched "\n " across a blank line
    # and produced bogus " /name" rows from v6 keys.
    v9 = re.compile(r"^ {2}'?(@?[^@\n/' ][^@\n']*)@(\d[^:\s(']*)(?:\([^\n']*\))?'?:", re.MULTILINE)
    for m in v9.finditer(text):
        _add(m.group(1).strip(), m.group(2))

    # v9 git/URL entries: "  pkg@https://codeload.github.com/…:" or
    # "  pkg@git+https://…:". Best-effort — the version slot keeps the raw
    # spec. v5/v6 git entries don't carry the package name in their key at
    # all ("github.com/user/repo/sha:") and are skipped as ambiguous.
    v9_url = re.compile(
        # The URL itself contains ':' ("https://"), so match to the key's
        # trailing ':' at end of line rather than stopping at the first ':'.
        r"^ {2}'?(@?[^@\n/' ][^@\n']*)@((?:git\+|git://|https?://)[^\s(']*?)'?:[ \t]*$",
        re.MULTILINE,
    )
    for m in v9_url.finditer(text):
        name, spec = m.group(1).strip(), m.group(2)
        key = (name, spec)
        if key in seen:
            continue
        seen.add(key)
        origin = "git" if (spec.startswith(("git+", "git://"))
                           or "github.com" in spec or spec.endswith(".git")) else "url"
        deps.append({"package": name, "version": spec,
                     "version_source": "resolved", "origin": origin})

    return deps
