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


def from_package_lock(text: str) -> list[dict]:
    """Handle package-lock.json v1 (npm 5/6) and v2/v3 (npm 7+)."""
    try:
        data = json.loads(text)
    except Exception:
        return []

    deps: list[dict] = []
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

    return deps


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


def from_yarn_lock(text: str) -> list[dict]:
    """Handles both classic (v1) and Berry (v2+) formats."""
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


def from_pnpm_lock(text: str) -> list[dict]:
    """Supports v5 (pnpm 6), v6 (pnpm 7/8), v9 (pnpm 9)."""
    deps: list[dict] = []
    seen: set[tuple] = set()

    def _add(name: str, ver: str) -> None:
        key = (name, ver)
        if key not in seen:
            seen.add(key)
            deps.append({"package": name, "version": ver, "version_source": "resolved"})

    # v5: /lodash/4.17.21:  or  /@scope/pkg/1.0.0:
    v5 = re.compile(r"^/(@?[^/\n]+(?:/@?[^/\n]+)?)/(\d[^:\s(]*):", re.MULTILINE)
    for m in v5.finditer(text):
        _add(m.group(1), m.group(2))

    # v6: /lodash@4.17.21:  or  /@scope/pkg@1.0.0:
    v6 = re.compile(r"^/(@?[^@/\n]+(?:/@?[^@/\n]+)?)@(\d[^:\s(]*):", re.MULTILINE)
    for m in v6.finditer(text):
        _add(m.group(1), m.group(2))

    # v9 packages section: entries like "  lodash@4.17.21:" — and SCOPED keys,
    # which pnpm/js-yaml single-quotes because '@' is a reserved YAML indicator:
    # "  '@scope/pkg@1.0.0':". Mirror the v9_url regex's leading `'?` + `'`-excluded
    # char classes + trailing `'?` so quoted scoped keys are parsed (without it,
    # every scoped dep in a pnpm v9 lockfile was silently dropped).
    v9 = re.compile(r"^\s{2}'?(@?[^@\n/'][^@\n']*)@(\d[^:\s(']*)'?:", re.MULTILINE)
    for m in v9.finditer(text):
        _add(m.group(1).strip(), m.group(2))

    # v9 git/URL entries: "  pkg@https://codeload.github.com/…:" or
    # "  pkg@git+https://…:". Best-effort — the version slot keeps the raw
    # spec. v5/v6 git entries don't carry the package name in their key at
    # all ("github.com/user/repo/sha:") and are skipped as ambiguous.
    v9_url = re.compile(
        r"^\s{2}'?(@?[^@\n/'][^@\n']*)@((?:git\+|git://|https?://)[^:\s(']*)'?:",
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
