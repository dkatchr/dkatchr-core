"""PyPI: requirements*.txt, Pipfile.lock, poetry.lock, setup.py, setup.cfg, pyproject.toml.

Dependency `resolved_url` (Dependency Confusion Exposure signal): the two
lockfiles record which index served each package, and the parsers carry it —
  - poetry.lock: the [package.source] sub-table (type + url). An ABSENT source
    table means "default PyPI" per poetry semantics, so the parser materializes
    the implicit default as PYPI_DEFAULT_INDEX_URL (otherwise the PUBLIC side
    of a resolution flip would be invisible). type git/directory/file/url
    sources additionally get a non-registry `origin` — consistent with how
    Gemfile.lock GIT/PATH sections and Cargo.lock git sources already parse.
  - Pipfile.lock: each package's `index` name joined to its URL in the
    _meta.sources block. An absent index ref is attributed only when exactly
    one source is declared (ambiguous otherwise — best-effort by design).
    git/path entries (no version key) now parse as origin rows, mirroring the
    npm/ruby treatment (their raw spec stands in as the version).
requirements.txt records no index URL — origin-only coverage there.
"""

import json
import re

from dkatchr.config import PYPI_DEFAULT_INDEX_URL

# `#egg=name` fragment on a VCS/archive URL — pip's way of naming a direct ref.
_EGG_RE = re.compile(r"[#&]egg=([A-Za-z0-9._-]+)", re.IGNORECASE)
# PEP 508 direct reference: "name [extras] @ <url>"
_PEP508_DIRECT_RE = re.compile(r"^([A-Za-z0-9._-]+)(?:\[[^\]]+\])?\s*@\s*(\S+)$")
# Classic pinned/ranged requirement: "name[extras] ==1.2.3"
_REQ_RE = re.compile(r"^([A-Za-z0-9._-]+)(?:\[[^\]]+\])?\s*([<>=!~]+)\s*([^\s;,]+)")


def _url_origin(url: str) -> str:
    return "git" if url.startswith("git+") else "url"


def from_requirements_txt(text: str) -> list[dict]:
    """Best-effort requirements.txt parser.

    Captures, with a non-registry `origin`:
      - `git+https://…#egg=name` VCS refs                → origin="git"
      - `http(s)://…#egg=name` direct archive URLs       → origin="url"
      - PEP 508 direct refs (`name @ <url>`)             → origin="git"/"url"
      - `-e`/`--editable` installs of the above          → same
    Lines that yield no package name (e.g. `-e ./local-path` with no #egg=)
    stay skipped, as do `-r` includes and other pip flags. The raw spec is
    kept as the row's version — there is no semver to clean on a URL ref.
    """
    deps = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip trailing comments only when whitespace precedes the '#' — a
        # bare split on '#' would eat the `#egg=` fragment of URL refs.
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        if not line:
            continue

        editable = False
        if line.startswith(("-e ", "--editable ")):
            editable = True
            line = line.split(None, 1)[1].strip() if " " in line else ""
            if not line:
                continue

        if line.startswith("-"):
            # -r includes, --index-url, --hash and friends: not dependencies.
            continue

        if line.startswith(("git+", "http://", "https://")):
            egg = _EGG_RE.search(line)
            if not egg:
                continue  # no resolvable name — skip (spec: nameless lines stay skipped)
            deps.append({
                "package":        egg.group(1),
                "version":        line,
                "version_source": "declared",
                "origin":         _url_origin(line),
            })
            continue

        direct = _PEP508_DIRECT_RE.match(line)
        if direct:
            url = direct.group(2)
            deps.append({
                "package":        direct.group(1),
                "version":        url,
                "version_source": "declared",
                "origin":         _url_origin(url),
            })
            continue

        if editable:
            # Editable local path ("-e ." / "-e ./pkg") — no name to extract.
            continue

        m = _REQ_RE.match(line)
        if m:
            dep = {
                "package":        m.group(1),
                "version":        m.group(3),
                "version_source": "declared",
            }
            # `==` / `===` is an exact pin: pip installs exactly this version,
            # so it is queried even when a lockfile nearby resolves another.
            if m.group(2) in ("==", "==="):
                dep["pinned"] = True
            deps.append(dep)
    return deps


def from_pipfile_lock(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except Exception:
        return []

    # _meta.sources: [{"name": "pypi", "url": "https://pypi.org/simple", ...}].
    # Per-package `index` refs join against this by name. With exactly one
    # source declared, packages that omit `index` can only have come from it;
    # with several, an omitted index is ambiguous → no resolved_url.
    sources: dict[str, str] = {}
    meta_sources = ((data.get("_meta") or {}).get("sources") or [])
    for s in meta_sources:
        if isinstance(s, dict) and s.get("name") and s.get("url"):
            sources[s["name"]] = s["url"]
    sole_source_url = meta_sources[0].get("url") if (
        len(meta_sources) == 1 and isinstance(meta_sources[0], dict)) else None

    deps = []
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            if not isinstance(meta, dict):
                continue
            ver = (meta.get("version") or "").lstrip("=").strip()
            if name and ver:
                dep = {"package": name, "version": ver, "version_source": "resolved"}
                resolved_url = sources.get(meta.get("index") or "") or (
                    sole_source_url if "index" not in meta else None)
                if resolved_url:
                    dep["resolved_url"] = resolved_url
                if section == "develop":
                    dep["scope"] = "dev"
                deps.append(dep)
                continue
            # Version-less entries are VCS/path installs: {"git": url, "ref": …}
            # or {"path": "./pkg"} / {"file": url}. Captured as origin rows so
            # the confusion signals (S1 live, source timelines historical) see
            # them; the raw spec stands in as the version (npm/ruby precedent).
            if not name:
                continue
            if isinstance(meta.get("git"), str) and meta["git"]:
                deps.append({"package": name, "version": meta["git"],
                             "version_source": "resolved", "origin": "git",
                             "resolved_url": meta["git"]})
            elif isinstance(meta.get("path"), str) and meta["path"]:
                deps.append({"package": name, "version": meta["path"],
                             "version_source": "resolved", "origin": "path"})
            elif isinstance(meta.get("file"), str) and meta["file"]:
                deps.append({"package": name, "version": meta["file"],
                             "version_source": "resolved", "origin": "url",
                             "resolved_url": meta["file"]})
    return deps


# [package.source] sub-table of a poetry.lock [[package]] section — everything
# between the header and the next [table] header. type/url are its only keys we
# read (reference/resolved_reference are git bookkeeping).
_POETRY_SOURCE_RE = re.compile(
    r"\n\[package\.source\]\s*\n(.*?)(?=\n\[|\Z)", re.DOTALL)
# [package.dependencies] sub-table: one `name = <spec>` line per dependency
# (spec may be a string, an inline table, or an array of constraint tables).
_POETRY_DEPS_RE = re.compile(
    r"\n\[package\.dependencies\]\s*\n(.*?)(?=\n\[|\Z)", re.DOTALL)
_POETRY_DEP_NAME_RE = re.compile(r'^"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*=', re.MULTILINE)


def from_poetry_lock(text: str) -> list[dict]:
    """Parse [[package]] sections of poetry.lock without a TOML lib.

    name/version are read from the section HEAD (before the first sub-table,
    where a [package.dependencies] entry named `name`/`version` could otherwise
    shadow them); the [package.source] sub-table is searched in the full
    section. Source mapping: absent → default PyPI (materialized as
    PYPI_DEFAULT_INDEX_URL); legacy → its index URL (public or private — the
    consumer classifies by host); git → origin "git"; directory/file → origin
    "path"; url → origin "url".
    """
    deps = []
    sections = re.split(r"\n\[\[package\]\]\s*\n", "\n" + text)
    for section in sections[1:]:
        head = re.split(r"\n\[\[?", section, maxsplit=1)[0]
        name_m = re.search(r'^name\s*=\s*"([^"]+)"', head, re.MULTILINE)
        ver_m  = re.search(r'^version\s*=\s*"([^"]+)"', head, re.MULTILINE)
        if not (name_m and ver_m):
            continue
        dep = {
            "package":        name_m.group(1),
            "version":        ver_m.group(1),
            "version_source": "resolved",
        }
        # Edges for dependency-graph reachability. poetry.lock lists every
        # package's dependencies (incl. optional/extra-gated ones — kept: an
        # over-approximated edge can only over-flag), so edges are known.
        # Dev-only packages: poetry < 1.2 wrote `category = "dev"`; lock
        # format 2.1 writes `groups = [...]` (anything without "main" is not
        # installed for the main group).
        cat_m = re.search(r'^category\s*=\s*"([^"]+)"', head, re.MULTILINE)
        groups_m = re.search(r'^groups\s*=\s*\[([^\]]*)\]', head, re.MULTILINE)
        if cat_m and cat_m.group(1) == "dev":
            dep["scope"] = "dev"
        elif groups_m:
            groups = re.findall(r'"([^"]+)"', groups_m.group(1))
            if groups and "main" not in groups:
                dep["scope"] = "dev"
        deps_m = _POETRY_DEPS_RE.search(section)
        dep["depends_on"] = _POETRY_DEP_NAME_RE.findall(deps_m.group(1)) if deps_m else []
        src_m = _POETRY_SOURCE_RE.search(section)
        if src_m is None:
            dep["resolved_url"] = PYPI_DEFAULT_INDEX_URL
        else:
            block = src_m.group(1)
            type_m = re.search(r'^type\s*=\s*"([^"]+)"', block, re.MULTILINE)
            url_m  = re.search(r'^url\s*=\s*"([^"]+)"', block, re.MULTILINE)
            src_type = type_m.group(1) if type_m else ""
            src_url  = url_m.group(1) if url_m else ""
            if src_type == "git":
                dep["origin"] = "git"
                if src_url:
                    dep["resolved_url"] = src_url
            elif src_type in ("directory", "file"):
                dep["origin"] = "path"
            elif src_type == "url":
                dep["origin"] = "url"
                if src_url:
                    dep["resolved_url"] = src_url
            elif src_url:
                # "legacy" (an explicit index) — carry its URL; the consumer
                # decides public vs private by host.
                dep["resolved_url"] = src_url
        deps.append(dep)
    return deps


# ---- declared-dependency manifests (setup.py / setup.cfg / pyproject.toml) ----
#
# These record what a project ASKS for, not what got installed. Their value is
# twofold: OSV coverage for repos with no lockfile, and marking a package as a
# direct dependency (dependency_scope / the reachability graph's roots). All
# rows are version_source "declared"; a bare name with no version specifier is
# skipped, matching from_requirements_txt.

def _pep508_rows(specs: list[str], scope: str | None = None) -> list[dict]:
    rows = from_requirements_txt("\n".join(s for s in specs if isinstance(s, str)))
    if scope:
        for r in rows:
            r["scope"] = scope
    return rows


def _str_list(node, assigns: dict) -> list[str]:
    """Literal list/tuple of strings from an AST node, following one level of
    module-level name assignment (install_requires=REQUIRES)."""
    import ast
    if isinstance(node, ast.Name) and node.id in assigns:
        node = assigns[node.id]
    if isinstance(node, (ast.List, ast.Tuple)):
        return [e.value for e in node.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)]
    return []


def from_setup_py(text: str) -> list[dict]:
    """setup.py — install_requires / extras_require / tests_require, read
    statically from the AST (the file is NEVER executed). Only literal lists
    (or a module-level name bound to one) are understood; anything computed
    at runtime (reading requirements.txt, list comprehensions) is skipped."""
    import ast
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    assigns = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                and isinstance(stmt.targets[0], ast.Name):
            assigns[stmt.targets[0].id] = stmt.value
    deps: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
        if name != "setup":
            continue
        for kw in node.keywords:
            if kw.arg == "install_requires":
                deps += _pep508_rows(_str_list(kw.value, assigns))
            elif kw.arg == "tests_require":
                deps += _pep508_rows(_str_list(kw.value, assigns), scope="dev")
            elif kw.arg == "extras_require":
                val = assigns.get(kw.value.id, kw.value) if isinstance(kw.value, ast.Name) else kw.value
                if isinstance(val, ast.Dict):
                    for v in val.values:
                        deps += _pep508_rows(_str_list(v, assigns))
    return deps


def from_setup_cfg(text: str) -> list[dict]:
    """setup.cfg — [options] install_requires / tests_require and
    [options.extras_require] (one requirement per line)."""
    import configparser
    cp = configparser.ConfigParser(interpolation=None)
    try:
        cp.read_string(text)
    except configparser.Error:
        return []
    def lines(section: str, key: str) -> list[str]:
        if not cp.has_option(section, key):
            return []
        return [l.strip() for l in cp.get(section, key).splitlines() if l.strip()]
    deps = _pep508_rows(lines("options", "install_requires"))
    deps += _pep508_rows(lines("options", "tests_require"), scope="dev")
    if cp.has_section("options.extras_require"):
        for key in cp.options("options.extras_require"):
            deps += _pep508_rows(lines("options.extras_require", key))
    return deps


def _poetry_rows(table: dict, scope: str | None = None) -> list[dict]:
    from dkatchr.parsers._common import clean_declared_version
    rows = []
    for name, spec in (table or {}).items():
        if name.lower() == "python":
            continue
        if isinstance(spec, dict):
            if spec.get("git") or spec.get("path") or spec.get("url"):
                src = spec.get("git") or spec.get("path") or spec.get("url")
                origin = "git" if spec.get("git") else "path" if spec.get("path") else "url"
                row = {"package": name, "version": src, "version_source": "declared", "origin": origin}
                if scope:
                    row["scope"] = scope
                rows.append(row)
                continue
            spec = spec.get("version", "")
        if not isinstance(spec, str):
            continue
        ver = clean_declared_version(spec.split(",")[0])
        if not ver or ver == "*":
            continue
        row = {"package": name, "version": ver, "version_source": "declared"}
        if scope:
            row["scope"] = scope
        rows.append(row)
    return rows


def from_pyproject_toml(text: str) -> list[dict]:
    """pyproject.toml — PEP 621 [project] dependencies / optional-dependencies,
    PEP 735 [dependency-groups] (dev scope), and Poetry's
    [tool.poetry.dependencies] / [tool.poetry.group.*.dependencies] /
    [tool.poetry.dev-dependencies]. Needs tomllib (Python 3.11+); on 3.10 the
    file is skipped."""
    try:
        import tomllib
    except ImportError:  # Python 3.10
        return []
    try:
        data = tomllib.loads(text)
    except Exception:
        return []
    deps: list[dict] = []
    project = data.get("project") or {}
    deps += _pep508_rows(project.get("dependencies") or [])
    for extra in (project.get("optional-dependencies") or {}).values():
        deps += _pep508_rows(extra or [])
    for group in (data.get("dependency-groups") or {}).values():
        deps += _pep508_rows([g for g in (group or []) if isinstance(g, str)], scope="dev")
    poetry = (data.get("tool") or {}).get("poetry") or {}
    deps += _poetry_rows(poetry.get("dependencies"))
    deps += _poetry_rows(poetry.get("dev-dependencies"), scope="dev")
    for gname, group in (poetry.get("group") or {}).items():
        scope = None if gname == "main" else "dev"
        deps += _poetry_rows((group or {}).get("dependencies"), scope=scope)
    return deps
