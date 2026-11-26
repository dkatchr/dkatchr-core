"""
Runtime & container-image references — which language runtimes and base
images a repo declares, read from repo files only (no I/O here).

WHY: library manifests never name the interpreter / toolchain the code runs on,
so a Ruby/Node/Python/Go/Java/.NET/PHP/Rust/Elixir/Erlang runtime CVE (or an
end-of-life runtime) was invisible. Runtime facts live in version files,
project files, Dockerfiles, compose / Kubernetes / Helm YAML and CI workflows.

Output rows (same shape as other inventory rows, plus a few extra keys):
  ecosystem "Runtime"        package = runtime id (dkatchr.config.RUNTIMES key)
  ecosystem "ContainerImage" package = canonical image repository
                             ("docker.io/library/ruby"), version = tag or digest
  version_source:
    exact      a full version ("3.2.2")
    minimum    an imprecise spec reported at its lowest version ("18", "~> 3.2",
               ">=3.9") — "may already be patched"
    image_tag  a container image reference (resolved later by the image
               resolver, see dkatchr.core.runtime_inventory)
  spec        the raw text, spec_kind "exact" | "line" (pins a release line:
              "18", "3.2", "~> 3.2") | "range" (open lower bound: ">=3.9")
  line        1-based line number of the reference
  scope "dev" CI workflows and non-final Dockerfile stages (build-only)

A file that is ALSO a library manifest (package.json, go.mod, Gemfile, ...)
keeps its library parser; this module is a second, independent extractor
(dkatchr.core.inventory.extract_file_inventory runs both).

What this module does NOT do: resolve floating tags, look up advisories or
end-of-life dates (dkatchr.core.runtime_inventory / runtime_findings).
"""

import json
import os
import re

from dkatchr.config import (
    THIRD_PARTY_DIRS,
    IMAGE_REGISTRY_DEFAULT,
    RUNTIME_DEPLOY_PATH_HINTS,
    RUNTIME_VERSION_FILES,
    RUNTIMES,
)

_NUM = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")
_ASDF_TO_RUNTIME = {alias: rt for rt, d in RUNTIMES.items() for alias in d["asdf"]}
_CI_KEYS = {"node": "node", "python": "python", "ruby": "ruby", "go": "go", "java": "java",
            "dotnet": "dotnet", "php": "php", "elixir": "elixir", "otp": "erlang", "erlang": "erlang",
            "rust": "rust"}

_DOCKERFILE = re.compile(r"^(?:Dockerfile|Containerfile)(?:[.-][\w.-]+)?$|.+\.(?:dockerfile|Dockerfile)$")
_COMPOSE = re.compile(r"^(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml$")
_YAML = re.compile(r".+\.ya?ml$")
_PROJECT = (".csproj", ".fsproj", ".vbproj")


# ---- file selection -----------------------------------------------------------

# Third-party code vendored into the repo: a dependency's package.json
# `engines` or go.mod `go` line says what THAT library supports, not what this
# repo runs on.
_THIRD_PARTY_DIRS = THIRD_PARTY_DIRS


def is_runtime_source(path: str) -> bool:
    """True when this repo path can name a runtime version or a container image."""
    if _THIRD_PARTY_DIRS & set(path.split("/")[:-1]):
        return False
    base = os.path.basename(path)
    if base in RUNTIME_VERSION_FILES or base.endswith(_PROJECT):
        return True
    if _DOCKERFILE.match(base) or _COMPOSE.match(base):
        return True
    if not _YAML.match(base):
        return False
    low = path.lower()
    if "/.github/workflows/" in f"/{low}":
        return True
    if base.startswith("values") or base == "Chart.yaml":
        return True
    segs = low.split("/")[:-1]
    return any(h in seg for seg in segs for h in RUNTIME_DEPLOY_PATH_HINTS)


# ---- version specs ------------------------------------------------------------

def parse_spec(spec: str) -> tuple[str, str, str] | None:
    """(version, version_source, spec_kind, precision) for a version spec, or None
    when it names no concrete version (lts/*, stable, latest, system, a
    template). precision = numeric components given ("3.x" -> 1, "3.12" -> 2)."""
    s = (spec or "").strip().strip("'\"").strip()
    if not s or "${" in s or "{{" in s:
        return None
    low = s.lower()
    if low in ("stable", "latest", "nightly", "beta", "system", "lts", "lts/*", "node", "current", "*"):
        return None
    low = re.sub(r"^(?:ruby|python|go|jdk|openjdk|temurin|node|v)[-@]?(?=\d)", "", low)
    low = re.sub(r"^(\d+)u(\d+)", r"\1.0.\2", low)          # Java 8: 8u392 -> 8.0.392
    if re.match(r"^\s*<", low):
        return None                                # upper bound only — nothing to report
    is_range = bool(re.match(r"^\s*>", low)) and "<" not in low
    m = _NUM.search(low)
    if not m:
        return None
    major, minor, patch = m.group(1), m.group(2), m.group(3)
    precision = 1 + (minor is not None) + (patch is not None)
    prefix = low[:m.start()].strip()
    exact = (patch is not None and prefix in ("", "=", "==") and not re.search(r"\.[x*]", low))
    version = ".".join([major, minor or "0", patch or "0"])
    # Java's 1.8 notation is Java 8.
    if major == "1" and minor in ("5", "6", "7", "8") and not exact:
        version = f"{minor}.0.0"
        precision = 1
    if exact:
        return version, "exact", "exact", precision
    return version, "minimum", ("range" if is_range else "line"), precision


def _row(path, runtime, spec, line, scope=None, **extra) -> dict | None:
    p = parse_spec(spec)
    if not p or runtime not in RUNTIMES:
        return None
    version, source, kind, precision = p
    row = {"file": path, "ecosystem": "Runtime", "package": runtime, "version": version,
           "version_source": source, "origin": "registry", "spec": str(spec).strip().strip("'\""),
           "spec_kind": kind, "precision": precision, "line": line}
    if scope == "dev":
        row["scope"] = "dev"
    row.update(extra)
    return row


def _line_of(content: str, idx: int) -> int:
    return content.count("\n", 0, idx) + 1


# ---- image references -----------------------------------------------------------

def parse_image_ref(ref: str) -> dict | None:
    """{registry, repository, tag, digest, ref} for an image reference."""
    r = (ref or "").strip().strip("'\"")
    if not r or "$" in r or "{{" in r or r.lower() == "scratch":
        return None
    digest = None
    if "@" in r:
        r, digest = r.split("@", 1)
    tag = None
    last = r.rsplit("/", 1)[-1]
    if ":" in last:
        r, tag = r.rsplit(":", 1)
    parts = r.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry, repo = parts[0], "/".join(parts[1:])
    else:
        registry, repo = IMAGE_REGISTRY_DEFAULT, r
    if registry == IMAGE_REGISTRY_DEFAULT and "/" not in repo:
        repo = f"library/{repo}"
    if not re.match(r"^[a-z0-9][a-z0-9._/-]*$", repo):
        return None
    return {"registry": registry, "repository": repo, "tag": tag or ("" if digest else "latest"),
            "digest": digest, "ref": f"{registry}/{repo}" + (f":{tag}" if tag else "")
            + (f"@{digest}" if digest else "")}


def _image_row(path, ref, line, scope=None, stage=None) -> dict | None:
    img = parse_image_ref(ref)
    if not img:
        return None
    row = {"file": path, "ecosystem": "ContainerImage",
           "package": f"{img['registry']}/{img['repository']}",
           "version": img["digest"] or img["tag"], "version_source": "image_tag",
           "origin": "registry", "image": img["ref"], "spec": ref.strip(), "line": line}
    if stage:
        row["stage"] = stage
    if scope == "dev":
        row["scope"] = "dev"
    return row


# ---- per-format extractors ---------------------------------------------------------

def _logical_lines(content: str):
    """(start line number, text) per Dockerfile instruction, joining '\\' continuations."""
    buf, start = [], None
    for n, raw in enumerate(content.splitlines(), 1):
        if start is None:
            start = n
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            buf.append(stripped[:-1])
            continue
        buf.append(stripped)
        yield start, " ".join(buf)
        buf, start = [], None
    if buf:
        yield start, " ".join(buf)


def _dockerfile(path: str, content: str) -> list[dict]:
    args: dict[str, str] = {}
    froms: list[tuple[str, int, str | None]] = []     # (image ref, line, stage alias)
    stages: set[str] = set()

    def sub(v: str) -> str:
        v = re.sub(r"\$\{(\w+):-([^}]*)\}", lambda x: args.get(x.group(1)) or x.group(2), v)
        v = re.sub(r"\$\{(\w+)\}", lambda x: args.get(x.group(1), x.group(0)), v)
        return re.sub(r"\$(\w+)", lambda x: args.get(x.group(1), x.group(0)), v)

    for line, text in _logical_lines(content):
        s = text.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"(?i)^ARG\s+([A-Za-z_]\w*)=(\S*)", s)
        if m:
            args.setdefault(m.group(1), m.group(2).strip("'\""))
            continue
        m = re.match(r"(?i)^FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", s)
        if not m:
            continue
        froms.append((sub(m.group(1)), line, m.group(2)))
        if m.group(2):
            stages.add(m.group(2).lower())
    rows: list[dict] = []
    for i, (ref, line, _alias) in enumerate(froms):
        if ref.lower() in stages:
            continue                                   # FROM <earlier stage>
        final = i == len(froms) - 1
        r = _image_row(path, ref, line, scope=None if final else "dev",
                       stage="final" if final else "build")
        if r:
            rows.append(r)
    return rows


# The value must sit on the SAME line as its key ([ \t]*, never \s*): a bare
# `repository:` / `image:` with a nested mapping below it (a CRD schema, a Helm
# values block) would otherwise read the next line's KEY as an image name.
_IMAGE_KEY = re.compile(r"^([ \t]*)-?[ \t]*image:[ \t]*[\"']?([^\s\"'#]+)[\"']?[ \t]*(?:#.*)?$", re.M)
_HELM_REPO = re.compile(r"^([ \t]*)repository:[ \t]*[\"']?([^\s\"'#]+)", re.M)
_HELM_TAG = re.compile(r"^[ \t]*tag:[ \t]*[\"']?([^\s\"'#]+)", re.M)
_CRD_KIND = re.compile(r"^kind:[ \t]*CustomResourceDefinition[ \t]*$", re.M)


def _yaml_images(path: str, content: str) -> list[dict]:
    rows = []
    crd_lines = _crd_line_ranges(content)
    for m in _IMAGE_KEY.finditer(content):
        val = m.group(2)
        if val in ("|", ">") or val.endswith(":"):
            continue
        r = _image_row(path, val, _line_of(content, m.start(2)))
        if r:
            rows.append(r)
    # Helm values: image: {repository: x, tag: y}
    for m in _HELM_REPO.finditer(content):
        nxt = content[m.end():m.end() + 400]
        t = _HELM_TAG.search(nxt)
        ref = m.group(2) + (f":{t.group(1)}" if t else "")
        r = _image_row(path, ref, _line_of(content, m.start(2)))
        if r:
            rows.append(r)
    if crd_lines:
        rows = [r for r in rows if not any(a <= (r.get("line") or 0) <= b for a, b in crd_lines)]
    return rows


def _crd_line_ranges(content: str) -> list[tuple[int, int]]:
    """Line ranges of the CustomResourceDefinition documents in a YAML stream.
    A CRD is an API schema: its `image` / `repository` entries describe fields,
    they never name an image that is deployed (other documents in the same file
    — an install bundle's Deployments — still count)."""
    if not _CRD_KIND.search(content):
        return []
    ranges, start, lines = [], 1, content.splitlines()
    bounds = [i + 1 for i, ln in enumerate(lines) if ln.startswith("---")] + [len(lines) + 1]
    for end in bounds:
        doc = "\n".join(lines[start - 1:end - 1])
        if _CRD_KIND.search(doc):
            ranges.append((start, end - 1))
        start = end + 1
    return ranges


def _workflow(path: str, content: str) -> list[dict]:
    rows = []
    pat = re.compile(r"^\s*-?\s*(node|python|ruby|go|java|dotnet|php|elixir|otp|erlang|rust)"
                     r"(?:-version)?\s*:\s*(.+?)\s*(?:#.*)?$", re.M)
    for m in pat.finditer(content):
        key, val = m.group(1), m.group(2).strip()
        if "-version" not in m.group(0) and not val.startswith("["):
            continue                                   # bare 'node:' only counts as a matrix list
        values = [v.strip() for v in val.strip("[]").split(",")] if val.startswith("[") else [val]
        for v in values:
            r = _row(path, _CI_KEYS[key], v, _line_of(content, m.start()), scope="dev")
            if r:
                rows.append(r)
    return rows


def _simple(path, runtime, content) -> list[dict]:
    for i, ln in enumerate(content.splitlines(), 1):
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            r = _row(path, runtime, ln, i)
            return [r] if r else []
    return []


def _search(path, runtime, content, pattern, flags=re.M) -> list[dict]:
    rows = []
    for m in re.finditer(pattern, content, flags):
        r = _row(path, runtime, m.group(1), _line_of(content, m.start(1)))
        if r:
            rows.append(r)
    return rows


def _json_get(content: str, *keys):
    try:
        d = json.loads(content)
    except (ValueError, TypeError):
        return None
    for k in keys:
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d


def _json_rows(path, runtime, content, keys, needle) -> list[dict]:
    val = _json_get(content, *keys)
    if not isinstance(val, str):
        return []
    idx = content.find(needle)
    r = _row(path, runtime, val, _line_of(content, idx) if idx >= 0 else 1)
    return [r] if r else []


def extract_runtime_inventory(path: str, content: str) -> list[dict]:
    """Runtime / image rows for one repo file (empty for anything else)."""
    if not content or not is_runtime_source(path):
        return []
    base = os.path.basename(path)
    try:
        rows = _dispatch(path, base, content)
    except Exception:  # noqa: BLE001 — one malformed file never breaks a scan
        return []
    return [r for r in rows if r]


def _dispatch(path: str, base: str, content: str) -> list[dict]:
    if _DOCKERFILE.match(base):
        return _dockerfile(path, content)
    if base == ".ruby-version":
        return _simple(path, "ruby", content)
    if base in (".nvmrc", ".node-version"):
        return _simple(path, "node", content)
    if base == ".python-version":
        return _simple(path, "python", content)
    if base == ".java-version":
        return _simple(path, "java", content)
    if base == ".tool-versions":
        rows = []
        for i, ln in enumerate(content.splitlines(), 1):
            parts = ln.split("#", 1)[0].split()
            if len(parts) >= 2 and parts[0] in _ASDF_TO_RUNTIME:
                spec = parts[1]
                if parts[0] == "elixir":
                    spec = spec.split("-otp-")[0]
                rows.append(_row(path, _ASDF_TO_RUNTIME[parts[0]], spec, i))
        return rows
    if base == ".sdkmanrc":
        return _search(path, "java", content, r"^\s*java\s*=\s*(\S+)")
    if base == "go.mod":
        rows = _search(path, "go", content, r"^go\s+(\d[\w.]*)\s*$")
        rows += _search(path, "go", content, r"^toolchain\s+go(\d[\w.]*)\s*$")
        return rows
    if base == "package.json":
        return _json_rows(path, "node", content, ("engines", "node"), '"node"')
    if base == "composer.json":
        return _json_rows(path, "php", content, ("require", "php"), '"php"')
    if base == "global.json":
        # An SDK version (8.0.100) is not a runtime version: keep the release line.
        rows = _json_rows(path, "dotnet", content, ("sdk", "version"), '"version"')
        for r in rows:
            r.update(version=".".join(r["version"].split(".")[:2]) + ".0",
                     version_source="minimum", spec_kind="line", precision=2)
        return rows
    if base == "Gemfile":
        return _search(path, "ruby", content, r"^\s*ruby\s+[\"']([^\"']+)[\"']")
    if base == "pyproject.toml":
        rows = _search(path, "python", content, r"^\s*requires-python\s*=\s*[\"']([^\"']+)[\"']")
        rows += _search(path, "python", content, r"^\s*python\s*=\s*[\"']([^\"']+)[\"']")
        return rows
    if base in ("rust-toolchain", "rust-toolchain.toml"):
        m = re.search(r"channel\s*=\s*[\"']([^\"']+)[\"']", content)
        spec = m.group(1) if m else content.strip().splitlines()[0] if content.strip() else ""
        r = _row(path, "rust", spec, _line_of(content, m.start(1)) if m else 1)
        return [r] if r else []
    if base == "mix.exs":
        return _search(path, "elixir", content, r"elixir:\s*\"([^\"]+)\"")
    if base == "pom.xml":
        return _search(path, "java", content,
                       r"<(?:java\.version|maven\.compiler\.release|maven\.compiler\.source|"
                       r"maven\.compiler\.target|release)>\s*([\d.]+)\s*</")[:1]
    if base in ("build.gradle", "build.gradle.kts"):
        rows = _search(path, "java", content, r"JavaLanguageVersion\.of\(\s*(\d+)\s*\)")
        rows += _search(path, "java", content, r"JavaVersion\.VERSION_(\d+(?:_\d+)?)")
        rows += _search(path, "java", content, r"sourceCompatibility\s*=\s*[\"']?([\d.]+)")
        for r in rows:
            if r:
                r["spec"] = r["spec"].replace("_", ".")
        return rows[:1]
    if base.endswith(_PROJECT):
        rows = []
        for m in re.finditer(r"<TargetFrameworks?>([^<]+)</", content):
            for tfm in m.group(1).split(";"):
                mm = re.match(r"^\s*(?:net|netcoreapp)(\d+\.\d+)", tfm.strip())
                if mm:                                  # net48 (.NET Framework) is a different product
                    rows.append(_row(path, "dotnet", mm.group(1), _line_of(content, m.start(1))))
        return rows
    if _COMPOSE.match(base):
        return _yaml_images(path, content)
    low = path.lower()
    if "/.github/workflows/" in f"/{low}":
        return _workflow(path, content) + [
            dict(r, scope="dev") for r in _yaml_images(path, content)]
    return _yaml_images(path, content)
