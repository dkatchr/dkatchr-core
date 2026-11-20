"""Maven / Gradle: pom.xml, gradle.lockfile."""

import os
import re
import xml.etree.ElementTree as ET

from dkatchr.parsers._common import clean_declared_version, strip_xml_namespace


_PROP_RE = re.compile(r"\$\{([^}]+)\}")


def _child_text(elem, name: str) -> str | None:
    for child in elem:
        if strip_xml_namespace(child.tag) == name and child.text:
            return child.text.strip()
    return None


def _child(elem, name: str):
    for child in elem:
        if strip_xml_namespace(child.tag) == name:
            return child
    return None


def _read_pom(text: str) -> dict | None:
    """The parts of a pom the effective-model resolution needs. None on bad XML."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    parent = _child(root, "parent")
    par = None
    if parent is not None:
        par = {"g": _child_text(parent, "groupId"), "a": _child_text(parent, "artifactId"),
               "v": _child_text(parent, "version"),
               "rel": _child_text(parent, "relativePath")}
    props: dict[str, str] = {}
    pe = _child(root, "properties")
    if pe is not None:
        for prop in pe:
            props[strip_xml_namespace(prop.tag)] = (prop.text or "").strip()
    managed = []
    dm = _child(root, "dependencyManagement")
    deps_el = _child(dm, "dependencies") if dm is not None else None
    for d in (list(deps_el) if deps_el is not None else []):
        if strip_xml_namespace(d.tag) != "dependency":
            continue
        managed.append({"g": _child_text(d, "groupId"), "a": _child_text(d, "artifactId"),
                        "v": _child_text(d, "version"), "scope": _child_text(d, "scope"),
                        "type": _child_text(d, "type")})
    deps = []
    for d in root.iter():
        if strip_xml_namespace(d.tag) != "dependency":
            continue
        deps.append({"g": _child_text(d, "groupId"), "a": _child_text(d, "artifactId"),
                     "v": _child_text(d, "version"), "scope": _child_text(d, "scope")})
    return {"g": _child_text(root, "groupId") or (par or {}).get("g"),
            "a": _child_text(root, "artifactId"),
            "v": _child_text(root, "version") or (par or {}).get("v"),
            "parent": par, "props": props, "managed": managed, "deps": deps}


def _substitute(value: str | None, props: dict[str, str]) -> str:
    """Resolve ${...} references, following chains (a property defined in terms
    of another) up to a fixed depth. Unknown references are left in place."""
    if not value:
        return ""
    for _ in range(10):
        new = _PROP_RE.sub(lambda m: props.get(m.group(1), m.group(0)), value)
        if new == value:
            break
        value = new
    return value


def _dep_rows(model: dict, props: dict[str, str], managed: dict[tuple, str]) -> list[dict]:
    rows = []
    for d in model["deps"]:
        gid, aid = _substitute(d["g"], props), _substitute(d["a"], props)
        if not gid or not aid or "${" in gid or "${" in aid:
            continue
        ver = _substitute(d["v"], props) if d["v"] else managed.get((gid, aid), "")
        ver = clean_declared_version(ver)
        # Still unresolved: the version comes from a parent / BOM outside the
        # repo. A literal "${x}" is not a version — querying it is junk.
        if not ver or "${" in ver:
            continue
        row = {"package": f"{gid}:{aid}", "version": ver, "version_source": "declared"}
        if (d.get("scope") or "").strip() == "test":
            row["scope"] = "dev"
        rows.append(row)
    return rows


def from_pom_xml(text: str) -> list[dict]:
    """Parse one pom.xml on its own: ${property} references resolve against the
    pom's own <properties>, and versionless dependencies against its own
    <dependencyManagement>. Use resolve_maven_project() when the repo's other
    poms are available — parents usually carry the properties."""
    model = _read_pom(text)
    if model is None:
        return []
    props = _base_props(model, {})
    managed = {}
    for m in model["managed"]:
        g, a = _substitute(m["g"], props), _substitute(m["a"], props)
        if m["v"]:
            managed[(g, a)] = _substitute(m["v"], props)
    return _dep_rows(model, props, managed)


def _base_props(model: dict, inherited: dict[str, str]) -> dict[str, str]:
    props = dict(inherited)
    par = model.get("parent") or {}
    if par.get("v"):
        props["project.parent.version"] = props["parent.version"] = par["v"]
    if par.get("g"):
        props["project.parent.groupId"] = par["g"]
    for key, val in (("groupId", model["g"]), ("artifactId", model["a"]), ("version", model["v"])):
        if val:
            props[f"project.{key}"] = props[f"pom.{key}"] = val
            if key == "version":
                props["version"] = val
    props.update(model["props"])
    return props


def resolve_maven_project(poms: dict[str, str]) -> dict[str, list[dict]]:
    """Inventory rows for every pom.xml of ONE repo, resolved against the repo's
    own Maven project structure: each pom inherits its parent's properties and
    <dependencyManagement> (parent found by <relativePath>, default
    "../pom.xml", else by groupId:artifactId among the repo's poms), and
    import-scope BOMs that live in the repo contribute their managed versions.

    Pure: {path: pom text} in, {path: rows} out. Parents or BOMs published
    elsewhere (spring-boot-starter-parent, a company parent on a private
    registry) are NOT fetched, so their properties stay unresolved and those
    dependencies are skipped rather than reported with a "${...}" version."""
    models = {}
    for path, text in poms.items():
        m = _read_pom(text)
        if m is not None:
            models[path] = m
    by_ga = {}
    for path, m in models.items():
        if m["g"] and m["a"]:
            by_ga.setdefault((m["g"], m["a"]), path)

    def parent_path(path: str) -> str | None:
        par = models[path]["parent"]
        if not par:
            return None
        rel = par.get("rel")
        if rel is None:
            rel = "../pom.xml"
        if rel:
            base = os.path.dirname(path)
            cand = os.path.normpath(os.path.join(base, rel))
            if not cand.endswith(".xml"):
                cand = os.path.join(cand, "pom.xml")
            pm = models.get(cand)
            if pm is not None and (pm["a"] == par.get("a")):
                return cand
        found = by_ga.get((par.get("g"), par.get("a")))
        return found if found != path else None

    effective: dict[str, tuple[dict, dict]] = {}

    def resolve(path: str, stack: frozenset = frozenset()) -> tuple[dict, dict]:
        if path in effective:
            return effective[path]
        model = models[path]
        props, managed = {}, {}
        ppath = parent_path(path)
        if ppath and ppath not in stack:
            pprops, pmanaged = resolve(ppath, stack | {path})
            props, managed = dict(pprops), dict(pmanaged)
        props = _base_props(model, props)
        for m in model["managed"]:
            g, a = _substitute(m["g"], props), _substitute(m["a"], props)
            v = _substitute(m["v"], props)
            if (m.get("scope") or "") == "import" and (m.get("type") or "") == "pom":
                bom = by_ga.get((g, a))
                if bom and bom != path and bom not in stack:
                    managed.update(resolve(bom, stack | {path})[1])
                continue
            if g and a and v and "${" not in v:
                managed[(g, a)] = v
        effective[path] = (props, managed)
        return effective[path]

    out = {}
    for path, model in models.items():
        props, managed = resolve(path)
        out[path] = _dep_rows(model, props, managed)
    return out


def from_gradle_lockfile(text: str) -> list[dict]:
    """gradle.lockfile: lines like 'group:artifact:version=config1,config2'."""
    deps = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        m = re.match(r"^([^:=\s]+):([^:=\s]+):([^=\s]+)=", line)
        if not m:
            continue
        gid, aid, ver = m.group(1), m.group(2), m.group(3)
        name = f"{gid}:{aid}"
        key = (name, ver)
        if key not in seen:
            seen.add(key)
            dep = {"package": name, "version": ver, "version_source": "resolved"}
            # Gradle lists the configurations that pulled the module in; only
            # test* configurations means it never reaches the runtime classpath.
            configs = [c for c in line.split("=", 1)[1].split(",") if c.strip()]
            if configs and all(c.strip().startswith("test") for c in configs):
                dep["scope"] = "dev"
            deps.append(dep)
    return deps
