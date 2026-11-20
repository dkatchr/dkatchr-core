"""NuGet: *.csproj/*.fsproj/*.vbproj (PackageReference), packages.config (legacy), packages.lock.json."""

import json
import xml.etree.ElementTree as ET

from dkatchr.parsers._common import clean_declared_version, strip_xml_namespace


def from_csproj(text: str) -> list[dict]:
    """Parse <PackageReference Include="X" Version="Y" /> items."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    deps = []
    for elem in root.iter():
        if strip_xml_namespace(elem.tag) != "PackageReference":
            continue
        # MSBuild tolerates both casings on attributes
        name = elem.get("Include") or elem.get("include")
        ver  = elem.get("Version") or elem.get("version")
        if not ver:
            for child in elem:
                if strip_xml_namespace(child.tag).lower() == "version" and child.text:
                    ver = child.text.strip()
                    break
        if name and ver:
            cleaned = clean_declared_version(ver)
            if cleaned:
                deps.append({"package": name, "version": cleaned, "version_source": "declared"})
    return deps


def from_packages_config(text: str) -> list[dict]:
    """Legacy NuGet: <package id="X" version="Y" /> in packages.config."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    deps = []
    for elem in root.iter():
        if strip_xml_namespace(elem.tag) != "package":
            continue
        name = elem.get("id")
        ver  = elem.get("version")
        if name and ver:
            deps.append({"package": name, "version": ver, "version_source": "declared"})
    return deps


def from_packages_lock_json(text: str) -> list[dict]:
    """packages.lock.json — resolved versions per target framework."""
    try:
        data = json.loads(text)
    except Exception:
        return []
    deps = []
    seen = set()
    # `depends_on` (dependency-graph reachability): each entry's own
    # `dependencies` map, unioned across target frameworks per package name.
    edges: dict[str, set[str]] = {}
    for tfm, pkgs in (data.get("dependencies") or {}).items():
        if not isinstance(pkgs, dict):
            continue
        for name, meta in pkgs.items():
            if not isinstance(meta, dict):
                continue
            if name:
                edges.setdefault(name, set()).update(
                    (meta.get("dependencies") or {}).keys()
                    if isinstance(meta.get("dependencies"), dict) else ())
            ver = meta.get("resolved", "")
            if name and ver:
                key = (name, ver)
                if key not in seen:
                    seen.add(key)
                    deps.append({"package": name, "version": ver, "version_source": "resolved"})
    for dep in deps:
        dep["depends_on"] = sorted(edges.get(dep["package"], set()))
    return deps


def from_deps_json(text: str) -> list[dict]:
    """*.deps.json — the .NET runtime dependency manifest written next to a
    built assembly (and often committed). Unlike a .csproj it records the FULL
    resolved graph, transitive packages included: `libraries` maps
    "Name/Version" to {type: package|project|reference}, and each target's
    entry lists that library's own `dependencies`. Only type "package" rows are
    NuGet packages; "project" entries are in-repo projects (skipped, their own
    .csproj is parsed) and "reference" entries are framework assemblies."""
    try:
        data = json.loads(text)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    libraries = data.get("libraries") or {}
    edges: dict[str, set[str]] = {}
    for target in (data.get("targets") or {}).values():
        if not isinstance(target, dict):
            continue
        for key, meta in target.items():
            if not isinstance(meta, dict) or "/" not in key:
                continue
            name = key.rsplit("/", 1)[0]
            deps_map = meta.get("dependencies")
            edges.setdefault(name, set()).update(deps_map.keys() if isinstance(deps_map, dict) else ())
    deps = []
    seen = set()
    for key, meta in libraries.items():
        if not isinstance(meta, dict) or meta.get("type") != "package" or "/" not in key:
            continue
        name, ver = key.rsplit("/", 1)
        if not name or not ver or (name, ver) in seen:
            continue
        seen.add((name, ver))
        deps.append({"package": name, "version": ver, "version_source": "resolved",
                     "depends_on": sorted(edges.get(name, set()))})
    return deps
