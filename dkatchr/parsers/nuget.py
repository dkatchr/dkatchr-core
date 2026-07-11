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
    for tfm, pkgs in (data.get("dependencies") or {}).items():
        if not isinstance(pkgs, dict):
            continue
        for name, meta in pkgs.items():
            if not isinstance(meta, dict):
                continue
            ver = meta.get("resolved", "")
            if name and ver:
                key = (name, ver)
                if key not in seen:
                    seen.add(key)
                    deps.append({"package": name, "version": ver, "version_source": "resolved"})
    return deps
