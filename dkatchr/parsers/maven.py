"""Maven / Gradle: pom.xml, gradle.lockfile."""

import re
import xml.etree.ElementTree as ET

from dkatchr.parsers._common import clean_declared_version, strip_xml_namespace


def from_pom_xml(text: str) -> list[dict]:
    """Parse Maven pom.xml. Resolves ${property} references where possible."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []

    # Build a property map for ${...} substitution.
    props: dict[str, str] = {}
    for child in root:
        tag = strip_xml_namespace(child.tag)
        if tag == "properties":
            for prop in child:
                if prop.text:
                    props[strip_xml_namespace(prop.tag)] = prop.text.strip()
        elif tag == "version" and child.text:
            props["project.version"] = child.text.strip()

    def resolve(s: str) -> str:
        if not s:
            return s
        return re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), s)

    deps: list[dict] = []
    for elem in root.iter():
        if strip_xml_namespace(elem.tag) != "dependency":
            continue
        gid = aid = ver = None
        for child in elem:
            t = strip_xml_namespace(child.tag)
            if t == "groupId" and child.text:
                gid = child.text.strip()
            elif t == "artifactId" and child.text:
                aid = child.text.strip()
            elif t == "version" and child.text:
                ver = child.text.strip()
        if not (gid and aid):
            continue
        name = f"{resolve(gid)}:{resolve(aid)}"
        ver_resolved = clean_declared_version(resolve(ver) if ver else "")
        if ver_resolved:
            deps.append({"package": name, "version": ver_resolved, "version_source": "declared"})
    return deps


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
            deps.append({"package": name, "version": ver, "version_source": "resolved"})
    return deps
