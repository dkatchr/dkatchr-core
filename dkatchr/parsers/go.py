"""Go modules: go.mod, go.sum."""

import re


def from_go_mod(text: str) -> list[dict]:
    deps = []
    # Single-line: `require module v1.2.3`
    for m in re.finditer(r"^require\s+(\S+)\s+(v\S+)", text, re.MULTILINE):
        deps.append({"package": m.group(1), "version": m.group(2), "version_source": "declared"})
    # Multi-line: `require ( ... )`
    for block in re.finditer(r"require\s*\(([^)]*)\)", text, re.DOTALL):
        for line in block.group(1).splitlines():
            line = line.split("//", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("v"):
                deps.append({
                    "package":        parts[0],
                    "version":        parts[1],
                    "version_source": "declared",
                })
    return deps


def from_go_sum(text: str) -> list[dict]:
    """go.sum: 'module version h1:hash' lines, plus 'module version/go.mod h1:hash' (skipped)."""
    deps = []
    seen = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        name, ver = parts[0], parts[1]
        if ver.endswith("/go.mod"):
            continue
        key = (name, ver)
        if key not in seen:
            seen.add(key)
            deps.append({"package": name, "version": ver, "version_source": "resolved"})
    return deps
