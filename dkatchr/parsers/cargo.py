"""crates.io: Cargo.lock."""

import re


def from_cargo_lock(text: str) -> list[dict]:
    """Cargo.lock — TOML [[package]] sections with name/version.

    Dependency `origin` comes from each section's `source` line:
      - absent            → "path" (workspace members and path deps carry no source)
      - "git+…"           → "git"
      - "registry+…" / "sparse+…" → registry (no origin key set)
    Repos with only a Cargo.toml (no Cargo.lock) carry no origin signal —
    documented limitation.

    `resolved_url` (Dependency Confusion Exposure signal): the source line's
    URL part with its registry+/sparse+/git+ protocol prefix stripped — e.g.
    "registry+https://github.com/rust-lang/crates.io-index" carries
    "https://github.com/rust-lang/crates.io-index". Path deps have no URL.
    """
    deps = []
    sections = re.split(r"\n\[\[package\]\]\s*\n", "\n" + text)
    for section in sections[1:]:
        section = re.split(r"\n\[\[?", section, maxsplit=1)[0]
        name_m = re.search(r'^name\s*=\s*"([^"]+)"', section, re.MULTILINE)
        ver_m  = re.search(r'^version\s*=\s*"([^"]+)"', section, re.MULTILINE)
        if not (name_m and ver_m):
            continue
        dep = {
            "package":        name_m.group(1),
            "version":        ver_m.group(1),
            "version_source": "resolved",
        }
        src_m = re.search(r'^source\s*=\s*"([^"]+)"', section, re.MULTILINE)
        if src_m is None:
            dep["origin"] = "path"
        else:
            src = src_m.group(1)
            for prefix in ("registry+", "sparse+", "git+"):
                if src.startswith(prefix):
                    if prefix == "git+":
                        dep["origin"] = "git"
                    url = src[len(prefix):]
                    if url:
                        dep["resolved_url"] = url
                    break
            # An unrecognized source protocol → registry default, no URL.
        deps.append(dep)
    return deps
