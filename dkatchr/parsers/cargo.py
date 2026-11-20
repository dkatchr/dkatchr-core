"""crates.io: Cargo.lock."""

import re

# `dependencies = [ "a", "b 1.2.3", "c 0.1.0 (registry+https://…)" ]` — the
# first token of each quoted entry is the crate name.
_CARGO_DEPS_RE = re.compile(r'^dependencies\s*=\s*\[(.*?)\]', re.MULTILINE | re.DOTALL)


def from_cargo_lock(text: str) -> list[dict]:
    """Cargo.lock — TOML [[package]] sections with name/version.

    Dependency `origin` comes from each section's `source` line:
      - absent            → "path" (workspace members and path deps carry no source)
      - "git+…"           → "git"
      - "registry+…" / "sparse+…" → registry (no origin key set)
    Repos with only a Cargo.toml (no Cargo.lock) carry no origin signal —
    documented limitation.

    `depends_on` (dependency-graph reachability): the crate names in the
    section's `dependencies = [...]` array (empty list when absent — Cargo.lock
    records every package's full dependency list, so edges are always known).

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
        deps_m = _CARGO_DEPS_RE.search(section)
        dep["depends_on"] = (
            [e.split()[0] for e in re.findall(r'"([^"]+)"', deps_m.group(1)) if e.split()]
            if deps_m else []
        )
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
