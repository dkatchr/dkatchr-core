"""
Runtime inventory from container images + runtime findings — pure logic.

expand_image_runtimes(): each ContainerImage row (dkatchr.parsers.runtime)
yields the runtime(s) the image ships and its Linux distribution:
  * resolved — the injected resolver read the image's environment from the
    registry (RUBY_VERSION=3.2.11): version_source "resolved_tag", exact;
  * fallback — the image is an official runtime image (config.RUNTIMES
    "images") and the resolver could not answer: the tag text ("3.2-slim")
    reported at its minimum, version_source "minimum";
  * distro — debian/ubuntu/alpine images and runtime-image tags naming a
    distro (bookworm, alpine3.19, jammy) become ecosystem "OS" rows, used for
    end-of-life checks (their package CVEs are image scanning, release B).
  Build-stage images give dev-only runtimes, except runtimes that compile
  their standard library into the binary (config.RUNTIMES "bakes_stdlib").

runtime_findings(): Runtime / OS rows -> finding rows (source "RUNTIME"):
  * one row per advisory from the injected advisory lookup (OSV + CVE.org +
    NVD, see dkatchr.clients.runtime_advisories), fix_versions = the fixes
    newer than the version. For an IMPRECISE version (version_source
    "minimum": go.mod "go 1.20", Java "11", CI "3.10") only advisories that no
    patch on that release line fixes are reported — a patch-level fix would
    already be in whatever patch is installed; a spec coarser than a release
    line ("3.x" for Python) reports nothing;
  * an end-of-life finding (vuln_id "EOL-{runtime}-{cycle}", severity HIGH)
    when the release line is past its end-of-life date — not for open ranges
    (">=3.9" names no line); every row of an end-of-life version carries
    eol_date for the badge.

No I/O: the resolver, advisory and end-of-life lookups are injected.
"""

import re
from datetime import date

from dkatchr.clients.cvelist import version_key
from dkatchr.config import DISTRO_EOL_PRODUCTS, RUNTIMES
from dkatchr.output.schema import empty_row
from dkatchr.parsers.runtime import parse_spec

_DISTRO_TAG = re.compile(r"(?:^|[-_.])(alpine)(\d+\.\d+)|(?:^|[-_])(bookworm|bullseye|buster|stretch|trixie|"
                         r"jammy|focal|noble|bionic)(?:$|[-_])", re.I)
_DEBIAN_CODENAMES = {"stretch", "buster", "bullseye", "bookworm", "trixie"}


def _short(repository: str) -> str:
    return repository[len("library/"):] if repository.startswith("library/") else repository


def expand_image_runtimes(inventory: list[dict], resolve=None) -> list[dict]:
    """New Runtime / OS rows for the inventory's ContainerImage rows."""
    out: list[dict] = []
    seen: set[tuple] = set()
    for row in inventory:
        if row.get("ecosystem") != "ContainerImage":
            continue
        registry, _, repository = row["package"].partition("/")
        reference = row.get("version") or "latest"
        short = _short(repository)
        build = row.get("stage") == "build" or row.get("scope") == "dev"
        info = None
        if resolve is not None:
            try:
                info = resolve(registry, repository, reference)
            except Exception:  # noqa: BLE001 — resolution is best-effort
                info = None
        env = (info or {}).get("env") or {}
        found = False
        for rt, d in RUNTIMES.items():
            version = source = kind = precision = None
            for var in d["env"]:
                if env.get(var):
                    p = parse_spec(env[var])
                    if p:
                        version, source, kind, precision = p[0], "resolved_tag", "exact", 3
                        break
            if version is None and short in d["images"] and not reference.startswith("sha256:"):
                p = parse_spec(reference)
                if p:
                    version, source, kind, precision = (p[0], "minimum",
                                                        "exact" if p[2] == "exact" else "line", p[3])
                    if p[1] == "exact":
                        source = "exact"
            if version is None:
                continue
            found = True
            key = (rt, version, row["file"])
            if key in seen:
                continue
            seen.add(key)
            r = {"file": row["file"], "ecosystem": "Runtime", "package": rt, "version": version,
                 "version_source": source, "origin": "registry", "spec": row.get("image", ""),
                 "spec_kind": kind, "precision": precision, "line": row.get("line"),
                 "image": row.get("image")}
            if build and not d.get("bakes_stdlib"):
                r["scope"] = "dev"
            out.append(r)
        distro = None
        if short in DISTRO_EOL_PRODUCTS and not reference.startswith("sha256:"):
            distro = (short, reference.split("-")[0])
        else:
            m = _DISTRO_TAG.search(reference)
            if m and m.group(1):
                distro = ("alpine", m.group(2))
            elif m and m.group(3):
                code = m.group(3).lower()
                distro = ("debian" if code in _DEBIAN_CODENAMES else "ubuntu", code)
        if distro and (found or short in DISTRO_EOL_PRODUCTS):
            key = ("OS", distro, row["file"])
            if key not in seen:
                seen.add(key)
                r = {"file": row["file"], "ecosystem": "OS", "package": distro[0], "version": distro[1],
                     "version_source": "image_tag", "origin": "registry", "spec": row.get("image", ""),
                     "spec_kind": "line", "line": row.get("line"), "image": row.get("image")}
                if build:
                    r["scope"] = "dev"
                out.append(r)
    return out


def _cycle_for(cycles: list[dict], version: str) -> dict | None:
    v = version.lower()
    best = None
    for c in cycles or []:
        cyc = str(c.get("cycle", "")).lower()
        code = str(c.get("codename") or "").lower()
        if v == cyc or v.startswith(cyc + ".") or (code and v == code):
            if best is None or len(cyc) > len(str(best["cycle"])):
                best = c
    if best is None and re.fullmatch(r"\d+\.0\.0", v):
        # "20.0.0" from a tag "20": match the major line
        major = v.split(".")[0]
        best = next((c for c in cycles or [] if str(c.get("cycle")) == major), None)
    return best


def _line_granularity(cycles: list[dict]) -> int:
    """How many numeric components name a release line (Node "22" -> 1,
    Python "3.12" -> 2), from the product's own cycles."""
    counts = [len(str(c.get("cycle", "")).split(".")) for c in cycles or []
              if re.fullmatch(r"\d+(?:\.\d+)*", str(c.get("cycle", "")))]
    return max(set(counts), key=counts.count) if counts else 1


def _eol_date(cycle: dict, today: date) -> str | None:
    e = cycle.get("eol")
    if e is True:
        return "past"
    if isinstance(e, str):
        try:
            if date.fromisoformat(e) <= today:
                return e
        except ValueError:
            return None
    return None


def _newest_supported(cycles: list[dict], today: date) -> str | None:
    live = [c for c in cycles or [] if not _eol_date(c, today) and c.get("latest")]
    if not live:
        return None
    return max((str(c["latest"]) for c in live), key=version_key)


def runtime_findings(repo_full_name: str, inventory: list[dict], advisories, eol_cycles,
                     today: date | None = None, kev_cve_set: set[str] | None = None) -> list[dict]:
    """Finding rows (source RUNTIME) for the repo's Runtime / OS inventory rows.
    advisories(runtime, version) -> [advisory]; eol_cycles(product) -> cycles | None."""
    today = today or date.today()
    rows: list[dict] = []
    for dep in inventory:
        eco = dep.get("ecosystem")
        if eco not in ("Runtime", "OS"):
            continue
        name, version = dep["package"], dep["version"]
        product = RUNTIMES[name]["eol"] if eco == "Runtime" and name in RUNTIMES else DISTRO_EOL_PRODUCTS.get(name)
        cycles = None
        if product:
            try:
                cycles = eol_cycles(product)
            except Exception:  # noqa: BLE001
                cycles = None
        # A spec less precise than the runtime's release lines ("3.x" for
        # Python, whose lines are 3.12 / 3.13) names no line: nothing
        # meaningful to report — its "lowest version" would be 3.0.0.
        if (eco == "Runtime" and cycles and dep.get("version_source") == "minimum"
                and dep.get("precision") and dep["precision"] < _line_granularity(cycles)):
            continue
        cycle = _cycle_for(cycles, version) if cycles else None
        eol = _eol_date(cycle, today) if cycle else None
        extra = {"line": dep.get("line"), "spec": dep.get("spec", ""), "image": dep.get("image") or "",
                 "eol_date": eol or ""}

        if eco == "Runtime":
            try:
                advs = advisories(name, version) or []
            except Exception:  # noqa: BLE001
                advs = []
            vk = version_key(version)
            imprecise = dep.get("version_source") == "minimum"
            gran = _line_granularity(cycles) if cycles else (1 if name in ("node", "java") else 2)
            line = ".".join(version.split(".")[:gran])
            for a in advs:
                fixes = sorted({f for f in a.get("fixed") or [] if version_key(f) > vk}, key=version_key)
                # Imprecise version (go.mod "go 1.20", Java "11", CI "3.10"):
                # only CVEs NO patch on that release line fixes — those hit
                # whatever patch is actually installed (decided 2026-11-22).
                if imprecise and any(f == line or f.startswith(line + ".") for f in fixes):
                    continue
                row = empty_row(repo_full_name, dep)
                aliases = ",".join(a.get("aliases") or [])
                row.update({
                    "source": "RUNTIME", "status": "vulnerable", "vuln_id": a["id"], "aliases": aliases,
                    "severity": a.get("severity") or a.get("cvss_vector") or "",
                    "cvss_score": a.get("cvss_score"), "summary": a.get("summary", ""),
                    "fix_versions": ", ".join(fixes), "cwe_ids": ",".join(a.get("cwe_ids") or []),
                    "published": a.get("published", ""),
                    "advisory_sources": ",".join(a.get("sources") or []), **extra,
                })
                if kev_cve_set is not None:
                    ids = {a["id"], *(a.get("aliases") or [])}
                    row["is_kev"] = "true" if ids & kev_cve_set else "false"
                rows.append(row)

        if eol and cycle and dep.get("spec_kind") != "range":
            label = name.capitalize() if eco == "Runtime" else name.capitalize()
            when = "" if eol == "past" else f" on {eol}"
            upgrade = _newest_supported(cycles, today)
            row = empty_row(repo_full_name, dep)
            row.update({
                "source": "RUNTIME", "status": "vulnerable",
                "vuln_id": f"EOL-{name}-{cycle['cycle']}", "severity": "HIGH",
                "summary": (f"{label} {cycle['cycle']} reached end of life{when}: it no longer "
                            f"receives security fixes. Upgrade to a supported release line."),
                "fix_versions": upgrade or "", **extra,
            })
            if kev_cve_set is not None:
                row["is_kev"] = "false"
            rows.append(row)
    return rows
