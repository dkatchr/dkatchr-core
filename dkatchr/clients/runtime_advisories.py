"""
RuntimeAdvisoryClient — vulnerabilities of a language RUNTIME version, merged
from three sources so every runtime gets the same coverage level:

  1. OSV  — Bitnami runtime records (node, python, php, java, dotnet, ruby...)
            and Go's own stdlib/toolchain records (config.RUNTIMES[...]["osv"]);
  2. CVE.org — the official CVE List's CNA "affected" versions (CveListIndex):
            catches recent CVEs NVD has not analysed yet;
  3. NVD  — analysed CPE configurations, version-aware (NVDClient.
            cves_for_product): older CVEs whose CVE.org record has no versions.

Results are de-duplicated by shared CVE id: an OSV record (GO-..., BIT-...)
and the CVE.org/NVD entry for the same CVE become one advisory; missing
severity / fix versions / summary are filled from the other sources.

Each advisory: {id, aliases, summary, published, cvss_score, cvss_vector,
severity, cwe_ids, fixed (list), sources (list)}. Never raises; a failing
source is skipped. Cached by the underlying clients.
"""

import re

from dkatchr.config import RUNTIMES
from dkatchr.core.osv_enrichment import (
    osv_aliases,
    osv_cvss_score,
    osv_cwe_ids,
    osv_fix_versions,
    osv_published,
    osv_severity,
    osv_summary,
)
from dkatchr.logger import log

_CVE = re.compile(r"CVE-\d{4}-\d+")


def _cve_ids(adv: dict) -> set[str]:
    return {x for x in [adv["id"], *adv.get("aliases", [])] if _CVE.fullmatch(x or "")}


class RuntimeAdvisoryClient:
    def __init__(self, osv_client=None, cvelist=None, nvd_client=None) -> None:
        self.osv = osv_client
        self.cvelist = cvelist
        self.nvd = nvd_client
        self._memo: dict[tuple[str, str], list[dict]] = {}

    def _from_osv(self, runtime: str, version: str) -> list[dict]:
        out = []
        for eco, pkg in RUNTIMES[runtime].get("osv", []):
            ids = self.osv.get_cached_ids(eco, pkg, version)
            if ids is None:
                ids = self.osv.query_batch([(eco, pkg, version)])[0]
                self.osv.set_cached_ids(eco, pkg, version, ids)
            for vid in ids:
                v = self.osv.get_vuln(vid)
                if not v:
                    continue
                fixes = [f.strip() for f in osv_fix_versions(v, eco, pkg).split(",") if f.strip()]
                out.append({"id": v.get("id", vid), "aliases": [a for a in osv_aliases(v).split(",") if a],
                            "summary": osv_summary(v), "published": osv_published(v),
                            "cvss_score": osv_cvss_score(v), "cvss_vector": None,
                            "severity": osv_severity(v),
                            "cwe_ids": [c for c in osv_cwe_ids(v).split(",") if c],
                            "fixed": fixes, "sources": ["OSV"]})
        return out

    @staticmethod
    def _plain(entries: list[dict] | None, source: str) -> list[dict]:
        return [{"id": e["id"], "aliases": [], "summary": e.get("summary", ""),
                 "published": e.get("published", ""), "cvss_score": e.get("cvss_score"),
                 "cvss_vector": e.get("cvss_vector"), "severity": e.get("cvss_vector") or "",
                 "cwe_ids": e.get("cwe_ids") or [], "fixed": list(e.get("fixed") or []),
                 "sources": [source]} for e in entries or [] if e.get("id")]

    @staticmethod
    def sources_for(runtime: str) -> list[str]:
        """The advisory sources this client queries for `runtime` (for coverage
        displays — kept here so the list can't drift from get())."""
        d = RUNTIMES.get(runtime) or {}
        return (["OSV"] if d.get("osv") else []) + ["CVE.org"] + (["NVD"] if d.get("cpe") else [])

    def get(self, runtime: str, version: str) -> list[dict]:
        key = (runtime, version)
        if key in self._memo:
            return self._memo[key]
        if runtime not in RUNTIMES:
            return []
        parts: list[dict] = []
        if self.osv is not None and RUNTIMES[runtime].get("osv"):
            try:
                parts += self._from_osv(runtime, version)
            except Exception as e:  # noqa: BLE001
                log(f"[!] runtime advisories OSV {runtime} {version}: {e}")
        if self.cvelist is not None:
            try:
                parts += self._plain(self.cvelist.affected(runtime, version), "CVE.org")
            except Exception as e:  # noqa: BLE001
                log(f"[!] runtime advisories CVE.org {runtime} {version}: {e}")
        if self.nvd is not None and RUNTIMES[runtime].get("cpe"):
            try:
                parts += self._plain(self.nvd.cves_for_product(RUNTIMES[runtime]["cpe"], version), "NVD")
            except Exception as e:  # noqa: BLE001
                log(f"[!] runtime advisories NVD {runtime} {version}: {e}")
        merged = _merge(parts)
        self._memo[key] = merged
        return merged


def _merge(parts: list[dict]) -> list[dict]:
    """One advisory per bug: entries sharing an id or CVE alias merge; the OSV
    record (first in `parts`) keeps its id, others become aliases."""
    groups: list[dict] = []
    for p in parts:
        ids = {p["id"], *p.get("aliases", [])}
        target = next((g for g in groups if g["_ids"] & ids), None)
        if target is None:
            g = dict(p, aliases=list(p.get("aliases", [])), fixed=list(p["fixed"]),
                     sources=list(p["sources"]), cwe_ids=list(p.get("cwe_ids", [])))
            g["_ids"] = set(ids)
            groups.append(g)
            continue
        target["_ids"] |= ids
        for x in ids:
            if x != target["id"] and x not in target["aliases"]:
                target["aliases"].append(x)
        for k in ("summary", "published", "cvss_vector", "severity"):
            if not target.get(k) and p.get(k):
                target[k] = p[k]
        if p.get("cvss_score") is not None and (target.get("cvss_score") is None):
            target["cvss_score"] = p["cvss_score"]
        for f in p["fixed"]:
            if f not in target["fixed"]:
                target["fixed"].append(f)
        for c in p.get("cwe_ids", []):
            if c not in target["cwe_ids"]:
                target["cwe_ids"].append(c)
        for s in p["sources"]:
            if s not in target["sources"]:
                target["sources"].append(s)
    for g in groups:
        g.pop("_ids", None)
    return groups
