"""
CveListIndex — runtime CVEs from the official CVE List (CVE.org, CVE JSON 5).

WHY: NVD analyses CVEs late — many recent runtime CVEs (e.g. CVE-2026-132825,
"Ruby before 3.3.14, 3.4.13, and 4.0.10") have NO NVD version data, while the
CNA's own CVE record carries structured "affected" versions. CVE.org has no
search API, so the list is mirrored locally:

  * baseline: the newest "all_CVEs_at_midnight" release asset of
    github.com/CVEProject/cvelistV5 (~640 MB zip, streamed to a temp file),
    re-taken when older than CVELIST_BASELINE_MAX_AGE_DAYS;
  * catch-up: for each later day, that day's newest hourly "delta" asset
    (cumulative since midnight), so the index stays current without a full
    re-download;
  * only records whose "affected" entries name a runtime in config.RUNTIMES
    (vendor/product, case-insensitive; product "*" = any, "x*" = prefix) are
    kept — the stored index is small.

sync() is TTL'd (CVELIST_SYNC_TTL) and fail-safe (a failed sync keeps the
existing index). affected(runtime, version) answers from the local index.

What this module does NOT do: merge with OSV/NVD (runtime_advisories does).
"""

import fcntl
import json
import os
import re
import shutil
import tempfile
import time
import zipfile
from datetime import date, datetime, timedelta, timezone

import requests

from dkatchr.config import (
    CVELIST_BASELINE_MAX_AGE_DAYS,
    CVELIST_INDEX_SCHEMA,
    CVELIST_RELEASES_API,
    CVELIST_SYNC_TTL,
    CVELIST_TIMEOUT,
    DKATCHR_USER_AGENT,
    RUNTIMES,
)
from dkatchr.logger import log

_TAG_DATE = re.compile(r"cve_(\d{4}-\d{2}-\d{2})_(\d{4})Z")
_NO_VERSION = {"", "0", "*", "n/a", "unspecified", "unknown", "-"}


def version_key(v: str) -> list:
    """Natural-order key: numbers numerically, pre-release words before release."""
    v = (v or "").strip().lstrip("vV")
    v = re.split(r"[+]", v, maxsplit=1)[0]
    parts = [(2, int(t)) if t.isdigit() else (1, t.lower()) for t in re.findall(r"\d+|[A-Za-z]+", v)]
    return parts + [(1.5,)]


def _cmp(a: str, b: str) -> int:
    ka, kb = version_key(a), version_key(b)
    # pad numeric length so 3.2 == 3.2.0
    while len(ka) < len(kb) and kb[len(ka)][0] == 2 and kb[len(ka)][1] == 0:
        ka.insert(len(ka) - 1, (2, 0))
    while len(kb) < len(ka) and ka[len(kb)][0] == 2 and ka[len(kb)][1] == 0:
        kb.insert(len(kb) - 1, (2, 0))
    return (ka > kb) - (ka < kb)


def _norm_listed(v: str) -> str:
    """'Oracle Java SE:8u391-perf' -> '8.0.391'; '17.0.14' unchanged."""
    v = v.rsplit(":", 1)[-1].strip()
    m = re.match(r"^(\d+)u(\d+)", v)
    return f"{m.group(1)}.0.{m.group(2)}" if m else v


def affected_fix(entry_versions: list[dict], version: str,
                 listed_is_max: bool = False) -> tuple[bool, str | None]:
    """(is `version` affected, fix version) for one CVE-5 `affected[].versions` list.
    listed_is_max: a plain listed version means "this and older on its release
    line" (Oracle's convention)."""
    for e in entry_versions or []:
        if (e.get("status") or "affected") != "affected":
            continue
        lo = _norm_listed(str(e.get("version") or ""))
        if listed_is_max and not (e.get("lessThan") or e.get("lessThanOrEqual")):
            if lo.lower() in _NO_VERSION or not re.match(r"^\d", lo):
                continue
            if lo.split(".")[0] == version.split(".")[0] and _cmp(version, lo) <= 0:
                return True, None
            continue
        lt, lte = e.get("lessThan"), e.get("lessThanOrEqual")
        if lt or lte:
            if lo.lower() not in _NO_VERSION and _cmp(version, lo) < 0:
                continue
            if lt and lt not in ("*",) and _cmp(version, lt) >= 0:
                continue
            if lte and lte not in ("*",) and _cmp(version, lte) > 0:
                continue
            return True, (lt if lt and lt != "*" else None)
        m = re.match(r"^\s*(<=?)\s*([\w.+-]+)\s*$", lo)
        if m:
            c = _cmp(version, m.group(2))
            if c < 0 or (m.group(1) == "<=" and c == 0):
                return True, (m.group(2) if m.group(1) == "<" else None)
            continue
        if lo.lower() in _NO_VERSION:
            continue
        if lo.lower().endswith(".x") and version.startswith(lo[:-1]):
            return True, None
        if _cmp(version, lo) == 0:
            return True, None
    return False, None


def _matcher():
    rules = []
    for rt, d in RUNTIMES.items():
        for vendor, product in d.get("cve_products", []):
            rules.append((rt, vendor.lower(), product.lower(), [x.lower() for x in d.get("cve_exclude", [])]))
    return rules


_RULES = _matcher()
_PREFILTER = sorted({v for _, v, _, _ in _RULES}, key=len)


def _runtime_for(vendor: str, product: str) -> str | None:
    v, p = (vendor or "").strip().lower(), (product or "").strip().lower()
    for rt, rv, rp, excl in _RULES:
        if v != rv or any(x in p for x in excl):
            continue
        if rp == "*" or p == rp or (rp.endswith("*") and p.startswith(rp[:-1])):
            return rt
    return None


def _summarize(doc: dict) -> tuple[str, dict] | None:
    meta = doc.get("cveMetadata") or {}
    cve_id = meta.get("cveId")
    if not cve_id or meta.get("state") == "REJECTED":
        return None
    cna = (doc.get("containers") or {}).get("cna") or {}
    by_rt: dict[str, list] = {}
    for a in cna.get("affected") or []:
        rt = _runtime_for(a.get("vendor"), a.get("product"))
        if rt and a.get("versions"):
            by_rt.setdefault(rt, []).append(a["versions"])
    if not by_rt:
        return None
    best = None
    for cont in [cna, *((doc.get("containers") or {}).get("adp") or [])]:
        for m in cont.get("metrics") or []:
            for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                c = m.get(k) or {}
                if c.get("baseScore") is not None and (best is None or c["baseScore"] > best[0]):
                    best = (c["baseScore"], c.get("vectorString"))
    desc = next((d.get("value", "") for d in cna.get("descriptions") or [] if d.get("lang", "en").startswith("en")), "")
    cwes = sorted({d.get("cweId") for pt in cna.get("problemTypes") or []
                   for d in pt.get("descriptions") or [] if d.get("cweId")})
    return cve_id, {"runtimes": by_rt, "summary": desc[:500],
                    "published": meta.get("datePublished", ""),
                    "cvss_score": best[0] if best else None, "cvss_vector": best[1] if best else None,
                    "cwe_ids": cwes}


class CveListIndex:
    def __init__(self, cache_dir: str) -> None:
        self.dir = os.path.join(cache_dir, "cvelist")
        self.path = os.path.join(self.dir, "index.json")
        os.makedirs(self.dir, exist_ok=True)
        self._idx = self._load()

    # ---- persistence -----------------------------------------------------------

    def _load(self) -> dict:
        try:
            with open(self.path, encoding="utf-8") as f:
                idx = json.load(f)
            if idx.get("schema") == CVELIST_INDEX_SCHEMA:
                return idx
        except (OSError, ValueError):
            pass
        return {"schema": CVELIST_INDEX_SCHEMA, "baseline_date": None, "applied": {},
                "last_sync": 0, "records": {}}

    def _save(self) -> None:
        fd, tmp = tempfile.mkstemp(prefix="index-", suffix=".tmp", dir=self.dir)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self._idx, f)
        os.replace(tmp, self.path)

    # ---- query ---------------------------------------------------------------------

    def affected(self, runtime: str, version: str) -> list[dict]:
        """[{id, summary, published, cvss_score, cvss_vector, cwe_ids, fixed}]"""
        out = []
        listed_is_max = bool(RUNTIMES.get(runtime, {}).get("cve_listed_is_max"))
        for cve_id, rec in self._idx["records"].items():
            for versions in rec["runtimes"].get(runtime, []):
                hit, fix = affected_fix(versions, version, listed_is_max)
                if hit:
                    out.append({"id": cve_id, "summary": rec["summary"], "published": rec["published"],
                                "cvss_score": rec["cvss_score"], "cvss_vector": rec["cvss_vector"],
                                "cwe_ids": rec["cwe_ids"], "fixed": [fix] if fix else []})
                    break
        return out

    @property
    def ready(self) -> bool:
        return bool(self._idx.get("baseline_date"))

    # ---- sync -----------------------------------------------------------------------

    def sync(self, on_progress=None, force: bool = False) -> bool:
        """Bring the local index up to date. True when the index is usable.
        Holds an exclusive OS file lock for the whole sync: the web app and
        the monitoring cron are separate processes sharing this index."""
        if not force and time.time() - self._idx.get("last_sync", 0) < CVELIST_SYNC_TTL and self.ready:
            return True
        with open(os.path.join(self.dir, ".sync.lock"), "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                self._idx = self._load()          # another process may have just synced
                if not force and time.time() - self._idx.get("last_sync", 0) < CVELIST_SYNC_TTL \
                        and self.ready:
                    return True
                return self._sync_locked(on_progress)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def _sync_locked(self, on_progress=None) -> bool:
        try:
            releases = self._releases()
        except Exception as e:  # noqa: BLE001
            log(f"[!] CVE list: could not list releases: {e}")
            return self.ready
        if not releases:
            return self.ready
        today = datetime.now(timezone.utc).date()
        base = self._idx.get("baseline_date")
        try:
            if not base or (today - date.fromisoformat(base)).days > CVELIST_BASELINE_MAX_AGE_DAYS:
                self._take_baseline(releases, on_progress)
            self._apply_deltas(releases, on_progress)
            self._idx["last_sync"] = time.time()
            self._save()
        except Exception as e:  # noqa: BLE001 — a failed sync keeps the old index
            log(f"[!] CVE list sync failed: {e}")
        return self.ready

    def _releases(self) -> list[dict]:
        """[(date, hhmm, tag, assets)] newest first, back to the baseline date."""
        out, page = [], 1
        base = self._idx.get("baseline_date")
        stop = date.fromisoformat(base) if base else None
        while page <= 12:
            r = requests.get(CVELIST_RELEASES_API.format(page=page), timeout=30,
                             headers={"User-Agent": DKATCHR_USER_AGENT,
                                      "Accept": "application/vnd.github+json"})
            r.raise_for_status()
            batch = r.json()
            if not batch:
                break
            for rel in batch:
                m = _TAG_DATE.match(rel.get("tag_name", ""))
                if m:
                    out.append({"date": date.fromisoformat(m.group(1)), "hhmm": m.group(2),
                                "tag": rel["tag_name"],
                                "assets": {a["name"]: a["browser_download_url"] for a in rel.get("assets", [])}})
            if stop is None or (out and out[-1]["date"] < stop):
                break
            page += 1
        return out

    def _download(self, url: str, on_progress=None, label: str = "") -> str:
        fd, tmp = tempfile.mkstemp(prefix="cvelist-", suffix=".zip", dir=self.dir)
        with os.fdopen(fd, "wb") as f, requests.get(url, stream=True, timeout=CVELIST_TIMEOUT,
                                                    headers={"User-Agent": DKATCHR_USER_AGENT}) as r:
            r.raise_for_status()
            total = int(r.headers.get("Content-Length") or 0)
            done, last = 0, 0.0
            for chunk in r.iter_content(1 << 20):
                f.write(chunk)
                done += len(chunk)
                if on_progress and time.time() - last > 1:
                    last = time.time()
                    try:
                        on_progress({"phase": "cvelist_download", "what": label,
                                     "bytes": done, "total": total})
                    except Exception:  # noqa: BLE001
                        pass
        return tmp

    def _ingest_zip(self, zf: zipfile.ZipFile, on_progress=None) -> int:
        n = 0
        names = [i for i in zf.namelist() if i.endswith(".json")]
        for i, name in enumerate(names, 1):
            if i % 20000 == 0 and on_progress:
                try:
                    on_progress({"phase": "cvelist_index", "current": i, "total": len(names)})
                except Exception:  # noqa: BLE001
                    pass
            raw = zf.read(name)
            low = raw.lower()
            if b'"affected"' not in low or not any(v.encode() in low for v in _PREFILTER):
                cid = os.path.basename(name)[:-5]
                self._idx["records"].pop(cid, None)
                continue
            try:
                s = _summarize(json.loads(raw))
            except ValueError:
                continue
            cid = os.path.basename(name)[:-5]
            if s:
                self._idx["records"][s[0]] = s[1]
                n += 1
            else:
                self._idx["records"].pop(cid, None)
        return n

    def _open_nested(self, path: str) -> zipfile.ZipFile:
        """The baseline asset is a zip holding one inner zip of JSON files:
        stream the inner one to its own temp file (never into memory)."""
        outer = zipfile.ZipFile(path)
        inner = [n for n in outer.namelist() if n.endswith(".zip")]
        if not inner:
            return outer
        fd, tmp = tempfile.mkstemp(prefix="cvelist-inner-", suffix=".zip", dir=self.dir)
        with os.fdopen(fd, "wb") as out, outer.open(inner[0]) as src:
            shutil.copyfileobj(src, out, 1 << 20)
        outer.close()
        os.unlink(path)                                # free the outer copy right away
        zf = zipfile.ZipFile(tmp)
        zf._dkatchr_tmp = tmp                          # removed by _take_baseline
        return zf

    def _take_baseline(self, releases: list[dict], on_progress=None) -> None:
        rel = next((r for r in releases if any("all_CVEs_at_midnight" in a for a in r["assets"])), None)
        if not rel:
            raise RuntimeError("no baseline asset found")
        name = next(a for a in rel["assets"] if "all_CVEs_at_midnight" in a)
        log(f"[+] CVE list: downloading baseline {name} (one-time, ~640 MB)")
        tmp = self._download(rel["assets"][name], on_progress, "baseline")
        inner_tmp = None
        try:
            self._idx["records"] = {}
            zf = self._open_nested(tmp)
            inner_tmp = getattr(zf, "_dkatchr_tmp", None)
            n = self._ingest_zip(zf, on_progress)
            zf.close()
        finally:
            for f in (tmp, inner_tmp):
                if f and os.path.exists(f):
                    os.unlink(f)
        self._idx["baseline_date"] = rel["date"].isoformat()
        self._idx["applied"] = {}
        log(f"[+] CVE list: baseline {rel['date']} indexed, {n} runtime CVE records")

    def _apply_deltas(self, releases: list[dict], on_progress=None) -> None:
        base = date.fromisoformat(self._idx["baseline_date"])
        newest: dict[date, dict] = {}
        for r in releases:
            if r["date"] >= base and any("delta" in a for a in r["assets"]):
                if r["date"] not in newest or r["hhmm"] > newest[r["date"]]["hhmm"]:
                    newest[r["date"]] = r
        for d in sorted(newest):
            rel = newest[d]
            if self._idx["applied"].get(d.isoformat()) == rel["tag"]:
                continue
            name = next(a for a in rel["assets"] if "delta" in a)
            tmp = self._download(rel["assets"][name], None, "delta")
            try:
                with zipfile.ZipFile(tmp) as zf:
                    self._ingest_zip(zf)
            finally:
                os.unlink(tmp)
            self._idx["applied"][d.isoformat()] = rel["tag"]
        cutoff = (datetime.now(timezone.utc).date() - timedelta(days=60)).isoformat()
        self._idx["applied"] = {k: v for k, v in self._idx["applied"].items() if k >= cutoff}
