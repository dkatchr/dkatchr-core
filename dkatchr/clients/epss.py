"""
EPSSClient — download, cache, and expose FIRST.org EPSS scores.

WHY: EPSS (Exploit Prediction Scoring System) gives each CVE a probability
(0–1) of being exploited in the next 30 days. Pairing it with CVSS severity
lets users triage by *likelihood of attack*, not just theoretical severity —
the core "reduce alert fatigue" signal.

Same role as kev.py for the CISA KEV catalog: a single daily download wrapped
in a file cache. FIRST.org publishes a fresh gzipped CSV every day at a stable
URL; each row is `cve,epss,percentile`. We keep only cve + epss.

Cache strategy: one JSON file per calendar date under {cache_dir}/epss/
(e.g. epss_scores-2026-05-29.json). A file for today's date IS the freshness
check — at most one download per day, so there's no retry storm and no need
for a rate limiter.

Fail-safe contract (never raise, never block the caller):
  fresh cache for today -> download -> most-recent stale cache -> empty dict.

This module does NOT do any DB work, percentage formatting, or join logic —
that lives in the web repositories / CLI runner. It only returns
dict[str, float] mapping uppercased CVE ID -> EPSS probability.
"""

import csv
import gzip
import json
import os
from datetime import date

import requests

from dkatchr.config import EPSS_SCORES_URL
from dkatchr.logger import log


class EPSSClient:
    def __init__(self, cache_dir: str, url: str = EPSS_SCORES_URL) -> None:
        # Cache lives under {cache_dir}/epss/ — caller passes the base cache dir.
        self.url = url
        self.cache_dir = os.path.join(cache_dir, "epss")
        os.makedirs(self.cache_dir, exist_ok=True)

    # ---- public API ---------------------------------------------------------

    def get_scores(self) -> dict[str, float]:
        """Return {CVE_ID (uppercase): epss_probability}.

        Fresh cache for today -> download -> most-recent stale cache -> {}.
        Never raises; on total failure returns an empty dict.
        """
        today = date.today().isoformat()
        path = self._cache_path(today)

        cached = self._read_cache(path)
        if cached is not None:
            log(f"[+] EPSS: loaded {len(cached)} scores from cache ({today})")
            return cached

        downloaded = self._download()
        if downloaded is not None:
            self._write_cache(path, downloaded)
            log(f"[+] EPSS: downloaded {len(downloaded)} scores ({today})")
            return downloaded

        stale = self._read_most_recent_cache()
        if stale is not None:
            log(f"[!] EPSS: download failed — using most recent cached scores ({len(stale)})")
            return stale

        log("[!] EPSS: no data available (download failed, no cache) — returning empty scores")
        return {}

    # ---- internals ----------------------------------------------------------

    def _cache_path(self, day: str) -> str:
        return os.path.join(self.cache_dir, f"epss_scores-{day}.json")

    def _read_cache(self, path: str) -> dict[str, float] | None:
        if not os.path.exists(path):
            return None
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            # Coerce defensively: JSON keys are strings, values should be floats.
            return {str(k): float(v) for k, v in data.items()}
        except Exception as e:
            log(f"[!] EPSS: cache read error ({path}): {e}")
            return None

    def _read_most_recent_cache(self) -> dict[str, float] | None:
        """Most recent epss_scores-*.json by filename (ISO dates sort lexically)."""
        try:
            files = sorted(
                f for f in os.listdir(self.cache_dir)
                if f.startswith("epss_scores-") and f.endswith(".json")
            )
        except OSError:
            return None
        for name in reversed(files):
            data = self._read_cache(os.path.join(self.cache_dir, name))
            if data is not None:
                return data
        return None

    def _write_cache(self, path: str, scores: dict[str, float]) -> None:
        try:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(scores, f)
            os.replace(tmp, path)
        except Exception as e:
            log(f"[!] EPSS: cache write error ({path}): {e}")

    def _download(self) -> dict[str, float] | None:
        """Single GET of the gzipped CSV. One attempt — no retry storm.

        Returns the parsed scores, or None on any failure (the caller falls
        back to stale cache / empty dict). Never raises.
        """
        log("[+] EPSS: downloading FIRST.org EPSS scores…")
        try:
            resp = requests.get(self.url, timeout=60)
            resp.raise_for_status()
            text = gzip.decompress(resp.content).decode("utf-8")
        except Exception as e:
            log(f"[!] EPSS: download failed: {e}")
            return None
        return self._parse_csv(text)

    @staticmethod
    def _parse_csv(text: str) -> dict[str, float]:
        """Parse the EPSS CSV body into {CVE (uppercase): epss float}.

        The FIRST.org file starts with a `#model_version:...` comment line
        before the real CSV header (`cve,epss,percentile`). Skip any line
        beginning with '#'. We keep only cve + epss; percentile and date are
        ignored per spec.
        """
        scores: dict[str, float] = {}
        rows = (ln for ln in text.splitlines() if not ln.startswith("#"))
        reader = csv.DictReader(rows)
        for row in reader:
            cve = (row.get("cve") or "").strip().upper()
            epss_raw = (row.get("epss") or "").strip()
            if not cve or not epss_raw:
                continue
            try:
                scores[cve] = float(epss_raw)
            except ValueError:
                continue
        return scores
