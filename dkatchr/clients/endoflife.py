"""
EndOfLifeClient — release-line support data from endoflife.date.

Per product (ruby, nodejs, python, debian, ...) the API lists release lines
("cycles") with their end-of-life date, latest patch version and codename.
Used by runtime scanning to flag end-of-life runtimes / base images and to
name the newest patch of a line as the upgrade target.

TTL'd file cache ({cache_dir}/endoflife/, 7 days): support dates change
rarely, but new cycles appear. Fail-safe: any failure returns None (the
caller skips EOL checks for that product), never raises.

What this module does NOT do: decide whether a version is end-of-life
(dkatchr.core.runtime_findings does, from these cycles).
"""

import json
import os
import re
import time

import requests

from dkatchr.clients.ratelimit import TokenBucket
from dkatchr.config import (
    DEFAULT_ENDOFLIFE_TTL,
    DKATCHR_USER_AGENT,
    ENDOFLIFE_API_URL,
    ENDOFLIFE_TIMEOUT,
)
from dkatchr.logger import log


class EndOfLifeClient:
    def __init__(self, cache_dir: str, ttl_seconds: int = DEFAULT_ENDOFLIFE_TTL) -> None:
        self.dir = os.path.join(cache_dir, "endoflife")
        self.ttl = ttl_seconds
        self.limiter = TokenBucket(rate=2.0, capacity=4)
        os.makedirs(self.dir, exist_ok=True)

    def _path(self, product: str) -> str:
        return os.path.join(self.dir, re.sub(r"[^\w.-]", "_", product) + ".json")

    def get_cycles(self, product: str) -> list[dict] | None:
        """[{cycle, eol (date str | bool), latest, codename, lts}], or None."""
        path = self._path(product)
        stale = None
        try:
            with open(path, encoding="utf-8") as f:
                cached = json.load(f)
            if time.time() - cached.get("fetched_at", 0) < self.ttl:
                return cached.get("cycles")
            stale = cached.get("cycles")
        except (OSError, ValueError):
            pass
        self.limiter.acquire()
        try:
            resp = requests.get(ENDOFLIFE_API_URL.format(product=product), timeout=ENDOFLIFE_TIMEOUT,
                                headers={"User-Agent": DKATCHR_USER_AGENT})
            if resp.status_code != 200:
                log(f"[!] endoflife.date {product}: HTTP {resp.status_code}")
                return stale
            data = resp.json()
        except (requests.RequestException, ValueError) as e:
            log(f"[!] endoflife.date {product}: {e}")
            return stale
        cycles = [{"cycle": str(c.get("cycle", "")), "eol": c.get("eol"),
                   "latest": c.get("latest"), "codename": c.get("codename"), "lts": c.get("lts")}
                  for c in data if isinstance(c, dict) and c.get("cycle") is not None]
        try:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"fetched_at": time.time(), "cycles": cycles}, f)
            os.replace(tmp, path)
        except OSError as e:
            log(f"[!] endoflife cache write {product}: {e}")
        return cycles
