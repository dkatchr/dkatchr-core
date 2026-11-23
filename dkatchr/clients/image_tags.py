"""
ImageTagResolver — what a PUBLIC container image tag points to today.

`FROM ruby:3.2` floats: today it means the newest 3.2.x. The registry's image
metadata (OCI distribution API: manifest -> config blob) carries the image's
environment, and official images record their runtime version there
(RUBY_VERSION, NODE_VERSION, PYTHON_VERSION, GOLANG_VERSION, JAVA_VERSION...).
Only metadata is read — no layer is downloaded.

Anonymous access: a registry that wants a token answers 401 with a
`WWW-Authenticate: Bearer realm=...,service=...,scope=...` header; an
anonymous token from that realm is enough for public images.

SECURITY: the registry host comes from a repo file, i.e. it is attacker-
controllable. Only hosts in config.PUBLIC_IMAGE_REGISTRIES are contacted,
always over https, and a token realm must be https on one of that registry's
own auth hosts — otherwise None, nothing fetched, nothing cached (no SSRF,
no private image names on disk). Private registries: release C (stored
credentials in dkatchr-web).

Docker Hub counts each manifest GET as a pull (100 per 6 h per IP for
anonymous clients): results are cached per reference for 24 h, failures for
1 h, and a 429 returns None so the caller falls back to the tag text.

Never raises. What this module does NOT do: decide which runtime an env var
names (dkatchr.core.runtime_inventory reads config.RUNTIMES for that).
"""

import hashlib
import ipaddress
import json
import os
import re
import socket
import time

import requests

from dkatchr.clients.ratelimit import TokenBucket
from urllib.parse import urlparse

from dkatchr.config import (
    DEFAULT_IMAGE_TAG_TTL,
    DKATCHR_USER_AGENT,
    IMAGE_REGISTRY_MAX_REDIRECTS,
    IMAGE_REGISTRY_RATE_LIMIT_BACKOFF,
    IMAGE_REGISTRY_TIMEOUT,
    IMAGE_TAG_CACHE_SCHEMA,
    PUBLIC_IMAGE_REGISTRIES,
)
from dkatchr.logger import log

_ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
_FAIL_TTL = 3600


def _public_https(url: str) -> bool:
    """A redirect target is followed only over https to a PUBLIC address —
    never loopback / private / link-local (cloud metadata) networks."""
    u = urlparse(url)
    if u.scheme != "https" or not u.hostname:
        return False
    try:
        infos = socket.getaddrinfo(u.hostname, u.port or 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return False
    return True


class ImageTagResolver:
    def __init__(self, cache_dir: str, ttl_seconds: int = DEFAULT_IMAGE_TAG_TTL) -> None:
        self.dir = os.path.join(cache_dir, "image_tags")
        self.ttl = ttl_seconds
        self.limiter = TokenBucket(rate=2.0, capacity=4)
        self._rate_limited_until = 0.0
        os.makedirs(self.dir, exist_ok=True)

    # ---- cache -----------------------------------------------------------------

    def _path(self, ref: str) -> str:
        return os.path.join(self.dir, hashlib.sha256(ref.encode()).hexdigest()[:32] + ".json")

    def _read(self, ref: str) -> tuple[bool, dict | None]:
        try:
            with open(self._path(ref), encoding="utf-8") as f:
                c = json.load(f)
        except (OSError, ValueError):
            return False, None
        if c.get("schema") != IMAGE_TAG_CACHE_SCHEMA:
            return False, None
        ttl = self.ttl if c.get("result") else _FAIL_TTL
        if time.time() - c.get("fetched_at", 0) > ttl:
            return False, None
        return True, c.get("result")

    def _write(self, ref: str, result: dict | None) -> None:
        try:
            p = self._path(ref)
            with open(p + ".tmp", "w", encoding="utf-8") as f:
                json.dump({"schema": IMAGE_TAG_CACHE_SCHEMA,
                           "fetched_at": time.time(), "result": result}, f)
            os.replace(p + ".tmp", p)
        except OSError:
            pass

    # ---- registry protocol -------------------------------------------------------

    def _get(self, url: str, accept: str, token_box: dict,
             auth_hosts: tuple[str, ...] = ()) -> requests.Response | None:
        for _ in range(2):
            headers = {"Accept": accept, "User-Agent": DKATCHR_USER_AGENT}
            if token_box.get("token"):
                headers["Authorization"] = f"Bearer {token_box['token']}"
            self.limiter.acquire()
            resp = requests.get(url, headers=headers, timeout=IMAGE_REGISTRY_TIMEOUT,
                                allow_redirects=False if "/manifests/" in url else True)
            if "/manifests/" in url and resp.is_redirect:
                return self._follow_redirect(resp, accept)
            if resp.status_code == 401 and not token_box.get("token"):
                token = self._anonymous_token(resp.headers.get("WWW-Authenticate", ""), auth_hosts)
                if not token:
                    return resp
                token_box["token"] = token
                continue
            return resp
        return None

    def _follow_redirect(self, resp: requests.Response, accept: str) -> requests.Response | None:
        """Follow a manifest redirect by hand (registry.k8s.io sends every
        request to a regional mirror): at most IMAGE_REGISTRY_MAX_REDIRECTS
        hops, each https to a PUBLIC address, no Authorization forwarded; a
        token the mirror asks for must come from the mirror's OWN host."""
        for _ in range(IMAGE_REGISTRY_MAX_REDIRECTS):
            loc = resp.headers.get("Location", "")
            if not _public_https(loc):
                log("[!] image registry redirect to a non-public or non-https location — skipped")
                return None
            host = (urlparse(loc).hostname or "").lower()
            headers = {"Accept": accept, "User-Agent": DKATCHR_USER_AGENT}
            self.limiter.acquire()
            resp = requests.get(loc, headers=headers, timeout=IMAGE_REGISTRY_TIMEOUT,
                                allow_redirects=False)
            if resp.status_code == 401:
                token = self._anonymous_token(resp.headers.get("WWW-Authenticate", ""), (host,))
                if not token:
                    return resp
                headers["Authorization"] = f"Bearer {token}"
                resp = requests.get(loc, headers=headers, timeout=IMAGE_REGISTRY_TIMEOUT,
                                    allow_redirects=False)
            if not resp.is_redirect:
                return resp
        return None

    @staticmethod
    def _anonymous_token(challenge: str, auth_hosts: tuple[str, ...]) -> str | None:
        fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = fields.pop("realm", None)
        if not realm or not challenge.lower().startswith("bearer"):
            return None
        u = urlparse(realm)
        if u.scheme != "https" or (u.hostname or "").lower() not in auth_hosts:
            log(f"[!] image registry token realm {u.hostname!r} not allowed — skipped")
            return None
        try:
            r = requests.get(realm, params=fields, timeout=IMAGE_REGISTRY_TIMEOUT,
                             headers={"User-Agent": DKATCHR_USER_AGENT})
            if r.status_code != 200:
                return None
            body = r.json()
            return body.get("token") or body.get("access_token")
        except (requests.RequestException, ValueError):
            return None

    def resolve(self, registry: str, repository: str, reference: str) -> dict | None:
        """{digest, env: {NAME: value}, os, os_version, architecture} for a public
        image reference (tag or sha256 digest), or None."""
        reg = PUBLIC_IMAGE_REGISTRIES.get((registry or "").lower())
        if reg is None or not re.fullmatch(r"[a-z0-9][a-z0-9._/-]*", repository or "") \
                or not re.fullmatch(r"[\w.:+-]+", reference or ""):
            return None                                   # never contact unknown hosts
        ref = f"{registry}/{repository}:{reference}"
        hit, result = self._read(ref)
        if hit:
            return result
        if time.time() < self._rate_limited_until:
            return None
        auth = tuple(reg["auth"])
        base = f"https://{reg['api']}/v2/{repository}"
        token_box: dict = {}
        try:
            resp = self._get(f"{base}/manifests/{reference}", _ACCEPT, token_box, auth)
            if resp is None or resp.status_code != 200:
                status = getattr(resp, "status_code", None)
                if status == 429:
                    self._rate_limited_until = time.time() + IMAGE_REGISTRY_RATE_LIMIT_BACKOFF
                    log(f"[!] image registry rate limit ({registry}) — falling back to tag text")
                    return None
                self._write(ref, None)
                return None
            digest = resp.headers.get("Docker-Content-Digest")
            manifest = resp.json()
            if manifest.get("manifests"):                       # index -> pick linux/amd64
                plats = manifest["manifests"]
                pick = next((m for m in plats if (m.get("platform") or {}).get("os") == "linux"
                             and (m.get("platform") or {}).get("architecture") == "amd64"), None)
                pick = pick or next((m for m in plats if (m.get("platform") or {}).get("os")
                                     not in (None, "unknown")), plats[0])
                resp = self._get(f"{base}/manifests/{pick['digest']}", _ACCEPT, token_box, auth)
                if resp is None or resp.status_code != 200:
                    self._write(ref, None)
                    return None
                manifest = resp.json()
            cfg_digest = (manifest.get("config") or {}).get("digest")
            if not cfg_digest:
                self._write(ref, None)
                return None
            resp = self._get(f"{base}/blobs/{cfg_digest}", "*/*", token_box, auth)
            if resp is None or resp.status_code != 200:
                self._write(ref, None)
                return None
            cfg = resp.json()
        except (requests.RequestException, ValueError, KeyError, IndexError) as e:
            log(f"[!] image resolve {ref}: {e}")
            return None
        env = {}
        for item in (cfg.get("config") or {}).get("Env") or []:
            if "=" in item:
                k, v = item.split("=", 1)
                env[k] = v
        result = {"digest": digest, "env": env, "os": cfg.get("os"),
                  "os_version": cfg.get("os.version"), "architecture": cfg.get("architecture")}
        self._write(ref, result)
        return result
