"""
GitHubClient — wraps GitHub REST API calls with rate limiting + retry handling.

MOVED FROM: dkatchr/github_client.py
WHY: Network I/O belongs in clients/. Single responsibility — fetch from
GitHub, nothing else. Scanner/CLI consume this as a dependency.

Handles:
  - Auth header (GITHUB_TOKEN env var or explicit token)
  - TokenBucket rate limiting
  - Primary rate-limit retries (X-RateLimit-Remaining=0 → sleep until reset)
  - Secondary rate-limit retries (Retry-After header)
  - Pagination
  - High-level helpers: list_user_orgs, list_org_repos, get_repo_meta,
    get_branch_sha, get_repo_tree, fetch_file
"""

import base64
import json
import os
import time
from urllib.parse import quote

import requests

from typing import Callable

from dkatchr.clients.ratelimit import TokenBucket
from dkatchr.config import (
    ATTRIBUTION_BOT_PATTERNS,
    GITHUB_API_BASE,
    GITHUB_GRAPHQL_URL,
    GITHUB_PAGE_SIZE,
    REACHABILITY_DOWNLOAD_CHUNK_BYTES,
    REACHABILITY_TARBALL_MAX_BYTES,
)
from dkatchr.logger import log


def _is_bot_author(handle: str | None, name: str | None) -> bool:
    """True when a commit author looks automated rather than human.

    A handle ending in "[bot]" is GitHub's canonical bot marker. Otherwise we
    match the author handle/name against ATTRIBUTION_BOT_PATTERNS (dependabot,
    renovate, snyk-bot, github-actions, …) case-insensitively. Kept here next to
    get_file_blame (which produces the `is_bot` flag) rather than in core, so
    core/attribution.py stays pure — it consumes blame dicts, doesn't classify.
    """
    h = (handle or "").strip().lower()
    n = (name or "").strip().lower()
    if h.endswith("[bot]") or n.endswith("[bot]"):
        return True
    for pat in ATTRIBUTION_BOT_PATTERNS:
        p = pat.lower()
        if p and (p in h or p in n):
            return True
    return False


class GitHubClient:
    def __init__(
        self,
        rps: float,
        burst: float,
        api_base: str = GITHUB_API_BASE,
        token: str | None = None,
    ) -> None:
        self.api_base = api_base
        self.token    = token if token is not None else os.environ.get("GITHUB_TOKEN", "")
        self.limiter  = TokenBucket(rate=rps, capacity=burst)
        if not self.token:
            log("[!] GITHUB_TOKEN is not set — requests will be unauthenticated (very low rate limit).")

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    # ---- core HTTP ------------------------------------------------------

    def get(self, url: str, params: dict | None = None, max_retries: int = 5) -> requests.Response:
        """
        Rate-limited GET with primary + secondary rate-limit retry handling.
        """
        last_resp: requests.Response | None = None
        for _ in range(max_retries):
            self.limiter.acquire()
            resp = requests.get(url, headers=self._headers(), params=params or {}, timeout=30)
            last_resp = resp

            if resp.status_code in (403, 429):
                retry_after = resp.headers.get("Retry-After")
                remaining   = resp.headers.get("X-RateLimit-Remaining")

                if retry_after:
                    try:
                        wait = max(1, int(float(retry_after)))
                    except ValueError:
                        wait = 30
                    log(f"[!] Rate limited (HTTP {resp.status_code}). Sleeping {wait}s (Retry-After).")
                    time.sleep(wait + 1)
                    continue

                if remaining == "0":
                    reset = resp.headers.get("X-RateLimit-Reset")
                    try:
                        wait = max(1, int(reset) - int(time.time()))
                    except (TypeError, ValueError):
                        wait = 60
                    log(f"[!] Primary rate limit exhausted. Sleeping {wait}s until reset.")
                    time.sleep(wait + 1)
                    continue

                break

            if resp.status_code >= 400:
                break

            return resp

        if last_resp is not None:
            log(f"[HTTP {last_resp.status_code}] GET {url}")
            try:
                log(json.dumps(last_resp.json())[:400])
            except Exception:
                log(last_resp.text[:400])
            last_resp.raise_for_status()
        raise RuntimeError(f"github_get failed for {url}")

    def paginate(self, url: str, params: dict | None = None) -> list:
        results: list = []
        page = 1
        base = dict(params or {})
        base["per_page"] = GITHUB_PAGE_SIZE
        while True:
            base["page"] = page
            data = self.get(url, params=base).json()
            if not data:
                break
            results.extend(data)
            if len(data) < GITHUB_PAGE_SIZE:
                break
            page += 1
        return results

    # ---- high-level helpers --------------------------------------------

    def list_user_orgs(self) -> list[str]:
        log("[+] Discovering orgs via GET /user/orgs...")
        data = self.paginate(f"{self.api_base}/user/orgs")
        orgs = [o["login"] for o in data if isinstance(o, dict) and o.get("login")]
        log(f"    {len(orgs)} org(s) discovered: {orgs}")
        return orgs

    def list_org_repos(self, org: str) -> list:
        log(f"[+] Fetching repos for org '{org}'...")
        repos = self.paginate(f"{self.api_base}/orgs/{org}/repos", {"type": "all"})
        log(f"    {len(repos)} repos found.")
        return repos

    def get_repo_meta(self, owner: str, name: str) -> dict:
        return self.get(f"{self.api_base}/repos/{owner}/{name}").json()

    def list_repo_languages(self, owner: str, name: str) -> dict[str, int]:
        """Return GitHub Linguist's language breakdown for a repo.

        Result is `{language_name: bytes_of_code}` — e.g. `{"Python": 12345, "Go": 678}`.
        An empty dict means the repo has no recognised source files (a common
        case for manifest-only test repos). One regular REST call; uses the
        main rate-limit budget, not the strict code-search bucket.
        """
        try:
            data = self.get(f"{self.api_base}/repos/{owner}/{name}/languages").json()
            return data if isinstance(data, dict) else {}
        except Exception as e:
            log(f"[!] list_repo_languages({owner}/{name}) failed: {e}")
            return {}

    def get_branch_sha(self, owner: str, repo: str, branch: str) -> str:
        url  = f"{self.api_base}/repos/{owner}/{repo}/git/refs/heads/{branch}"
        data = self.get(url).json()
        if isinstance(data, list):
            data = data[0]
        return data["object"]["sha"]

    def get_repo_tree(self, owner: str, repo: str, sha: str) -> list:
        url  = f"{self.api_base}/repos/{owner}/{repo}/git/trees/{sha}"
        data = self.get(url, {"recursive": "1"}).json()
        return data.get("tree", [])

    def fetch_file(self, owner: str, repo: str, path: str, ref: str) -> str:
        url  = f"{self.api_base}/repos/{owner}/{repo}/contents/{quote(path, safe='/')}"
        data = self.get(url, {"ref": ref}).json()
        if isinstance(data, list):
            return ""
        content  = data.get("content", "")
        encoding = data.get("encoding", "base64")
        if encoding == "base64":
            try:
                return base64.b64decode(content).decode("utf-8", errors="replace")
            except Exception:
                return ""
        return content

    # ---- attribution helpers -------------------------------------------

    def get_file_contents(self, owner: str, repo: str, path: str, ref: str) -> str:
        """Raw text of a single file at `ref` via the REST contents API.

        Unlike fetch_file (which swallows errors into ""), this is the
        attribution pass's content fetch: it goes through self.get() (which
        acquires a rate-limit token and raises via raise_for_status on a
        non-2xx after the retry budget), then base64-decodes the payload.
        Raises on a directory response or a malformed/undecodable body so the
        caller can fall back to an empty AttributionResult for that manifest.
        """
        url  = f"{self.api_base}/repos/{owner}/{repo}/contents/{quote(path, safe='/')}"
        data = self.get(url, {"ref": ref}).json()  # self.get → limiter.acquire() + raise_for_status
        if isinstance(data, list):
            raise ValueError(f"{owner}/{repo}:{path} is a directory, not a file")
        content  = data.get("content", "")
        encoding = data.get("encoding", "base64")
        if encoding == "base64":
            return base64.b64decode(content).decode("utf-8", errors="replace")
        return content

    def get_file_blame(self, owner: str, repo: str, path: str, ref: str) -> list[dict]:
        """Git blame for a single file at `ref`, via the GraphQL v4 API.

        REST has no blame endpoint, so commit-line attribution requires
        GraphQL. Returns a flat list of range dicts:

            {sha, message, date, author_name, author_email, author_handle,
             start_line, end_line, is_bot}

        `ref` is resolved with `object(expression: $ref)`, which accepts a raw
        commit SHA (what the scanner records), a branch name, or a tree-ish —
        so we blame at the exact scanned commit. The token bucket is acquired
        before the POST. Returns [] on ANY exception (network, GraphQL error,
        unexpected shape): attribution is best-effort and must never propagate
        a failure into the scan.
        """
        query = """
        query($owner: String!, $repo: String!, $ref: String!, $path: String!) {
          repository(owner: $owner, name: $repo) {
            object(expression: $ref) {
              ... on Commit {
                blame(path: $path) {
                  ranges {
                    commit {
                      oid
                      message
                      committedDate
                      author { name email user { login } }
                    }
                    startingLine
                    endingLine
                  }
                }
              }
            }
          }
        }
        """
        variables = {"owner": owner, "repo": repo, "ref": ref, "path": path}
        try:
            self.limiter.acquire()
            resp = requests.post(
                GITHUB_GRAPHQL_URL,
                headers=self._headers(),
                json={"query": query, "variables": variables},
                timeout=30,
            )
            if resp.status_code != 200:
                log(f"[attribution] blame HTTP {resp.status_code} for {owner}/{repo}:{path}")
                return []
            body = resp.json()
            if body.get("errors"):
                log(f"[attribution] blame GraphQL errors for {owner}/{repo}:{path}: {body['errors']}")
                return []
            commit = (((body.get("data") or {}).get("repository") or {}).get("object")) or {}
            ranges = ((commit.get("blame") or {}).get("ranges")) or []
            out: list[dict] = []
            for rng in ranges:
                c = rng.get("commit") or {}
                author = c.get("author") or {}
                user = author.get("user") or {}
                handle = user.get("login")
                name = author.get("name")
                out.append({
                    "sha":           c.get("oid"),
                    "message":       c.get("message"),
                    "date":          c.get("committedDate"),
                    "author_name":   name,
                    "author_email":  author.get("email"),
                    "author_handle": handle,
                    "start_line":    rng.get("startingLine"),
                    "end_line":      rng.get("endingLine"),
                    "is_bot":        _is_bot_author(handle, name),
                })
            return out
        except Exception as e:
            log(f"[attribution] blame failed for {owner}/{repo}:{path}: {e}")
            return []

    def open_repo_tarball_stream(
        self,
        repo_full_name: str,
        ref: str = "HEAD",
        on_progress: Callable[[int, int | None], None] | None = None,
    ) -> tuple["_TarballStream | None", str]:
        """
        Open a streaming, file-like reader over the repo tarball at `ref`.

        Returns ``(stream, "ok")`` on success or ``(None, reason)`` on any
        pre-stream failure. The stream MUST be used as a context manager; it
        owns the underlying HTTP connection and the size-cap accounting.

        Designed for ``tarfile.open(mode="r|gz", fileobj=stream)`` so the
        gzipped tarball is decompressed and walked one tar member at a time
        with no full-archive buffering. A 1GB tarball never touches memory
        — peak usage is one tar member's content (capped at REACHABILITY_MAX_FILE_BYTES).

        Reasons emitted by this method (pre-stream failures only):
          - "ok"
          - "http_{status}"          (e.g. "http_404", "http_403", "http_502")
          - "network_error: {msg}"   (DNS, refused, TLS, etc — before any bytes)
          - "too_large_declared_{MB}MB"  (rare — CDN usually sends chunked)

        Failures *during* streaming (cap exceeded, dropped connection) are
        signalled by ``stream.failure_reason`` after the iteration ends and
        by raising :class:`TarballSizeExceeded` mid-read for the cap case.

        Counts against the standard REST rate limit (5000/hr).

        GitHub responds with a 302 redirect to a CDN URL. The Authorization
        header must NOT be forwarded to the CDN — `requests` strips it
        automatically when the redirect crosses to a different host, but we
        also use a fresh Session with `trust_env=False` for predictability.
        """
        url = f"{self.api_base}/repos/{repo_full_name}/tarball/{ref}"
        self.limiter.acquire()

        try:
            session = requests.Session()
            session.trust_env = False
            resp = session.get(
                url,
                headers=self._headers(),
                allow_redirects=True,
                stream=True,
                # (connect_timeout, read_timeout). Big monorepos take a while;
                # 120s per individual chunk read is generous but bounded.
                timeout=(30, 120),
            )
        except Exception as e:
            reason = f"network_error: {type(e).__name__}: {e}"[:200]
            log(f"[!] tarball download failed for {repo_full_name}: {reason}")
            return None, reason

        if resp.status_code != 200:
            reason = f"http_{resp.status_code}"
            log(f"[!] tarball HTTP {resp.status_code} for {repo_full_name}")
            resp.close()
            return None, reason

        # CDN almost always uses Transfer-Encoding: chunked (no Content-Length),
        # but parse it when present so we can fail fast on an over-cap header.
        total: int | None = None
        cl = resp.headers.get("Content-Length")
        if cl:
            try:
                total = int(cl)
            except ValueError:
                total = None

        if total is not None and total > REACHABILITY_TARBALL_MAX_BYTES:
            size_mb = total / 1024 / 1024
            cap_mb = REACHABILITY_TARBALL_MAX_BYTES / 1024 / 1024
            log(
                f"[!] tarball for {repo_full_name} is {size_mb:.1f}MB "
                f"(> {cap_mb:.0f}MB cap) — skipping. "
                f"Raise DKATCHR_REACHABILITY_TARBALL_MAX_BYTES if needed."
            )
            resp.close()
            return None, f"too_large_declared_{size_mb:.0f}MB"

        return _TarballStream(
            response=resp,
            total_bytes=total,
            max_bytes=REACHABILITY_TARBALL_MAX_BYTES,
            chunk_size=REACHABILITY_DOWNLOAD_CHUNK_BYTES,
            on_progress=on_progress,
            repo_full_name=repo_full_name,
        ), "ok"


class TarballSizeExceeded(Exception):
    """Raised mid-stream when the size cap is hit. Carries a short reason."""
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _TarballStream:
    """File-like wrapper around a streaming requests response.

    Designed for ``tarfile.open(mode="r|gz", fileobj=self)``. Each ``read(n)``
    pulls from the underlying socket, ticks the progress callback, and
    enforces the byte-count cap. The HTTP connection is released by the
    context manager exit.

    After successful iteration ``failure_reason`` is ``None``; on a graceful
    abort (cap exceeded) it carries a short machine-parseable reason like
    ``"too_large_streamed_487MB"``.
    """

    def __init__(
        self,
        response: requests.Response,
        total_bytes: int | None,
        max_bytes: int,
        chunk_size: int,
        on_progress: Callable[[int, int | None], None] | None,
        repo_full_name: str,
    ) -> None:
        self._response       = response
        self._raw            = response.raw
        self._raw.decode_content = False  # tarfile mode="r|gz" handles gzip itself
        self._total          = total_bytes
        self._max            = max_bytes
        self._chunk          = chunk_size
        self._on_progress    = on_progress
        self._repo           = repo_full_name
        self.bytes_read: int = 0
        self.failure_reason: str | None = None
        self._last_emit_bytes: int = 0

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self._chunk
        try:
            data = self._raw.read(size)
        except Exception as e:
            self.failure_reason = f"stream_error: {type(e).__name__}: {e}"[:200]
            log(f"[!] tarball stream failed for {self._repo}: {self.failure_reason}")
            raise

        if not data:
            return data

        self.bytes_read += len(data)
        if self.bytes_read > self._max:
            cap_mb = self._max / 1024 / 1024
            size_mb = self.bytes_read / 1024 / 1024
            log(
                f"[!] tarball for {self._repo} exceeded {cap_mb:.0f}MB mid-stream "
                f"— aborting. Raise DKATCHR_REACHABILITY_TARBALL_MAX_BYTES if needed."
            )
            reason = f"too_large_streamed_{size_mb:.0f}MB"
            self.failure_reason = reason
            raise TarballSizeExceeded(reason)

        # Throttle the progress callback to one tick per chunk_size of bytes
        # so we don't fire 4× per chunk if tarfile reads in small slices.
        if self._on_progress is not None and (
            self.bytes_read - self._last_emit_bytes >= self._chunk
        ):
            self._last_emit_bytes = self.bytes_read
            try:
                self._on_progress(self.bytes_read, self._total)
            except Exception:
                pass  # progress emit must never break the stream

        return data

    def __enter__(self) -> "_TarballStream":
        return self

    def __exit__(self, *exc) -> None:
        try:
            self._response.close()
        except Exception:
            pass
