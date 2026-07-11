"""
Shared HTTP helpers for registry resolvers.

WHY: every per-ecosystem resolver downloads a package artifact (wheel, gem,
JAR, .nupkg, zip) or queries a registry JSON endpoint. The download path has
a strict size guard so a hostile or accidentally enormous artifact cannot
exhaust memory — resolvers stream into a bounded BytesIO and never touch
disk. Network failures are converted into None returns, never raised, so a
single broken registry never aborts a batch.

Does NOT: cache, retry, write to disk, or know about ecosystems.
"""

import io
import json
from typing import Any

import requests

from dkatchr.logger import log


class RegistryResolverBase:
    """
    Common HTTP helpers for the per-ecosystem resolvers in this package.

    Subclasses set ``ECOSYSTEM`` (used in log lines) and implement
    ``resolve(package: str, version: str | None) -> tuple[list[str], str] | None``
    which returns ``(import_names, source)`` on success or ``None`` on any
    failure path.
    """

    ECOSYSTEM: str = "base"

    MAX_DOWNLOAD_BYTES: int = 50 * 1024 * 1024  # 50MB hard cap
    DEFAULT_TIMEOUT:    int = 30                # seconds per request

    USER_AGENT: str = "dkatchr/1.0 (+https://github.com/dkatchr)"

    # ---- HTTP ----------------------------------------------------------

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        h = {"User-Agent": self.USER_AGENT}
        if extra:
            h.update(extra)
        return h

    def _get_json(
        self,
        url: str,
        package: str,
        headers: dict[str, str] | None = None,
    ) -> dict | list | None:
        """GET + parse JSON. Returns None with explicit log on any failure."""
        try:
            resp = requests.get(
                url,
                headers=self._headers(headers),
                timeout=self.DEFAULT_TIMEOUT,
            )
        except requests.RequestException as e:
            log(f"[resolver] {self.ECOSYSTEM}/{package}: registry unreachable — {e}")
            return None

        if resp.status_code == 404:
            log(f"[resolver] {self.ECOSYSTEM}/{package}: not found (private package?)")
            return None
        if resp.status_code != 200:
            log(
                f"[resolver] {self.ECOSYSTEM}/{package}: unexpected response from "
                f"{url} — {resp.status_code}"
            )
            return None

        try:
            return resp.json()
        except (ValueError, json.JSONDecodeError) as e:
            log(f"[resolver] {self.ECOSYSTEM}/{package}: parse error — {e}")
            return None

    def _download_bytes(
        self,
        url: str,
        package: str,
        headers: dict[str, str] | None = None,
    ) -> bytes | None:
        """
        Stream-download into memory. Returns None on:
        - non-200 status
        - Content-Length or actual size exceeds MAX_DOWNLOAD_BYTES
        - any network/timeout error

        Never raises. Never writes to disk.
        """
        try:
            resp = requests.get(
                url,
                headers=self._headers(headers),
                timeout=self.DEFAULT_TIMEOUT,
                stream=True,
            )
        except requests.RequestException as e:
            log(f"[resolver] {self.ECOSYSTEM}/{package}: registry unreachable — {e}")
            return None

        with resp:
            if resp.status_code == 404:
                log(f"[resolver] {self.ECOSYSTEM}/{package}: not found (private package?)")
                return None
            if resp.status_code != 200:
                log(
                    f"[resolver] {self.ECOSYSTEM}/{package}: unexpected response from "
                    f"{url} — {resp.status_code}"
                )
                return None

            content_length = resp.headers.get("Content-Length")
            if content_length:
                try:
                    declared = int(content_length)
                except ValueError:
                    declared = -1
                if declared > self.MAX_DOWNLOAD_BYTES:
                    log(
                        f"[resolver] {self.ECOSYSTEM}/{package}: download exceeds "
                        f"{self.MAX_DOWNLOAD_BYTES // (1024 * 1024)}MB limit"
                    )
                    return None

            buf = io.BytesIO()
            try:
                for chunk in resp.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    if buf.tell() + len(chunk) > self.MAX_DOWNLOAD_BYTES:
                        log(
                            f"[resolver] {self.ECOSYSTEM}/{package}: download exceeds "
                            f"{self.MAX_DOWNLOAD_BYTES // (1024 * 1024)}MB limit"
                        )
                        return None
                    buf.write(chunk)
            except requests.RequestException as e:
                log(f"[resolver] {self.ECOSYSTEM}/{package}: registry unreachable — {e}")
                return None

            return buf.getvalue()

    # ---- subclass contract --------------------------------------------

    def resolve(
        self, package: str, version: str | None = None
    ) -> tuple[list[str], str] | None:  # pragma: no cover - abstract
        raise NotImplementedError
