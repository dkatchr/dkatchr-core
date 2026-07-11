"""
PyPI import-name resolver.

WHY: install name and import name diverge in PyPI more than any other
ecosystem (`beautifulsoup4` → `bs4`, `pillow` → `PIL`, etc). The wheel
contains the authoritative answer in `*.dist-info/top_level.txt`. Fall
back to inspecting the wheel's top-level directories, and finally to the
sdist's `*.egg-info/top_level.txt` when only an sdist is published.

Does NOT: write to disk, cache, or normalize names.
"""

import io
import os
import tarfile
import zipfile

from dkatchr.clients.resolvers._base import RegistryResolverBase
from dkatchr.logger import log

_PYPI_API = "https://pypi.org/pypi/{package}/json"


class PyPIResolver(RegistryResolverBase):
    ECOSYSTEM = "pypi"

    def resolve(
        self, package: str, version: str | None = None
    ) -> tuple[list[str], str] | None:
        url = _PYPI_API.format(package=package)
        data = self._get_json(url, package)
        if not isinstance(data, dict):
            return None

        urls = data.get("urls") or []
        if not isinstance(urls, list):
            return None

        wheel = _pick_wheel(urls)
        sdist = _pick_sdist(urls)

        # Try wheel first.
        if wheel is not None:
            wheel_url = wheel.get("url")
            if isinstance(wheel_url, str):
                blob = self._download_bytes(wheel_url, package)
                if blob is not None:
                    result = _from_wheel(blob, package)
                    if result is not None:
                        return result

        # Fall through to sdist.
        if sdist is not None:
            sdist_url = sdist.get("url")
            if isinstance(sdist_url, str):
                blob = self._download_bytes(sdist_url, package)
                if blob is not None:
                    result = _from_sdist(blob, package)
                    if result is not None:
                        return result

        log(f"[resolver] {self.ECOSYSTEM}/{package}: parse error — no wheel/sdist yielded names")
        return None


# ---- helpers ---------------------------------------------------------------


def _pick_wheel(urls: list[dict]) -> dict | None:
    """Prefer a `none-any.whl` (pure-Python) wheel, else the first wheel."""
    wheels = [u for u in urls if isinstance(u, dict) and u.get("packagetype") == "bdist_wheel"]
    if not wheels:
        return None
    for u in wheels:
        fn = u.get("filename") or ""
        if isinstance(fn, str) and fn.endswith("-none-any.whl"):
            return u
    return wheels[0]


def _pick_sdist(urls: list[dict]) -> dict | None:
    for u in urls:
        if isinstance(u, dict) and u.get("packagetype") == "sdist":
            return u
    return None


def _from_wheel(blob: bytes, package: str) -> tuple[list[str], str] | None:
    """Wheel → top_level.txt (primary), or directory structure (fallback)."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile as e:
        log(f"[resolver] pypi/{package}: parse error — bad wheel zip: {e}")
        return None

    with zf:
        names = zf.namelist()

        # Primary: dist-info/top_level.txt
        for entry in names:
            if entry.endswith(".dist-info/top_level.txt"):
                try:
                    content = zf.read(entry).decode("utf-8", errors="ignore")
                except KeyError:
                    continue
                imports = [
                    line.strip()
                    for line in content.splitlines()
                    if line.strip()
                ]
                if imports:
                    return imports, "wheel_top_level"

        # Fallback: top-level directories that are not dist-info / data.
        tops: set[str] = set()
        for entry in names:
            # Skip nested-only entries: we want the first path segment that
            # represents an importable package.
            first, _, _ = entry.partition("/")
            if not first:
                continue
            if first.endswith(".dist-info") or first.endswith(".data"):
                continue
            # An importable package must have an __init__.py or be a single
            # top-level .py module sitting directly in the zip root.
            if "/" not in entry and entry.endswith(".py"):
                tops.add(entry[:-3])
                continue
            if "/" in entry:
                tops.add(first)

        if tops:
            return sorted(tops), "wheel_directory_structure"

    return None


def _from_sdist(blob: bytes, package: str) -> tuple[list[str], str] | None:
    """Sdist (.tar.gz) → egg-info/top_level.txt or PKG-INFO Name."""
    try:
        tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:*")
    except tarfile.TarError as e:
        log(f"[resolver] pypi/{package}: parse error — bad sdist tar: {e}")
        return None

    with tf:
        for member in tf:
            if not member.isfile():
                continue
            name = member.name
            base = os.path.basename(name)
            parts = name.split("/")
            if base == "top_level.txt" and any(p.endswith(".egg-info") for p in parts):
                try:
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    content = f.read().decode("utf-8", errors="ignore")
                except Exception:
                    continue
                imports = [
                    line.strip()
                    for line in content.splitlines()
                    if line.strip()
                ]
                if imports:
                    return imports, "sdist_egg_info"

        # PKG-INFO fallback: extract the `Name:` header, normalize to a
        # likely module name. This is a weak fallback — the actual import
        # name may diverge — but it is still better than nothing for an
        # sdist-only package with no egg-info.
        for member in tf:
            if member.isfile() and os.path.basename(member.name) == "PKG-INFO":
                try:
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    content = f.read().decode("utf-8", errors="ignore")
                except Exception:
                    continue
                for line in content.splitlines():
                    if line.startswith("Name:"):
                        name_val = line.split(":", 1)[1].strip()
                        if name_val:
                            normalized = name_val.lower().replace("-", "_")
                            return [normalized], "sdist_egg_info"
                break

    return None
