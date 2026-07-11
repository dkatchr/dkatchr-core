"""Packagist (Composer): composer.json (declared), composer.lock (resolved)."""

import json

from dkatchr.parsers._common import clean_declared_version


def from_composer_json(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except Exception:
        return []
    deps = []
    for section in ("require", "require-dev"):
        for name, ver in (data.get(section) or {}).items():
            if not isinstance(ver, str):
                continue
            cleaned = clean_declared_version(ver)
            if cleaned:
                deps.append({"package": name, "version": cleaned, "version_source": "declared"})
    return deps


def _lock_origin(pkg: dict) -> str | None:
    """Best-effort non-registry origin for a composer.lock package entry.

    Discriminator (verified against Composer's source, not just docs):
    `notification-url` is written into lock entries ONLY by registry-type
    repositories (ComposerRepository — packagist.org or a private Composer
    registry), while PathRepository writes `dist.type == "path"` and VCS
    repositories leave only `source.type == "git"`. So:
      - notification-url pointing at packagist.org → registry (None)
      - else dist.type "path" → "path"; source.type "git" → "git";
        a bare dist URL → "url"; nothing recognizable → registry (conservative).
    A private Composer registry's packages (non-packagist notification-url)
    classify by their source/dist type — i.e. as non-public-registry — which is
    exactly the confusion-relevant signal. Best-effort by design; see CLAUDE.md.
    """
    notif = pkg.get("notification-url") or ""
    if "packagist.org" in notif:
        return None
    dist = pkg.get("dist") or {}
    src  = pkg.get("source") or {}
    if (dist.get("type") or "") == "path":
        return "path"
    if (src.get("type") or "") == "git":
        return "git"
    if dist.get("url"):
        return "url"
    return None


def _lock_resolved_url(pkg: dict) -> str | None:
    """URL evidence for the Dependency Confusion Exposure check: prefer the
    registry's notification-url (packagist.org for public; a private Composer
    registry writes its own), falling back to dist.url then source.url."""
    for candidate in (pkg.get("notification-url"),
                      (pkg.get("dist") or {}).get("url"),
                      (pkg.get("source") or {}).get("url")):
        if isinstance(candidate, str) and candidate:
            return candidate
    return None


def from_composer_lock(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except Exception:
        return []
    deps = []
    for section in ("packages", "packages-dev"):
        for pkg in (data.get(section) or []):
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            ver  = (pkg.get("version") or "").lstrip("v")
            if name and ver:
                dep = {"package": name, "version": ver, "version_source": "resolved"}
                origin = _lock_origin(pkg)
                if origin:
                    dep["origin"] = origin
                resolved_url = _lock_resolved_url(pkg)
                if resolved_url:
                    dep["resolved_url"] = resolved_url
                deps.append(dep)
    return deps
