"""
crates.io import-name resolver.

WHY: a Cargo crate's in-source `use` name is the crate's `lib_name` (which
defaults to the crate name with hyphens normalized to underscores, but can
be overridden in `Cargo.toml` via `[lib] name = "..."`). The crates.io API
exposes `lib_name` directly on the version response — no binary download.

Must send a descriptive User-Agent; crates.io rejects requests without one.
"""

from dkatchr.clients.resolvers._base import RegistryResolverBase
from dkatchr.logger import log

_CRATE_VERSION = "https://crates.io/api/v1/crates/{crate}/{version}"
_CRATE_LATEST  = "https://crates.io/api/v1/crates/{crate}"


class CratesResolver(RegistryResolverBase):
    ECOSYSTEM = "crates.io"

    def resolve(
        self, package: str, version: str | None = None
    ) -> tuple[list[str], str] | None:
        resolved_version = version
        if not resolved_version:
            data = self._get_json(_CRATE_LATEST.format(crate=package), package)
            if not isinstance(data, dict):
                return None
            crate_meta = data.get("crate")
            if isinstance(crate_meta, dict):
                resolved_version = crate_meta.get("max_stable_version") or crate_meta.get("max_version")
            if not isinstance(resolved_version, str) or not resolved_version:
                log(f"[resolver] crates.io/{package}: parse error — no max stable version")
                return None

        data = self._get_json(
            _CRATE_VERSION.format(crate=package, version=resolved_version),
            package,
        )
        if not isinstance(data, dict):
            return None

        version_meta = data.get("version")
        if isinstance(version_meta, dict):
            lib_name = version_meta.get("lib_name")
            if isinstance(lib_name, str) and lib_name:
                return [lib_name], "cargo_api_lib_name"

        normalized = package.replace("-", "_").lower()
        return [normalized], "cargo_name_normalized"
