"""
RubyGems require-name resolver.

WHY: most gems use a `require` name that matches the gem name, but bundler/
autoload ecosystems (Rails) almost never write `require 'rails'`, and many
gems expose a different top-level constant than the gem name suggests
(`activerecord` → `ActiveRecord`, `omniauth-oauth2` → `OmniAuth::OAuth2`).
The authoritative source is the gem's `lib/` directory: any `lib/foo.rb`
is a valid `require 'foo'`, and any `lib/foo/` directory is the namespace
root that callers `require` then access as `Foo::Whatever`.

A `.gem` file is an outer ustar tarball containing `metadata.gz` plus
`data.tar.gz`. The lib/ contents live inside `data.tar.gz`.

Meta-gems (e.g. `rails`) ship only as a dependency declaration — no `lib/`,
no code. For those the lib/-based path finds nothing. We fall back to
returning the gem name itself, so downstream pattern generation can still
derive `Rails::` / `Rails.` via the existing module-candidate algorithm.
The fallback is narrow: only triggered when `lib/` is genuinely empty.

Does NOT: cache, normalize names.
"""

import io
import os
import tarfile

from dkatchr.clients.resolvers._base import RegistryResolverBase
from dkatchr.logger import log

_RUBYGEMS_API = "https://rubygems.org/api/v1/gems/{gem}.json"


class RubyGemsResolver(RegistryResolverBase):
    ECOSYSTEM = "rubygems"

    def resolve(
        self, package: str, version: str | None = None
    ) -> tuple[list[str], str] | None:
        url = _RUBYGEMS_API.format(gem=package)
        data = self._get_json(url, package)
        if not isinstance(data, dict):
            return None

        gem_uri = data.get("gem_uri")
        if not isinstance(gem_uri, str) or not gem_uri:
            log(f"[resolver] rubygems/{package}: unexpected response from {url} — no gem_uri")
            return None

        blob = self._download_bytes(gem_uri, package)
        if blob is None:
            return None

        try:
            outer = tarfile.open(fileobj=io.BytesIO(blob), mode="r:")
        except tarfile.TarError as e:
            log(f"[resolver] rubygems/{package}: parse error — bad gem tar: {e}")
            return None

        with outer:
            data_member = None
            for member in outer.getmembers():
                if member.isfile() and member.name == "data.tar.gz":
                    data_member = member
                    break
            if data_member is None:
                log(f"[resolver] rubygems/{package}: parse error — no data.tar.gz in .gem")
                return None

            try:
                f = outer.extractfile(data_member)
                if f is None:
                    log(f"[resolver] rubygems/{package}: parse error — data.tar.gz unreadable")
                    return None
                inner_bytes = f.read()
            except Exception as e:
                log(f"[resolver] rubygems/{package}: parse error — extracting data.tar.gz: {e}")
                return None

        try:
            inner = tarfile.open(fileobj=io.BytesIO(inner_bytes), mode="r:gz")
        except tarfile.TarError as e:
            log(f"[resolver] rubygems/{package}: parse error — bad inner tar: {e}")
            return None

        requires: set[str] = set()
        with inner:
            for member in inner.getmembers():
                name = member.name.lstrip("./")
                # Direct .rb files under lib/: lib/nokogiri.rb → "nokogiri".
                # NOT lib/nokogiri/parser.rb.
                if member.isfile() and name.startswith("lib/") and name.endswith(".rb"):
                    rest = name[len("lib/"):]
                    if "/" not in rest:
                        requires.add(rest[:-3])
                        continue
                # Direct subdirectories under lib/: lib/nokogiri/ → "nokogiri".
                if member.isdir() and name.startswith("lib/"):
                    rest = name[len("lib/"):].rstrip("/")
                    if rest and "/" not in rest:
                        requires.add(rest)

            # Some gem tarballs do not emit explicit directory entries —
            # infer subdirectories from file paths as a fallback.
            if not requires:
                for member in inner.getmembers():
                    if not member.isfile():
                        continue
                    name = member.name.lstrip("./")
                    if not name.startswith("lib/"):
                        continue
                    rest = name[len("lib/"):]
                    if "/" in rest:
                        first = rest.split("/", 1)[0]
                        if first:
                            requires.add(first)
                    elif rest.endswith(".rb"):
                        requires.add(rest[:-3])

        if not requires:
            # Meta-gem (rails et al.) — the gem unpacked fine but has no
            # code in lib/. Return the gem name itself; reachability's
            # `_ruby_module_candidates_from_require` will turn `rails`
            # into `Rails`, `omniauth-oauth2` into `Omniauth::Oauth2`,
            # etc. Better than UNKNOWN for every Rails-app's `rails` row.
            log(
                f"[resolver] rubygems/{package}: lib/ empty — meta-gem fallback "
                f"to gem name for module patterns"
            )
            return [package], "gem_name_fallback"

        return sorted(requires), "gem_lib_files"
