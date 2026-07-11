"""
NuGet namespace resolver.

WHY: a NuGet package ID often resembles the namespace exposed by its DLLs
but is not authoritative — `Microsoft.AspNetCore.Mvc.Core` contains types
under `Microsoft.AspNetCore.Mvc.*`. The .nupkg is a zip; its `lib/` folder
contains the .NET assemblies (.dll); the assemblies' metadata tables list
the actual namespaces. `dotnetfile` parses the CLR metadata tables.

Filtered out: CLR built-ins (`System`, `Microsoft.CSharp`,
`Microsoft.VisualBasic`) and `<Module>`. Truncated to two dot-separated
segments to avoid over-specific patterns like `Newtonsoft.Json.Linq` that
would miss `using Newtonsoft.Json;`.

Does NOT: handle .NET native images, signed catalog files, or analyzer
DLLs (those live outside `lib/`).
"""

import io
import zipfile

from dkatchr.clients.resolvers._base import RegistryResolverBase
from dkatchr.logger import log

# Flat-container endpoints are simpler and more reliable than registration5:
# the index returns a plain {"versions": [...]} list; the download URL is
# deterministic. registration5 is paginated for large packages and redirects
# to registration5-gz for compressed responses — both cause 404s in some
# environments. Flat-container is the canonical stable API.
_NUGET_FLAT_INDEX = "https://api.nuget.org/v3-flatcontainer/{id_lower}/index.json"
_NUGET_DL         = "https://api.nuget.org/v3-flatcontainer/{id_lower}/{version_lower}/{id_lower}.{version_lower}.nupkg"

# CLR / framework namespaces that should never count as a package's "own"
# namespace — every .NET DLL references types from these.
_CLR_BUILTINS: frozenset[str] = frozenset({
    "System",
    "Microsoft.CSharp",
    "Microsoft.VisualBasic",
    "Microsoft.Win32",
    "Microsoft.Internal",
})

# Subfolders under .nupkg that are NOT runtime assemblies.
_NUGET_NON_LIB_DIRS: tuple[str, ...] = ("ref/", "tools/", "build/", "analyzers/")


class NuGetResolver(RegistryResolverBase):
    ECOSYSTEM = "nuget"

    def resolve(
        self, package: str, version: str | None = None
    ) -> tuple[list[str], str] | None:
        try:
            from dotnetfile import DotNetPE  # type: ignore
        except ImportError:
            log(
                f"[resolver] nuget/{package}: parse error — dotnetfile not installed; "
                "add `dotnetfile` to requirements.txt"
            )
            return None

        id_lower = package.lower()
        resolved_version = version
        if not resolved_version:
            index_url = _NUGET_FLAT_INDEX.format(id_lower=id_lower)
            data = self._get_json(index_url, package)
            if not isinstance(data, dict):
                return None
            versions = data.get("versions")
            if not isinstance(versions, list) or not versions:
                log(f"[resolver] nuget/{package}: unexpected response from {index_url} — no versions list")
                return None
            resolved_version = versions[-1]  # flat-container lists versions oldest→newest

        version_lower = resolved_version.lower()
        url = _NUGET_DL.format(id_lower=id_lower, version_lower=version_lower)
        blob = self._download_bytes(url, package)
        if blob is None:
            return None

        try:
            zf = zipfile.ZipFile(io.BytesIO(blob))
        except zipfile.BadZipFile as e:
            log(f"[resolver] nuget/{package}: parse error — bad nupkg zip: {e}")
            return None

        with zf:
            dll_entries = [
                name for name in zf.namelist()
                if name.lower().endswith(".dll")
                and name.startswith("lib/")
                and not any(name.startswith(skip) for skip in _NUGET_NON_LIB_DIRS)
            ]
            if not dll_entries:
                # Content-only package (e.g. jQuery, Bootstrap distributed as NuGet).
                # These contain CSS/JS in content/ with no managed DLLs — there are no
                # C# namespaces to extract. Return empty list; caller emits UNKNOWN.
                # This is correct: a JS/CSS lib has no C# import patterns to match.
                log(f"[resolver] nuget/{package}: content-only package — no lib/ DLLs; no C# namespaces")
                return [], "content_only"

            namespaces: set[str] = set()
            for entry in dll_entries:
                try:
                    dll_bytes = zf.read(entry)
                except Exception as e:
                    log(f"[resolver] nuget/{package}: parse error — reading {entry}: {e}")
                    continue
                try:
                    namespaces.update(_extract_namespaces(dll_bytes, DotNetPE))
                except Exception as e:
                    log(f"[resolver] nuget/{package}: parse error — {entry}: {e}")
                    continue

        cleaned = _filter_namespaces(namespaces)
        if not cleaned and dll_entries:
            # All DLLs failed to yield namespaces — most common cause is mixed-mode
            # C++/CLI assemblies (e.g. CefSharp, OpenCV wrappers) which interleave
            # native and managed code in ways dotnetfile cannot parse. Fall back to
            # a namespace derived from the package ID: `CefSharp.Common` → `CefSharp`,
            # `Telerik.Windows.Controls.Navigation` → `Telerik.Windows`. This is a
            # reliable heuristic because .NET package naming convention almost always
            # matches the root namespace. Prefers false positives over false negatives
            # per the reachability design rules.
            fallback = _namespace_from_package_id(package)
            if fallback:
                log(
                    f"[resolver] nuget/{package}: dotnetfile failed on all {len(dll_entries)} DLL(s) "
                    f"(likely mixed-mode/native); falling back to package-name namespace '{fallback}'"
                )
                return [fallback], "package_name_fallback"
            log(f"[resolver] nuget/{package}: parse error — no usable namespaces extracted")
            return None
        if not cleaned:
            log(f"[resolver] nuget/{package}: parse error — no usable namespaces extracted")
            return None

        return sorted(cleaned), "dotnetfile_namespace"


def _extract_namespaces(dll_bytes: bytes, dotnet_pe_cls) -> set[str]:
    # dotnetfile >= 0.2.x: DotNetPE's first arg is `file_ref` and the parser
    # dispatches on isinstance(file_ref, bytes) — so passing the DLL bytes
    # positionally avoids a temp file. The old `data=` kwarg was removed.
    # Metadata access also changed: rows now live on
    # `metadata_tables_lookup[name].table_rows`, and TypeNamespace is read
    # via the row's `string_stream_references` indirection into the
    # `#Strings` heap (pe.get_string(addr)).
    pe = dotnet_pe_cls(dll_bytes)
    out: set[str] = set()
    lookup = getattr(pe, "metadata_tables_lookup", None)
    if not isinstance(lookup, dict):
        return out
    for table_name in ("TypeRef", "TypeDef"):
        table = lookup.get(table_name)
        if table is None:
            continue
        for row in getattr(table, "table_rows", None) or []:
            refs = getattr(row, "string_stream_references", None)
            if not isinstance(refs, dict):
                continue
            addr = refs.get("TypeNamespace")
            if addr is None:
                continue
            try:
                ns = pe.get_string(addr)
            except Exception:
                continue
            if isinstance(ns, str):
                ns = ns.strip()
                if ns:
                    out.add(ns)
    return out


def _namespace_from_package_id(package_id: str) -> str | None:
    """Derive a root namespace from a NuGet package ID.

    Truncates to the first two dot-segments (same rule as _filter_namespaces)
    and rejects anything that starts with a CLR builtin prefix.

    Examples:
        CefSharp.Common            → CefSharp
        CefSharp.Wpf               → CefSharp
        Telerik.Windows.Controls   → Telerik.Windows
        Microsoft.AspNetCore.Mvc   → None  (CLR builtin prefix — already covered by dotnetfile)
        Newtonsoft.Json            → Newtonsoft.Json
    """
    if not package_id:
        return None
    parts = package_id.split(".")
    truncated = ".".join(parts[:2]) if len(parts) >= 2 else parts[0]
    first = parts[0]
    if first in _CLR_BUILTINS:
        return None
    if any(truncated == b or truncated.startswith(b + ".") for b in _CLR_BUILTINS):
        return None
    return truncated


def _filter_namespaces(namespaces: set[str]) -> set[str]:
    """Drop CLR built-ins / `<Module>`. Truncate to first two dot-segments."""
    result: set[str] = set()
    for ns in namespaces:
        if not ns or ns == "<Module>":
            continue
        first = ns.split(".", 1)[0]
        if first in _CLR_BUILTINS:
            continue
        # Also drop the deeper builtin forms (Microsoft.CSharp.RuntimeBinder etc).
        if any(ns == b or ns.startswith(b + ".") for b in _CLR_BUILTINS):
            continue
        parts = ns.split(".")
        truncated = ".".join(parts[:2])
        result.add(truncated)
    return result
