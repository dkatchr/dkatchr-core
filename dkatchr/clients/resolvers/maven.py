"""
Maven import-name resolver.

WHY: Maven coordinates are `groupId:artifactId:version`. The Java packages
inside a JAR rarely equal the group ID — `com.fasterxml.jackson.core:jackson-core`
exposes `com.fasterxml.jackson.core` but `org.springframework:spring-web`
exposes `org.springframework.web.*` and more. The Maven Central Solr API
cannot return this — the only way to know is to inspect the JAR.

Fast path: OSGi bundles declare exported packages in `META-INF/MANIFEST.MF`
under `Export-Package`. When present this is authoritative and tiny to parse.
Fallback: enumerate `.class` paths and take the first two segments as a
package root.

Does NOT: descend into nested JARs (fat JARs / Spring Boot uber-JARs would
require recursive unpacking; out of scope for Level 1).
"""

import io
import zipfile

from dkatchr.clients.resolvers._base import RegistryResolverBase
from dkatchr.logger import log

_MAVEN_CENTRAL = (
    "https://repo1.maven.org/maven2/"
    "{group_path}/{artifact}/{version}/{artifact}-{version}.jar"
)


class MavenResolver(RegistryResolverBase):
    ECOSYSTEM = "maven"

    def resolve(
        self, package: str, version: str | None = None
    ) -> tuple[list[str], str] | None:
        if ":" not in package:
            log(f"[resolver] maven/{package}: parse error — coord missing ':' (need groupId:artifactId)")
            return None
        group_id, artifact_id = package.split(":", 1)
        if not group_id or not artifact_id:
            log(f"[resolver] maven/{package}: parse error — empty groupId or artifactId")
            return None
        if not version:
            log(f"[resolver] maven/{package}: parse error — version required")
            return None

        url = _MAVEN_CENTRAL.format(
            group_path=group_id.replace(".", "/"),
            artifact=artifact_id,
            version=version,
        )
        blob = self._download_bytes(url, package)
        if blob is None:
            return None

        try:
            zf = zipfile.ZipFile(io.BytesIO(blob))
        except zipfile.BadZipFile as e:
            log(f"[resolver] maven/{package}: parse error — bad jar zip: {e}")
            return None

        with zf:
            # Fast path: MANIFEST.MF / Export-Package
            manifest_packages = _parse_export_package(zf, package)
            if manifest_packages:
                return manifest_packages, "jar_manifest_export_package"

            # Fallback: .class directory structure
            packages: set[str] = set()
            has_classes = False
            for name in zf.namelist():
                if not name.endswith(".class"):
                    continue
                has_classes = True
                # com/example/util/StringUtils.class → "com.example"
                parts = name.split("/")
                if len(parts) >= 2:
                    packages.add(".".join(parts[:2]))

            if not has_classes:
                log(f"[resolver] maven/{package}: parse error — jar contains no .class files")
                return None

            if not packages:
                log(f"[resolver] maven/{package}: parse error — could not extract package paths")
                return None

            return sorted(packages), "jar_class_paths"


def _parse_export_package(zf: zipfile.ZipFile, package: str) -> list[str]:
    """Return Export-Package entries from META-INF/MANIFEST.MF, or []."""
    try:
        with zf.open("META-INF/MANIFEST.MF") as f:
            raw = f.read().decode("utf-8", errors="ignore")
    except KeyError:
        return []
    except Exception as e:
        log(f"[resolver] maven/{package}: parse error — reading MANIFEST.MF: {e}")
        return []

    # Java manifests fold long lines by starting continuation lines with a
    # single leading space. Unfold first.
    unfolded_lines: list[str] = []
    for line in raw.splitlines():
        if line.startswith(" ") and unfolded_lines:
            unfolded_lines[-1] += line[1:]
        else:
            unfolded_lines.append(line)

    export_value = ""
    for line in unfolded_lines:
        if line.startswith("Export-Package:"):
            export_value = line.split(":", 1)[1].strip()
            break

    if not export_value:
        return []

    # Split on commas, but not commas inside quoted attribute values.
    entries: list[str] = []
    buf: list[str] = []
    in_quotes = False
    for ch in export_value:
        if ch == '"':
            in_quotes = not in_quotes
            buf.append(ch)
        elif ch == "," and not in_quotes:
            entries.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        entries.append("".join(buf).strip())

    packages: set[str] = set()
    for entry in entries:
        # Strip attribute clauses after ';' — `pkg;version="1.0"` → `pkg`.
        pkg = entry.split(";", 1)[0].strip()
        if pkg:
            packages.add(pkg)

    return sorted(packages)
