"""
Manifest dispatcher + ecosystem registry.

To add a new ecosystem:
1. Write a parser module under dkatchr/parsers/<eco>.py with functions that
   return list[dict] — each dict has {"package", "version", "version_source"}.
2. Register filenames in EXACT_MANIFESTS or extension matchers in SUFFIX_MANIFESTS.
3. Add the ecosystem label + a name-list field to ECOSYSTEM_NAME_FIELD so rules
   can target it.
4. Bump CACHE_SCHEMA in config.py if extractor semantics change.
"""

from dkatchr.parsers import cargo, composer, go, maven, npm, nuget, pypi, ruby

# Exact filename → (ecosystem_label, parser_fn).
EXACT_MANIFESTS: dict[str, tuple[str, callable]] = {
    # npm
    "package.json":       ("npm",        npm.from_package_json),
    "package-lock.json":  ("npm",        npm.from_package_lock),
    "yarn.lock":          ("npm",        npm.from_yarn_lock),
    "pnpm-lock.yaml":     ("npm",        npm.from_pnpm_lock),
    # RubyGems
    "Gemfile":            ("RubyGems",   ruby.from_gemfile),
    "Gemfile.lock":       ("RubyGems",   ruby.from_gemfile_lock),
    # Maven / Gradle
    "pom.xml":            ("Maven",      maven.from_pom_xml),
    "gradle.lockfile":    ("Maven",      maven.from_gradle_lockfile),
    # NuGet
    "packages.config":    ("NuGet",      nuget.from_packages_config),
    "packages.lock.json": ("NuGet",      nuget.from_packages_lock_json),
    # PyPI
    "requirements.txt":   ("PyPI",       pypi.from_requirements_txt),
    "Pipfile.lock":       ("PyPI",       pypi.from_pipfile_lock),
    "poetry.lock":        ("PyPI",       pypi.from_poetry_lock),
    # Go
    "go.mod":             ("Go",         go.from_go_mod),
    "go.sum":             ("Go",         go.from_go_sum),
    # crates.io
    "Cargo.lock":         ("crates.io",  cargo.from_cargo_lock),
    # Composer
    "composer.json":      ("Packagist",  composer.from_composer_json),
    "composer.lock":      ("Packagist",  composer.from_composer_lock),
}

# Suffix matches for project files where the basename varies (e.g. *.csproj).
SUFFIX_MANIFESTS: list[tuple[str, str, callable]] = [
    (".csproj", "NuGet", nuget.from_csproj),
    (".fsproj", "NuGet", nuget.from_csproj),
    (".vbproj", "NuGet", nuget.from_csproj),
]


def manifest_handler(filename: str) -> tuple[str, callable] | None:
    """Return (ecosystem, parser) if this filename is a known manifest, else None."""
    if filename in EXACT_MANIFESTS:
        return EXACT_MANIFESTS[filename]
    for suffix, eco, fn in SUFFIX_MANIFESTS:
        if filename.endswith(suffix):
            return (eco, fn)
    return None


# Field on a rule that lists package names for a given ecosystem.
# Keep ecosystem labels matching OSV's expected values.
ECOSYSTEM_NAME_FIELD: dict[str, str] = {
    "npm":       "npm_names",
    "RubyGems":  "rubygems_names",
    "Maven":     "maven_names",
    "NuGet":     "nuget_names",
    "PyPI":      "pypi_names",
    "Go":        "go_names",
    "crates.io": "cargo_names",
    "Packagist": "composer_names",
}
