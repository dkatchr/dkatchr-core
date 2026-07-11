"""Helpers shared across manifest parsers. Keep this small."""

import re

# Strip semver/range operators and bracket prefixes used by various ecosystems
# (npm/yarn ^~, ruby ~>, NuGet/Maven ranges, Go v-prefix).
_RANGE_PREFIX = re.compile(r"^[\^~>=<*v\[\(\s]+")


def clean_declared_version(v: str) -> str:
    """Strip range operators, take first token, strip trailing range punctuation."""
    if not isinstance(v, str):
        return ""
    cleaned = _RANGE_PREFIX.sub("", v.strip())
    parts = cleaned.split()
    cleaned = parts[0] if parts else cleaned
    return cleaned.rstrip(",)]")


def strip_xml_namespace(tag: str) -> str:
    """{namespace}localname → localname"""
    return tag.split("}", 1)[-1] if "}" in tag else tag
