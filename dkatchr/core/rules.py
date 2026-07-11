"""
Rule compilation + matching + application.

MOVED FROM: dkatchr/rules.py
WHY: Pure business logic — loads a rule config, compiles patterns, runs
inventory through them. No I/O beyond loading a JSON file the user pointed at.

Schema:
  {
    "<rule_name>": {
      "description": "...",
      "reason": "INTERNAL_VULNERABLE",          # optional — one of
                                                # INTERNAL_VULNERABLE, ORG_BANNED,
                                                # LICENSE_ISSUE, PRE_CVE. Defaults
                                                # to empty (displayed as CUSTOM).
      "<eco>_names": ["pkg1", ...],            # one or more of:
                                                # npm_names, rubygems_names,
                                                # maven_names, nuget_names,
                                                # pypi_names, go_names,
                                                # cargo_names, composer_names
      "vulnerable_versions": ["1.2.3", ...],
      "vulnerable_version_patterns": ["^[123]\\."]
    }
  }
"""

import json
import re

from dkatchr.logger import log
from dkatchr.output.schema import empty_row
from dkatchr.parsers import ECOSYSTEM_NAME_FIELD


# Inline rules — used when no -c <file> is passed.
DEFAULT_PACKAGE_CONFIG: dict = {
    # Example:
    # "lodash_rule": {
    #     "description": "Track lodash, flag versions below 4.17.21",
    #     "npm_names": ["lodash"],
    #     "vulnerable_versions": ["4.17.20", "4.17.19"],
    #     "vulnerable_version_patterns": [r"^[123]\."],
    # },
}


def load_package_config(config_path: str | None) -> dict:
    if not config_path:
        return DEFAULT_PACKAGE_CONFIG
    try:
        with open(config_path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("top-level JSON value must be an object")
        return data
    except Exception as e:
        log(f"[!] Could not load config from {config_path}: {e}")
        log("[!] Falling back to inline DEFAULT_PACKAGE_CONFIG.")
        return DEFAULT_PACKAGE_CONFIG


def compile_rules(package_config: dict) -> dict:
    """Pre-compile regex patterns so we catch invalid ones at startup.

    Defensive: a malformed or empty config must not abort a scan. If the
    config isn't a dict (e.g. it got truncated, was passed a list, or was
    cleared), we log a warning and return an empty rule set so the scan
    continues with OSV and inventory only.
    """
    if not isinstance(package_config, dict) or not package_config:
        log("[!] Rule set config invalid or empty — skipping rule evaluation for this scan.")
        return {}

    compiled = {}
    for key, rule in package_config.items():
        if not isinstance(rule, dict):
            log(f"[!] Rule '{key}' is not an object — skipping.")
            continue
        r = dict(rule)
        patterns = []
        for pat in rule.get("vulnerable_version_patterns") or []:
            try:
                patterns.append(re.compile(pat))
            except re.error as e:
                log(f"[!] Invalid regex '{pat}' in rule '{key}': {e} — skipping this pattern.")
        r["_compiled_patterns"] = patterns
        compiled[key] = r
    return compiled


def find_rule(package_config: dict, ecosystem: str, package_name: str) -> dict | None:
    field = ECOSYSTEM_NAME_FIELD.get(ecosystem)
    if not field:
        return None
    for rule in package_config.values():
        if package_name in (rule.get(field) or []):
            return rule
    return None


def check_version(rule: dict, version: str) -> tuple[str, str]:
    """Return (status, evidence). status is 'vulnerable' or 'ok'.

    `evidence` is free-text describing how the version matched (exact value,
    regex pattern). It is distinct from the rule's `reason` field — which is
    an enum category set on the rule itself."""
    ver = version.strip()
    if not ver:
        return "ok", ""
    if ver in (rule.get("vulnerable_versions") or []):
        return "vulnerable", f"exact match on flagged version {ver}"
    for pat in rule.get("_compiled_patterns") or []:
        if pat.search(ver):
            return "vulnerable", f"version {ver!r} matches pattern {pat.pattern!r}"
    return "ok", ""


def apply_rules(inventory: list[dict], package_config: dict, repo_full_name: str) -> list[dict]:
    """Apply rules to a cached inventory and return CSV-ready rows (source='CUSTOM')."""
    rows = []
    for dep in inventory:
        rule = find_rule(package_config, dep["ecosystem"], dep["package"])
        if rule is None:
            continue
        status, evidence = check_version(rule, dep["version"])
        row = empty_row(repo_full_name, dep)
        row["source"]  = "CUSTOM"
        row["status"]  = status
        row["reason"]  = rule.get("reason", "") or ""
        row["summary"] = evidence
        rows.append(row)
    return rows
