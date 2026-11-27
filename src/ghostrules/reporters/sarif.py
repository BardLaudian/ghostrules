"""SARIF 2.1.0 report (GitHub code scanning)."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote

from ghostrules import PROJECT_URL, __version__
from ghostrules.models import Finding, ScanResult, Severity
from ghostrules.reporters.common import safe
from ghostrules.rules.registry import Rule, all_rules

SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}
_NOT_REPO_RELATIVE = re.compile(r"^(?:~|/|[A-Za-z]:[\\/])")


def is_repo_relative(path: str) -> bool:
    """False for user-level files (``~/...``) and absolute paths, which SARIF cannot place."""
    return _NOT_REPO_RELATIVE.match(path) is None


def _rule_entry(rule: Rule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.title,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description},
        "helpUri": f"{PROJECT_URL}/blob/main/docs/RULES.md#{rule.id.lower()}",
        "defaultConfiguration": {"level": _LEVEL[rule.severity]},
        "properties": {
            "security-severity": _SECURITY_SEVERITY[rule.severity],
            "tags": ["security", "ai-agents"],
        },
    }


def _result(finding: Finding, rule_index: dict[str, int]) -> dict[str, Any]:
    region: dict[str, Any] = {
        "startLine": finding.line,
        "startColumn": finding.column,
        "endLine": finding.line,
        "endColumn": max(finding.end_column, finding.column),
        "snippet": {"text": safe(finding.snippet)},
    }
    properties: dict[str, Any] = {"security-severity": _SECURITY_SEVERITY[finding.severity]}
    if finding.decoded:
        properties["decodedHiddenText"] = safe(finding.decoded)
    if finding.fix_hint:
        properties["fixHint"] = safe(finding.fix_hint)
    if finding.agents:
        properties["agents"] = list(finding.agents)
    if finding.tags:
        properties["tags"] = list(finding.tags)
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": _LEVEL[finding.severity],
        "message": {"text": safe(f"{finding.title}: {finding.message}")},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": quote(safe(finding.path), safe="/"),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": region,
                }
            }
        ],
        "properties": properties,
    }
    if finding.rule_id in rule_index:
        result["ruleIndex"] = rule_index[finding.rule_id]
    related = _related_locations(finding)
    if related:
        result["relatedLocations"] = related
    return result


def _related_locations(finding: Finding) -> list[dict[str, Any]]:
    """The import chain: one location per ``path:line`` in ``finding.via`` (repo files only)."""
    out: list[dict[str, Any]] = []
    for step in finding.via:
        path, _, line = step.rpartition(":")
        if not is_repo_relative(path) or not line.isdigit():
            continue
        out.append(
            {
                "id": len(out),
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": quote(safe(path), safe="/"),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": max(int(line), 1)},
                },
                "message": {"text": "imports the next file in the chain"},
            }
        )
    return out


def to_dict(result: ScanResult) -> dict[str, Any]:
    """The SARIF log as plain data. Findings in user-level files are left out (and counted)."""
    rules = all_rules()
    rule_index = {r.id: i for i, r in enumerate(rules)}
    reportable = [f for f in result.findings if is_repo_relative(f.path)]
    skipped = len(result.findings) - len(reportable)
    notifications = [
        {"level": "warning", "message": {"text": safe(w)}} for w in result.warnings
    ] + [{"level": "error", "message": {"text": safe(e)}} for e in result.errors]
    if skipped:
        notifications.append(
            {
                "level": "note",
                "message": {
                    "text": f"{skipped} finding(s) in files outside the repository (--home) "
                    "are not included in SARIF."
                },
            }
        )
    return {
        "$schema": SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ghostrules",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": PROJECT_URL,
                        "rules": [_rule_entry(r) for r in rules],
                    }
                },
                "columnKind": "unicodeCodePoints",
                "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
                "results": [_result(f, rule_index) for f in reportable],
                "invocations": [
                    {
                        "executionSuccessful": not result.errors,
                        "toolExecutionNotifications": notifications,
                    }
                ],
            }
        ],
    }


def render(result: ScanResult, **_options: Any) -> str:
    """Render the SARIF 2.1.0 log."""
    return json.dumps(to_dict(result), indent=2, ensure_ascii=False) + "\n"
