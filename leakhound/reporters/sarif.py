"""SARIF 2.1.0 output for GitHub code scanning and other CI dashboards.

Upload it with ``github/codeql-action/upload-sarif`` and findings show up as
code-scanning alerts on the exact line, de-duplicated across runs via
``partialFingerprints``.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from .. import __version__
from ..models import Finding, Severity
from ..rules import Rule
from ..scanner import ScanResult

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
# GitHub maps this numeric score to its own critical/high/medium/low badges.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
}


def _pascal(rule_id: str) -> str:
    return "".join(part.capitalize() for part in rule_id.split("-"))


def _rule_descriptor(rule: Rule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": _pascal(rule.id),
        "shortDescription": {"text": rule.name},
        "fullDescription": {"text": rule.description},
        "help": {
            "text": f"{rule.description} Revoke and rotate the credential, then remove it "
            "from the code (and from git history if it was ever committed).",
        },
        "defaultConfiguration": {"level": _LEVEL[rule.severity]},
        "properties": {
            "tags": ["security", "secret", *rule.tags],
            "security-severity": _SECURITY_SEVERITY[rule.severity],
            "precision": "high" if rule.regex is not None and "generic" not in rule.tags else "medium",
        },
    }


def _result(finding: Finding, rule_index: int, redact_secrets: bool) -> dict[str, Any]:
    message = f"{finding.rule_name} detected: {finding.display_secret(redact_secrets)}"
    if finding.commit:
        message += f" (introduced in commit {finding.commit.sha[:12]} by {finding.commit.author})"
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL[finding.severity],
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path, "uriBaseId": "%SRCROOT%"},
                    "region": {
                        "startLine": finding.line,
                        "startColumn": finding.column,
                        "endLine": finding.end_line,
                        "endColumn": finding.end_column,
                        "snippet": {"text": finding.display_line(redact_secrets)},
                    },
                }
            }
        ],
        "partialFingerprints": {"leakhound/v1": finding.fingerprint},
        "properties": {
            "severity": finding.severity.label,
            "entropy": round(finding.entropy, 3),
            "tags": list(finding.tags),
        },
    }
    if finding.commit:
        result["properties"]["commit"] = finding.commit.to_dict()
    return result


def render(
    result: ScanResult,
    redact_secrets: bool = True,
    rules: Iterable[Rule] = (),
    **_: object,
) -> str:
    """Render a SARIF 2.1.0 log.

    Args:
        result: The scan result.
        redact_secrets: Mask secrets in messages and snippets.
        rules: All rules that were active; each becomes a rule descriptor so
            dashboards can show rule help even for rules with no results.
    """
    descriptors: list[dict[str, Any]] = []
    index_of: dict[str, int] = {}
    for rule in rules:
        if rule.id not in index_of:
            index_of[rule.id] = len(descriptors)
            descriptors.append(_rule_descriptor(rule))
    for finding in result.findings:  # findings from rules not passed in
        if finding.rule_id not in index_of:
            index_of[finding.rule_id] = len(descriptors)
            descriptors.append(
                _rule_descriptor(Rule(finding.rule_id, finding.rule_name, finding.description, finding.severity))
            )

    log = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "leakhound",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "rules": descriptors,
                    }
                },
                "results": [_result(f, index_of[f.rule_id], redact_secrets) for f in result.findings],
                "columnKind": "unicodeCodePoints",
            }
        ],
    }
    return json.dumps(log, indent=2, ensure_ascii=False) + "\n"
