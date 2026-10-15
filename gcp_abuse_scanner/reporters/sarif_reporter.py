"""SARIF 2.1.0 reporter — output format for GitHub Advanced Security, VS Code, etc."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from gcp_abuse_scanner.models.finding import Finding, FindingStatus, Severity
from gcp_abuse_scanner.models.report import ScanReport

_SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"
_SARIF_VERSION = "2.1.0"
_TOOL_NAME = "gcp-abuse-scanner"

from gcp_abuse_scanner import __version__ as _TOOL_VERSION  # noqa: E402

_INFORMATION_URI = "https://github.com/uCloud-Global/gcp-abuse-scanner"
_HELP_URI_BASE = "https://github.com/uCloud-Global/gcp-abuse-scanner/blob/main/docs/checks/"

_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_SEVERITY_TO_PROBLEM_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _to_rule_name(title: str) -> str:
    """Convert a finding title to a camelCase rule name.

    Example: "VM instance has external IP" → "VmInstanceHasExternalIp"
    """
    # Replace any non-alphanumeric character (except spaces) with a space, then title-case
    cleaned = re.sub(r"[^a-zA-Z0-9 ]", " ", title)
    words = cleaned.split()
    return "".join(word.capitalize() for word in words if word)


def _build_rule(check_id: str, finding: Finding) -> dict[str, Any]:
    """Build a SARIF rule descriptor from a representative finding."""
    level = _SEVERITY_TO_LEVEL[finding.severity]
    problem_severity = _SEVERITY_TO_PROBLEM_SEVERITY[finding.severity]
    rule_name = _to_rule_name(finding.title)

    return {
        "id": check_id,
        "name": rule_name,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "helpUri": f"{_HELP_URI_BASE}{check_id}",
        "properties": {
            "tags": ["security", "gcp", finding.vector.value],
            "precision": "high",
            "problem.severity": problem_severity,
        },
        "defaultConfiguration": {
            "level": level,
        },
    }


def _build_result(finding: Finding) -> dict[str, Any]:
    """Build a SARIF result from a single finding."""
    level = _SEVERITY_TO_LEVEL[finding.severity]

    # Compose message: title + description, truncated to 1000 chars
    raw_message = f"{finding.title}. {finding.description}"
    message_text = raw_message[:1000]

    resource = finding.resource
    fqn = f"gcp://{resource.project_id}/{resource.resource_type}/{resource.resource_id}"

    result: dict[str, Any] = {
        "ruleId": finding.check_id,
        "level": level,
        "message": {
            "text": message_text,
        },
        "locations": [
            {
                "logicalLocations": [
                    {
                        "name": resource.resource_id,
                        "kind": "resource",
                        "fullyQualifiedName": fqn,
                    }
                ]
            }
        ],
        "properties": {
            "check_id": finding.check_id,
            "vector": finding.vector.value,
            "severity": finding.severity.value,
            "exploitability_score": finding.exploitability_score,
            "blast_radius": finding.blast_radius,
            "project_id": resource.project_id,
            "priority_rank": finding.priority_rank,
            "remediation_effort": finding.remediation.effort.value,
            "remediation_summary": finding.remediation.summary,
            "references": finding.references,
        },
        "suppressions": [],
    }

    return result


def _build_invocation(report: ScanReport) -> dict[str, Any]:
    """Build a SARIF invocation block from scan metadata."""
    meta = report.metadata

    invocation: dict[str, Any] = {
        "executionSuccessful": True,
        "startTimeUtc": meta.started_at.isoformat(),
        "toolExecutionNotifications": [],
    }

    if meta.finished_at is not None:
        invocation["endTimeUtc"] = meta.finished_at.isoformat()

    return invocation


class SARIFReporter:
    """Renders a :class:`ScanReport` as a SARIF 2.1.0 JSON document.

    Parameters
    ----------
    output_path:
        Optional file path where the SARIF output will be written.
        If *None*, the output is only returned as a string.
    """

    def __init__(self, output_path: str | Path | None = None) -> None:
        self._output_path = Path(output_path) if output_path else None

    def render(self, report: ScanReport) -> str:
        """Generate a SARIF 2.1.0 JSON string from *report*.

        Only findings with ``status == FAIL`` and ``suppressed == False`` are
        included as results.  One rule descriptor is emitted per unique
        ``check_id`` found across those findings.

        Parameters
        ----------
        report:
            The scan report to serialise.

        Returns
        -------
        str
            Pretty-printed SARIF JSON (2-space indent).
        """
        # Collect active (FAIL, not suppressed) findings
        active_findings = [
            f for f in report.findings if f.status == FindingStatus.FAIL and not f.suppressed
        ]

        # Build rules — one per unique check_id, using the first finding as representative
        rules_map: dict[str, dict[str, Any]] = {}
        for finding in active_findings:
            if finding.check_id not in rules_map:
                rules_map[finding.check_id] = _build_rule(finding.check_id, finding)

        rules = list(rules_map.values())

        # Build results
        results = [_build_result(f) for f in active_findings]

        # Build invocation
        invocations = [_build_invocation(report)]

        sarif_doc: dict[str, Any] = {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": _TOOL_NAME,
                            "version": _TOOL_VERSION,
                            "informationUri": _INFORMATION_URI,
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "invocations": invocations,
                }
            ],
        }

        output = json.dumps(sarif_doc, indent=2, default=str)

        if self._output_path:
            self._output_path.write_text(output, encoding="utf-8")

        return output
