"""Scoring engine — assigns priority ranks and adjusts severity by context."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from gcp_abuse_scanner.models.finding import Finding, Severity
from gcp_abuse_scanner.models.report import (
    ExecutiveSummary,
    SeveritySummary,
    VectorSummary,
)

logger = logging.getLogger(__name__)

# Severity weights for posture score calculation
_SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 5.0,
    Severity.MEDIUM: 2.0,
    Severity.LOW: 0.5,
    Severity.INFO: 0.0,
}

# Sort order for severity
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_BLAST_RADIUS_WEIGHT: dict[str, float] = {
    "billing_account": 1.5,
    "organization": 1.3,
    "project": 1.0,
    "resource": 0.8,
}


def load_allowlist(path: Path) -> list[dict[str, Any]]:
    """
    Parse an allowlist YAML file into a list of suppression rules.

    Accepts either a top-level list of rules or a mapping with an ``allowlist`` key
    (the format used in docs/allowlist.md). Raises ValueError on any other shape so
    the CLI can fail before collecting inventory.
    """
    import yaml

    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc

    if data is None:
        return []
    if isinstance(data, dict):
        if "allowlist" not in data:
            raise ValueError("expected a list of rules or a mapping with an 'allowlist' key")
        data = data["allowlist"] or []
    if not isinstance(data, list):
        raise ValueError(f"'allowlist' must be a list of rules, got {type(data).__name__}")

    for i, rule in enumerate(data, start=1):
        if not isinstance(rule, dict):
            raise ValueError(f"rule #{i} must be a mapping, got {type(rule).__name__}: {rule!r}")
    return data


class ScoringEngine:
    """
    Assigns priority_rank to findings and computes the executive summary.

    Priority formula:
        score = exploitability_score * blast_radius_weight * severity_weight_factor
    Findings are ranked by score descending, then by severity.
    """

    def __init__(self, allowlist: list[dict[str, Any]] | None = None) -> None:
        self._allowlist = allowlist or []

    def process(self, findings: list[Finding]) -> list[Finding]:
        """Apply allowlist suppression, compute priority ranks, return sorted findings."""
        findings = self._apply_allowlist(findings)
        findings = self._assign_priority_ranks(findings)
        return findings

    def _apply_allowlist(self, findings: list[Finding]) -> list[Finding]:
        for finding in findings:
            for rule in self._allowlist:
                if self._matches_allowlist(finding, rule):
                    finding.suppressed = True
                    finding.suppression_reason = rule.get("reason", "Suppressed by allowlist")
                    logger.debug(
                        "Suppressed finding %s: %s", finding.finding_id, finding.suppression_reason
                    )
                    break
        return findings

    @staticmethod
    def _matches_allowlist(finding: Finding, rule: dict[str, Any]) -> bool:
        if rule.get("check_id") and rule["check_id"] != finding.check_id:
            return False
        if rule.get("project_id") and rule["project_id"] != finding.resource.project_id:
            return False
        if rule.get("resource_id") and rule["resource_id"] not in finding.resource.resource_id:
            return False
        return True

    def _assign_priority_ranks(self, findings: list[Finding]) -> list[Finding]:
        def sort_key(f: Finding) -> tuple[float, int]:
            blast_w = _BLAST_RADIUS_WEIGHT.get(f.blast_radius, 1.0)
            score = f.exploitability_score * blast_w
            return (-score, _SEVERITY_ORDER.get(f.severity, 5))

        active = [f for f in findings if not f.suppressed]
        suppressed = [f for f in findings if f.suppressed]

        active.sort(key=sort_key)
        for rank, finding in enumerate(active, start=1):
            finding.priority_rank = rank

        return active + suppressed

    def build_executive_summary(
        self, findings: list[Finding], max_projects: int = 1
    ) -> ExecutiveSummary:
        active = [f for f in findings if not f.suppressed]

        by_severity = self._count_by_severity(active)
        by_vector = self._count_by_vector(active)
        posture = self._compute_posture_score(active, max_projects)

        top_findings = [
            {
                "priority_rank": f.priority_rank,
                "check_id": f.check_id,
                "title": f.title,
                "severity": f.severity.value,
                "vector": f.vector.value,
                "project_id": f.resource.project_id,
                "resource_id": f.resource.resource_id,
            }
            for f in sorted(active, key=lambda x: x.priority_rank or 9999)[:10]
        ]

        return ExecutiveSummary(
            posture_score=posture,
            total_findings=len(active),
            by_severity=by_severity,
            by_vector=by_vector,
            top_findings=top_findings,
        )

    @staticmethod
    def _count_by_severity(findings: list[Finding]) -> SeveritySummary:
        counts: dict[str, int] = {s.value.lower(): 0 for s in Severity}
        for f in findings:
            counts[f.severity.value.lower()] += 1
        return SeveritySummary(
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            info=counts["info"],
            total=len(findings),
        )

    @staticmethod
    def _count_by_vector(findings: list[Finding]) -> list[VectorSummary]:
        from collections import defaultdict

        from gcp_abuse_scanner.models.finding import Vector

        vector_findings: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            vector_findings[f.vector.value].append(f)

        summaries = []
        for vector in Vector:  # lgtm[py/non-iterable-in-for-loop] — Enum classes are iterable
            vf = vector_findings.get(vector.value, [])
            summaries.append(
                VectorSummary(
                    vector=vector.value,
                    findings_count=len(vf),
                    by_severity=ScoringEngine._count_by_severity(vf),
                )
            )
        return summaries

    @staticmethod
    def _compute_posture_score(findings: list[Finding], max_projects: int) -> float:
        """
        Score 0–100. 100 = no findings. Penalized by severity weight.
        Normalized by number of projects to avoid penalizing large orgs unfairly.
        """
        if not findings:
            return 100.0

        total_penalty = sum(_SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
        # Normalize: assume ~20 checks per project as baseline
        baseline = max(max_projects * 20 * _SEVERITY_WEIGHTS[Severity.LOW], 1)
        score = max(0.0, 100.0 - (total_penalty / baseline * 100))
        return round(score, 1)
