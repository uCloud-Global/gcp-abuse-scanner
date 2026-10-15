"""Scan report model — top-level output of a scanner run."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from gcp_abuse_scanner.models.finding import Finding, Severity, Vector


class ScanMetadata(BaseModel):
    tool_name: str = "gcp-abuse-scanner"
    tool_version: str = "0.1.0"
    scan_id: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    scope_type: str = Field(description="organization | project_list")
    organization_id: str | None = None
    project_ids: list[str] = Field(default_factory=list)
    service_account: str | None = None
    vectors_scanned: list[str] = Field(default_factory=list)


class SeveritySummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0


class VectorSummary(BaseModel):
    vector: str
    findings_count: int = 0
    by_severity: SeveritySummary = Field(default_factory=SeveritySummary)


class CoverageReport(BaseModel):
    projects_scanned: int = 0
    projects_inaccessible: int = 0
    inaccessible_project_ids: list[str] = Field(default_factory=list)
    checks_executed: int = 0
    checks_passed: int = 0
    checks_failed: int = 0
    checks_not_applicable: int = 0
    checks_skipped: int = 0
    checks_errored: int = 0
    checks_not_applicable_ids: list[str] = Field(
        default_factory=list,
        description="Check IDs marked NOT_APPLICABLE (required API not enabled in scope).",
    )
    checks_errored_ids: list[str] = Field(
        default_factory=list,
        description="Check IDs that raised while evaluating the inventory.",
    )
    skipped_apis_by_project: dict[str, list[str]] = Field(default_factory=dict)
    unreadable_budget_accounts: list[str] = Field(
        default_factory=list,
        description=(
            "Billing accounts whose budgets could not be read — the budget checks "
            "(CMN-001/002, CM-060, GEM-051) do not assert anything about them."
        ),
    )
    collector_errors: list[dict[str, str]] = Field(default_factory=list)


class CoverageGap(BaseModel):
    """A part of the assessment the scan could not evaluate."""

    domain: str = Field(description="api_keys | iam | network | projects")
    reason: str
    projects: list[str] = Field(default_factory=list)
    missing_apis: list[str] = Field(default_factory=list)
    collectors: list[str] = Field(default_factory=list)
    affected_checks: list[str] = Field(default_factory=list)


class RiskTrigger(BaseModel):
    """A finding that drove the risk level."""

    check_id: str
    finding_id: str
    project_id: str
    severity: str
    rule: str = Field(description="Why it counted: level_4_check | critical | high")


class RiskAssessment(BaseModel):
    """
    SOP risk score (1–4) derived from the findings, plus the coverage gate.

    The scanner reports a posture score (0–100) and findings by severity; the SOP
    decides with levels 1 to 4. This object is the single conversion rule, so the
    same report always maps to the same level.
    """

    level: int = Field(ge=1, le=4, description="SOP risk score: 4 = unacceptable.")
    label: str = Field(description="LOW | MEDIUM | HIGH | CRITICAL")
    rationale: str
    triggering_check_ids: list[str] = Field(default_factory=list)
    triggers: list[RiskTrigger] = Field(
        default_factory=list, description="Up to 10 findings that drove the level."
    )
    coverage_complete: bool = True
    coverage_gaps: list[CoverageGap] = Field(default_factory=list)
    auto_approval_eligible: bool = Field(
        description="Level 1 with complete coverage — nothing left to review."
    )
    auto_approval_blockers: list[str] = Field(default_factory=list)


class ExecutiveSummary(BaseModel):
    posture_score: float = Field(
        description=(
            "0–100 score (100 = no findings). Weighted by severity and NORMALIZED BY "
            "PROJECT COUNT, so it saturates at 0 for small scopes (1 CRITICAL zeroes it "
            "on a single-project scan). Compare only between scans of the same scope, or "
            "use penalty_points."
        ),
        ge=0.0,
        le=100.0,
    )
    penalty_points: float = Field(
        default=0.0,
        description=(
            "Σ severity weights of active findings (CRITICAL=10, HIGH=5, MEDIUM=2, "
            "LOW=0.5). Scope-independent and uncapped — the metric to track when comparing "
            "two scans (it falls linearly as findings are fixed)."
        ),
        ge=0.0,
    )
    total_findings: int = 0
    by_severity: SeveritySummary = Field(default_factory=SeveritySummary)
    by_vector: list[VectorSummary] = Field(default_factory=list)
    top_findings: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Top 10 findings by priority_rank (summary fields only)",
    )


class ScanReport(BaseModel):
    """Top-level output of a gcp-abuse-scanner run."""

    metadata: ScanMetadata
    executive_summary: ExecutiveSummary
    coverage: CoverageReport
    findings: list[Finding] = Field(default_factory=list)
    risk_assessment: RiskAssessment | None = Field(
        default=None,
        description="SOP risk level 1–4 and coverage gate. See docs/risk-model.md.",
    )

    # Convenience accessors
    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity and not f.suppressed]

    def findings_by_vector(self, vector: Vector) -> list[Finding]:
        return [f for f in self.findings if f.vector == vector and not f.suppressed]

    def prioritized_findings(self) -> list[Finding]:
        """Return active findings sorted by priority_rank, then severity."""
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        active = [f for f in self.findings if not f.suppressed]
        return sorted(
            active,
            key=lambda f: (
                f.priority_rank if f.priority_rank is not None else 9999,
                severity_order.get(f.severity, 5),
            ),
        )
