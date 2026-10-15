"""
Risk level mapping (SOP risk score 1–4) and the coverage gate.

The scanner emits a posture score (0–100) and findings by severity; the SOP
decides with levels 1 to 4. This module is the only translation rule, so two
analysts (or two runs) reading the same report always reach the same level:

    4  Unrestricted access to Gemini from an API key, or public access
       (LEVEL_4_CHECKS) — unacceptable, regardless of anything else.
    3  Any other CRITICAL finding (identity gaps included: a personal account
       with Owner/Editor is a CRITICAL finding).
    2  HIGH findings and no CRITICAL.
    1  Only MEDIUM/LOW/INFO findings.

Coverage is a separate gate, not a level: a scan that could not read API keys,
IAM or network leaves the assessment undetermined, so it can never be approved
automatically even when it reports no findings. See docs/risk-model.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from gcp_abuse_scanner.models.finding import Severity
from gcp_abuse_scanner.models.report import (
    CoverageGap,
    RiskAssessment,
    RiskTrigger,
)

if TYPE_CHECKING:
    from gcp_abuse_scanner.models.finding import Finding
    from gcp_abuse_scanner.models.report import CoverageReport

# ---------------------------------------------------------------------------
# Level 4 — the conditions the SOP treats as unacceptable
# ---------------------------------------------------------------------------

# API keys that can reach Gemini without restriction, and public access bindings.
# Both are "exposed now, exploitable with no further prerequisite".
LEVEL_4_CHECKS: frozenset[str] = frozenset(
    {
        "GEM-001",  # API key has no API restrictions
        "GEM-002",  # API key has no application restrictions
        "GEM-006",  # API key targeting Gemini API has no referrer restriction
        "CM-043",  # IAM binding grants access to allUsers/allAuthenticatedUsers
        "GEM-021",  # Vertex AI role granted to allUsers/allAuthenticatedUsers
    }
)

LEVEL_LABELS: dict[int, str] = {
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL",
}

_MAX_TRIGGERS = 10


# ---------------------------------------------------------------------------
# Coverage domains that gate automatic approval
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Domain:
    """A part of the assessment whose absence makes the result undetermined."""

    name: str
    apis: tuple[str, ...]
    collectors: tuple[str, ...]
    checks: tuple[str, ...]


_SENSITIVE_DOMAINS: tuple[_Domain, ...] = (
    _Domain(
        name="api_keys",
        apis=("apikeys.googleapis.com",),
        collectors=("api_keys",),
        checks=(
            "GEM-001",
            "GEM-002",
            "GEM-003",
            "GEM-004",
            "GEM-005",
            "GEM-006",
            "GEM-010",
        ),
    ),
    _Domain(
        name="iam",
        apis=("iam.googleapis.com", "cloudresourcemanager.googleapis.com"),
        collectors=("iam",),
        checks=(
            "CM-040",
            "CM-041",
            "CM-042",
            "CM-043",
            "CM-044",
            "CM-045",
            "CM-046",
            "GEM-020",
            "GEM-021",
            "GEM-022",
            "GEM-023",
            "CMN-004",
        ),
    ),
    _Domain(
        name="network",
        apis=("compute.googleapis.com",),
        collectors=("network",),
        checks=("CM-003", "CM-004", "CM-008", "CM-050"),
    ),
)


def assess_risk(
    findings: list[Finding],
    coverage: CoverageReport,
) -> RiskAssessment:
    """Return the SOP risk level plus the coverage gate for a completed scan."""
    active = [f for f in findings if not f.suppressed]
    level, triggers, rationale = _risk_level(active)
    gaps = _coverage_gaps(coverage)

    coverage_complete = not gaps
    blockers: list[str] = []

    if level != 1:
        blockers.append(
            f"risk level {level} ({LEVEL_LABELS[level]}) — findings require remediation "
            "before the assessment can be approved"
        )
    for gap in gaps:
        blockers.append(
            f"coverage gap in {gap.domain}: {gap.reason}"
            + (f" (projects: {', '.join(gap.projects)})" if gap.projects else "")
        )

    return RiskAssessment(
        level=level,
        label=LEVEL_LABELS[level],
        rationale=rationale,
        triggering_check_ids=sorted({t.check_id for t in triggers}),
        triggers=triggers,
        coverage_complete=coverage_complete,
        coverage_gaps=gaps,
        auto_approval_eligible=coverage_complete and level == 1,
        auto_approval_blockers=blockers,
    )


def _risk_level(
    active_findings: list[Finding],
) -> tuple[int, list[RiskTrigger], str]:
    level_4 = [f for f in active_findings if f.check_id in LEVEL_4_CHECKS]
    if level_4:
        return (
            4,
            [_trigger(f, "level_4_check") for f in level_4[:_MAX_TRIGGERS]],
            (
                f"{len(level_4)} finding(s) of the level-4 class — unrestricted Gemini API "
                f"key or public access ({_count_by_check(level_4)})."
            ),
        )

    critical = [f for f in active_findings if f.severity == Severity.CRITICAL]
    if critical:
        return (
            3,
            [_trigger(f, "critical") for f in critical[:_MAX_TRIGGERS]],
            (
                f"{len(critical)} CRITICAL finding(s) outside the level-4 class, no "
                f"unrestricted key or public access ({_count_by_check(critical)})."
            ),
        )

    high = [f for f in active_findings if f.severity == Severity.HIGH]
    if high:
        others = len(active_findings) - len(high)
        detail = f"; {others} MEDIUM/LOW also present" if others else ""
        return (
            2,
            [_trigger(f, "high") for f in high[:_MAX_TRIGGERS]],
            (
                f"{len(high)} HIGH finding(s) and no CRITICAL findings{detail} "
                f"({_count_by_check(high)})."
            ),
        )

    return (
        1,
        [],
        (
            f"No CRITICAL or HIGH findings — {len(active_findings)} MEDIUM/LOW/INFO "
            "finding(s) only."
        ),
    )


def _trigger(finding: Finding, rule: str) -> RiskTrigger:
    return RiskTrigger(
        check_id=finding.check_id,
        finding_id=finding.finding_id,
        project_id=finding.resource.project_id,
        severity=finding.severity.value,
        rule=rule,
    )


def _count_by_check(findings: list[Finding]) -> str:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.check_id] = counts.get(finding.check_id, 0) + 1
    return ", ".join(f"{check_id} ×{count}" for check_id, count in sorted(counts.items()))


def _coverage_gaps(coverage: CoverageReport) -> list[CoverageGap]:
    gaps: list[CoverageGap] = []

    if coverage.inaccessible_project_ids:
        gaps.append(
            CoverageGap(
                domain="projects",
                reason=(
                    f"{len(coverage.inaccessible_project_ids)} project(s) could not be scanned "
                    "at all — every check is unevaluated there"
                ),
                projects=sorted(coverage.inaccessible_project_ids),
            )
        )

    errored_collectors = {str(entry.get("collector", "")) for entry in coverage.collector_errors}

    for domain in _SENSITIVE_DOMAINS:
        missing_apis: dict[str, list[str]] = {}
        for project_id, apis in coverage.skipped_apis_by_project.items():
            hits = [api for api in domain.apis if api in apis]
            if hits:
                missing_apis[project_id] = sorted(hits)

        errored = sorted(c for c in domain.collectors if c in errored_collectors)
        not_applicable = sorted(c for c in coverage.checks_not_applicable_ids if c in domain.checks)
        errored_checks = sorted(c for c in coverage.checks_errored_ids if c in domain.checks)

        if not (missing_apis or errored or not_applicable or errored_checks):
            continue

        reasons: list[str] = []
        if missing_apis:
            reasons.append("required API not enabled or not readable")
        if errored:
            reasons.append("collector failed")
        if not_applicable:
            reasons.append("checks not applicable in scope")
        if errored_checks:
            reasons.append("checks raised an error")

        gaps.append(
            CoverageGap(
                domain=domain.name,
                reason=f"{domain.name} coverage incomplete — " + ", ".join(reasons),
                projects=sorted(missing_apis),
                missing_apis=sorted({api for apis in missing_apis.values() for api in apis}),
                collectors=errored,
                affected_checks=sorted(set(not_applicable) | set(errored_checks)),
            )
        )

    return gaps
