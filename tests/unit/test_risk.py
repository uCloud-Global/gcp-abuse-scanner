"""Unit tests for the SOP risk-level mapping and the coverage gate."""

from __future__ import annotations

from gcp_abuse_scanner.models.finding import Severity
from gcp_abuse_scanner.models.report import CoverageReport
from gcp_abuse_scanner.scoring.risk import LEVEL_4_CHECKS, assess_risk


def _coverage(**kwargs) -> CoverageReport:
    kwargs.setdefault("projects_scanned", 1)
    return CoverageReport(**kwargs)


class TestRiskLevelMapping:
    def test_level_4_for_unrestricted_gemini_key(self, make_finding) -> None:
        findings = [make_finding(check_id="GEM-001", severity=Severity.CRITICAL)]
        risk = assess_risk(findings, _coverage())
        assert risk.level == 4
        assert risk.label == "CRITICAL"
        assert risk.triggering_check_ids == ["GEM-001"]
        assert risk.triggers[0].rule == "level_4_check"
        assert "GEM-001" in risk.rationale

    def test_level_4_for_every_level_4_check(self, make_finding) -> None:
        for check_id in sorted(LEVEL_4_CHECKS):
            findings = [make_finding(check_id=check_id, severity=Severity.CRITICAL)]
            assert assess_risk(findings, _coverage()).level == 4, check_id

    def test_level_4_wins_over_other_criticals(self, make_finding) -> None:
        findings = [
            make_finding(check_id="CM-004", severity=Severity.CRITICAL),
            make_finding(check_id="CM-043", severity=Severity.CRITICAL),
        ]
        risk = assess_risk(findings, _coverage())
        assert risk.level == 4
        assert risk.triggering_check_ids == ["CM-043"]

    def test_level_3_for_other_critical(self, make_finding) -> None:
        findings = [make_finding(check_id="CM-004", severity=Severity.CRITICAL)]
        risk = assess_risk(findings, _coverage())
        assert risk.level == 3
        assert risk.label == "HIGH"
        assert risk.triggers[0].rule == "critical"

    def test_level_2_for_high_without_critical(self, make_finding) -> None:
        findings = [
            make_finding(check_id="CM-001", severity=Severity.HIGH),
            make_finding(check_id="CM-050", severity=Severity.HIGH),
            make_finding(check_id="CM-009", severity=Severity.MEDIUM),
        ]
        risk = assess_risk(findings, _coverage())
        assert risk.level == 2
        assert risk.label == "MEDIUM"
        assert set(risk.triggering_check_ids) == {"CM-001", "CM-050"}
        assert "MEDIUM/LOW also present" in risk.rationale

    def test_level_1_for_medium_only(self, make_finding) -> None:
        findings = [
            make_finding(check_id="CM-009", severity=Severity.MEDIUM),
            make_finding(check_id="CM-045", severity=Severity.LOW),
        ]
        risk = assess_risk(findings, _coverage())
        assert risk.level == 1
        assert risk.label == "LOW"
        assert risk.triggers == []
        assert risk.triggering_check_ids == []

    def test_level_1_for_no_findings(self) -> None:
        risk = assess_risk([], _coverage())
        assert risk.level == 1
        assert risk.coverage_complete is True
        assert risk.auto_approval_eligible is True

    def test_suppressed_findings_do_not_count(self, make_finding) -> None:
        findings = [
            make_finding(check_id="GEM-001", severity=Severity.CRITICAL, suppressed=True),
            make_finding(check_id="CM-004", severity=Severity.CRITICAL, suppressed=True),
        ]
        risk = assess_risk(findings, _coverage())
        assert risk.level == 1
        assert risk.auto_approval_eligible is True

    def test_triggers_are_capped_and_check_ids_are_unique(self, make_finding) -> None:
        findings = [make_finding(check_id="GEM-001", severity=Severity.CRITICAL) for _ in range(25)]
        risk = assess_risk(findings, _coverage())
        assert len(risk.triggers) == 10
        assert risk.triggering_check_ids == ["GEM-001"]
        assert "GEM-001 ×25" in risk.rationale


class TestCoverageGate:
    def test_incomplete_api_key_coverage_blocks_auto_approval(self, make_finding) -> None:
        risk = assess_risk(
            [make_finding(check_id="CM-009", severity=Severity.MEDIUM)],
            _coverage(skipped_apis_by_project={"proj-1": ["apikeys.googleapis.com"]}),
        )
        assert risk.level == 1  # the level is untouched by coverage ...
        assert risk.coverage_complete is False  # ... but the gate is not open
        assert risk.auto_approval_eligible is False
        assert [g.domain for g in risk.coverage_gaps] == ["api_keys"]
        gap = risk.coverage_gaps[0]
        assert gap.projects == ["proj-1"]
        assert gap.missing_apis == ["apikeys.googleapis.com"]
        assert any("coverage gap in api_keys" in b for b in risk.auto_approval_blockers)

    def test_iam_collector_error_blocks_auto_approval(self) -> None:
        risk = assess_risk(
            [],
            _coverage(collector_errors=[{"collector": "iam", "error": "HTTP 403"}]),
        )
        assert [g.domain for g in risk.coverage_gaps] == ["iam"]
        assert risk.coverage_gaps[0].collectors == ["iam"]
        assert risk.auto_approval_eligible is False

    def test_network_skip_is_detected_via_compute_api(self) -> None:
        risk = assess_risk(
            [],
            _coverage(skipped_apis_by_project={"proj-1": ["compute.googleapis.com"]}),
        )
        assert [g.domain for g in risk.coverage_gaps] == ["network"]
        assert risk.coverage_gaps[0].missing_apis == ["compute.googleapis.com"]

    def test_not_applicable_sensitive_check_is_a_gap(self) -> None:
        coverage = _coverage(
            checks_not_applicable_ids=["GEM-001", "CM-011"],
            checks_not_applicable=2,
        )
        risk = assess_risk([], coverage)
        assert [g.domain for g in risk.coverage_gaps] == ["api_keys"]
        assert risk.coverage_gaps[0].affected_checks == ["GEM-001"]

    def test_errored_sensitive_check_is_a_gap(self) -> None:
        coverage = _coverage(checks_errored_ids=["CM-004"], checks_errored=1)
        risk = assess_risk([], coverage)
        assert [g.domain for g in risk.coverage_gaps] == ["network"]
        assert risk.coverage_gaps[0].affected_checks == ["CM-004"]

    def test_inaccessible_project_is_a_gap(self) -> None:
        coverage = _coverage(
            projects_scanned=3,
            projects_inaccessible=1,
            inaccessible_project_ids=["locked-proj"],
        )
        risk = assess_risk([], coverage)
        assert [g.domain for g in risk.coverage_gaps] == ["projects"]
        assert risk.coverage_gaps[0].projects == ["locked-proj"]
        assert risk.auto_approval_eligible is False

    def test_non_sensitive_gaps_do_not_block(self) -> None:
        """GKE/Recommender gaps are not part of the SOP's approval gate."""
        coverage = _coverage(
            skipped_apis_by_project={"proj-1": ["container.googleapis.com"]},
            collector_errors=[{"collector": "gke", "error": "HTTP 403"}],
        )
        risk = assess_risk([], coverage)
        assert risk.coverage_gaps == []
        assert risk.coverage_complete is True
        assert risk.auto_approval_eligible is True

    def test_multiple_domains_gap_are_all_reported(self) -> None:
        coverage = _coverage(
            skipped_apis_by_project={
                "proj-1": ["apikeys.googleapis.com", "compute.googleapis.com"],
                "proj-2": ["apikeys.googleapis.com"],
            },
            collector_errors=[{"collector": "iam", "error": "boom"}],
        )
        risk = assess_risk([], coverage)
        assert [g.domain for g in risk.coverage_gaps] == ["api_keys", "iam", "network"]
        api_keys_gap = risk.coverage_gaps[0]
        assert api_keys_gap.projects == ["proj-1", "proj-2"]

    def test_level_4_is_never_auto_approvable(self, make_finding) -> None:
        risk = assess_risk(
            [make_finding(check_id="GEM-002", severity=Severity.CRITICAL)],
            _coverage(),
        )
        assert risk.level == 4
        assert risk.coverage_complete is True
        assert risk.auto_approval_eligible is False
        assert any("risk level 4" in b for b in risk.auto_approval_blockers)

    def test_clean_scan_with_full_coverage_is_auto_approvable(self, make_finding) -> None:
        risk = assess_risk(
            [make_finding(check_id="CM-009", severity=Severity.MEDIUM)],
            _coverage(skipped_apis_by_project={"proj-1": ["container.googleapis.com"]}),
        )
        assert risk.level == 1
        assert risk.auto_approval_eligible is True
        assert risk.auto_approval_blockers == []
