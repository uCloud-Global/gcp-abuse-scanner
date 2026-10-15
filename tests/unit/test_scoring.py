"""Unit tests for the scoring engine."""

from __future__ import annotations

import pytest

from gcp_abuse_scanner.models.finding import (
    Finding,
    FindingStatus,
    GCPResource,
    Remediation,
    RemediationEffort,
    Severity,
    Vector,
)
from gcp_abuse_scanner.scoring.engine import ScoringEngine, load_allowlist


def _make_finding(
    check_id: str,
    severity: Severity,
    exploitability: float = 5.0,
    blast_radius: str = "project",
    project_id: str = "test-project",
) -> Finding:
    return Finding(
        finding_id=f"{check_id}-{project_id}-test",
        check_id=check_id,
        vector=Vector.CRYPTO_MINING,
        title=f"Test finding {check_id}",
        severity=severity,
        status=FindingStatus.FAIL,
        exploitability_score=exploitability,
        blast_radius=blast_radius,
        resource=GCPResource(
            resource_type="compute.googleapis.com/Instance",
            resource_id=f"projects/{project_id}/instances/test-vm",
            project_id=project_id,
        ),
        description="Test description",
        impact="Test impact",
        remediation=Remediation(
            summary="Test remediation",
            effort=RemediationEffort.LOW,
        ),
    )


class TestScoringEngine:
    def test_priority_ranks_assigned(self) -> None:
        findings = [
            _make_finding("CM-001", Severity.LOW, exploitability=2.0),
            _make_finding("CM-004", Severity.CRITICAL, exploitability=9.5),
            _make_finding("CM-009", Severity.MEDIUM, exploitability=4.0),
        ]
        engine = ScoringEngine()
        result = engine.process(findings)

        ranked = sorted(result, key=lambda f: f.priority_rank or 9999)
        assert ranked[0].check_id == "CM-004"  # CRITICAL + highest exploitability
        assert ranked[-1].check_id == "CM-001"  # LOW + lowest exploitability

    def test_allowlist_suppresses_finding(self) -> None:
        findings = [
            _make_finding("CM-001", Severity.HIGH, project_id="allowed-project"),
            _make_finding("CM-004", Severity.CRITICAL, project_id="other-project"),
        ]
        allowlist = [
            {"check_id": "CM-001", "project_id": "allowed-project", "reason": "Known exception"}
        ]
        engine = ScoringEngine(allowlist=allowlist)
        result = engine.process(findings)

        suppressed = [f for f in result if f.suppressed]
        active = [f for f in result if not f.suppressed]
        assert len(suppressed) == 1
        assert suppressed[0].check_id == "CM-001"
        assert len(active) == 1
        assert active[0].check_id == "CM-004"

    def test_blast_radius_affects_priority(self) -> None:
        # Same exploitability, different blast radius
        findings = [
            _make_finding("CM-001", Severity.HIGH, exploitability=7.0, blast_radius="project"),
            _make_finding(
                "CM-002", Severity.HIGH, exploitability=7.0, blast_radius="billing_account"
            ),
        ]
        engine = ScoringEngine()
        result = engine.process(findings)
        ranked = sorted(result, key=lambda f: f.priority_rank or 9999)
        assert ranked[0].check_id == "CM-002"  # billing_account has higher weight

    def test_posture_score_100_when_no_findings(self) -> None:
        engine = ScoringEngine()
        summary = engine.build_executive_summary([], max_projects=1)
        assert summary.posture_score == 100.0

    def test_posture_score_decreases_with_critical_findings(self) -> None:
        findings = [
            _make_finding("CM-004", Severity.CRITICAL, exploitability=9.5) for _ in range(5)
        ]
        engine = ScoringEngine()
        processed = engine.process(findings)
        summary = engine.build_executive_summary(processed, max_projects=1)
        assert summary.posture_score < 100.0
        assert summary.by_severity.critical == 5


class TestLoadAllowlist:
    def test_top_level_list(self, tmp_path):
        path = tmp_path / "allowlist.yaml"
        path.write_text("- check_id: CM-001\n  reason: r\n")
        assert load_allowlist(path) == [{"check_id": "CM-001", "reason": "r"}]

    def test_mapping_with_allowlist_key(self, tmp_path):
        """The documented `allowlist:` format must load, not crash the scoring engine."""
        path = tmp_path / "allowlist.yaml"
        path.write_text("allowlist:\n  - check_id: CM-001\n    project_id: p\n")
        assert load_allowlist(path) == [{"check_id": "CM-001", "project_id": "p"}]

    def test_config_example_file_loads(self):
        from pathlib import Path

        rules = load_allowlist(Path(__file__).parents[2] / "examples" / "config.example.yaml")
        assert [r["check_id"] for r in rules] == ["CM-001", "CM-009"]

    def test_empty_file(self, tmp_path):
        path = tmp_path / "allowlist.yaml"
        path.write_text("")
        assert load_allowlist(path) == []

    def test_empty_allowlist_key(self, tmp_path):
        path = tmp_path / "allowlist.yaml"
        path.write_text("allowlist:\n")
        assert load_allowlist(path) == []

    def test_mapping_without_allowlist_key_raises(self, tmp_path):
        path = tmp_path / "allowlist.yaml"
        path.write_text("check_id: CM-001\n")
        with pytest.raises(ValueError, match="'allowlist' key"):
            load_allowlist(path)

    def test_non_mapping_rule_raises(self, tmp_path):
        path = tmp_path / "allowlist.yaml"
        path.write_text("- CM-001\n")
        with pytest.raises(ValueError, match="rule #1"):
            load_allowlist(path)

    def test_scalar_allowlist_raises(self, tmp_path):
        path = tmp_path / "allowlist.yaml"
        path.write_text("allowlist: CM-001\n")
        with pytest.raises(ValueError, match="must be a list"):
            load_allowlist(path)

    def test_invalid_yaml_raises(self, tmp_path):
        path = tmp_path / "allowlist.yaml"
        path.write_text("- check_id: [unclosed\n")
        with pytest.raises(ValueError, match="invalid YAML"):
            load_allowlist(path)

    def test_mapping_rules_suppress_findings(self, tmp_path):
        path = tmp_path / "allowlist.yaml"
        path.write_text("allowlist:\n  - check_id: CM-001\n    reason: accepted\n")
        finding = _make_finding("CM-001", Severity.HIGH)
        result = ScoringEngine(allowlist=load_allowlist(path)).process([finding])
        assert result[0].suppressed is True
        assert result[0].suppression_reason == "accepted"


class TestPenaltyPoints:
    """penalty_points is the scope-independent companion of posture_score (docs/risk-model.md)."""

    @staticmethod
    def _summary(findings: list[Finding], max_projects: int = 1):
        return ScoringEngine().build_executive_summary(findings, max_projects=max_projects)

    def test_weights_are_severity_based(self) -> None:
        findings = [
            _make_finding("CM-004", Severity.CRITICAL),
            _make_finding("GEM-002", Severity.CRITICAL),
            _make_finding("CM-001", Severity.HIGH),
            _make_finding("CM-009", Severity.MEDIUM),
            _make_finding("CMN-003", Severity.LOW),
        ]
        assert self._summary(findings).penalty_points == 10 + 10 + 5 + 2 + 0.5

    def test_no_findings_means_zero_penalty(self) -> None:
        summary = self._summary([])
        assert summary.penalty_points == 0.0
        assert summary.posture_score == 100.0

    def test_suppressed_findings_do_not_penalize(self) -> None:
        active = _make_finding("CM-004", Severity.CRITICAL)
        suppressed = _make_finding("GEM-002", Severity.CRITICAL, project_id="other")
        suppressed.suppressed = True
        assert self._summary([active, suppressed]).penalty_points == 10.0

    def test_penalty_is_independent_of_scope(self) -> None:
        """Same findings → same penalty whatever the scope; posture_score differs."""
        findings = [
            _make_finding("CM-004", Severity.CRITICAL),
            _make_finding("CM-001", Severity.HIGH),
        ]

        one = self._summary(findings, max_projects=1)
        hundred = self._summary(findings, max_projects=100)

        assert one.penalty_points == hundred.penalty_points == 15.0
        assert one.posture_score == 0.0  # clamped: 100 - (15/10 × 100) = -50
        assert hundred.posture_score > one.posture_score

    def test_penalty_still_moves_when_posture_is_already_zero(self) -> None:
        """The live scan's case: posture 0.0 whether the penalty is 11 or 85."""
        few = [_make_finding("CM-004", Severity.CRITICAL)]  # penalty 10 → posture 0.0
        many = [_make_finding("CM-004", Severity.CRITICAL)] + [
            _make_finding(f"CM-00{i}", Severity.HIGH) for i in range(10)
        ]

        summary_few = self._summary(few)
        summary_many = self._summary(many)

        assert summary_few.posture_score == summary_many.posture_score == 0.0
        assert summary_few.penalty_points == 10.0
        assert summary_many.penalty_points == 60.0

    def test_fixing_a_finding_lowers_the_penalty_linearly(self) -> None:
        findings = [
            _make_finding("CM-004", Severity.CRITICAL),
            _make_finding("CM-001", Severity.HIGH),
        ]
        before = self._summary(findings).penalty_points
        after = self._summary([findings[1]]).penalty_points

        assert before - after == 10.0  # removing the CRITICAL removes exactly its weight
