"""Shared pytest fixtures for gcp-abuse-scanner tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

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
from gcp_abuse_scanner.models.inventory import ResourceInventory
from gcp_abuse_scanner.models.report import (
    CoverageReport,
    ExecutiveSummary,
    ScanMetadata,
    ScanReport,
    SeveritySummary,
    VectorSummary,
)

# ─── Finding factories ────────────────────────────────────────────────────────


@pytest.fixture
def make_finding():
    """Factory fixture: returns a callable that creates Finding objects."""

    def _factory(
        check_id: str = "CM-001",
        severity: Severity = Severity.HIGH,
        vector: Vector = Vector.CRYPTO_MINING,
        status: FindingStatus = FindingStatus.FAIL,
        priority_rank: int = 1,
        suppressed: bool = False,
        project_id: str = "proj-1",
        evidence: dict | None = None,
    ) -> Finding:
        return Finding(
            finding_id=f"{check_id}-{project_id}-abc",
            check_id=check_id,
            vector=vector,
            title=f"Test finding {check_id}",
            severity=severity,
            status=status,
            exploitability_score=7.5,
            blast_radius="project",
            priority_rank=priority_rank,
            suppressed=suppressed,
            resource=GCPResource(
                resource_type="compute.googleapis.com/Instance",
                resource_id=f"projects/{project_id}/zones/us-central1-a/instances/vm-1",
                project_id=project_id,
                region="us-central1-a",
            ),
            evidence=evidence or {"instance_name": "vm-1"},
            description="Test description.",
            impact="Test impact.",
            remediation=Remediation(
                summary="Fix by doing X.",
                steps=["Step 1.", "Step 2."],
                gcloud_commands=["gcloud compute instances delete vm-1"],
                effort=RemediationEffort.LOW,
            ),
        )

    return _factory


@pytest.fixture
def sample_finding(make_finding) -> Finding:
    """A single HIGH crypto-mining finding."""
    return make_finding()


@pytest.fixture
def sample_inventory() -> ResourceInventory:
    """Minimal ResourceInventory for unit tests."""
    return ResourceInventory(
        project_ids=["proj-1", "proj-2"],
        organization_id="123456789",
    )


# ─── Report factory ───────────────────────────────────────────────────────────


@pytest.fixture
def make_report(make_finding):
    """Factory fixture: returns a callable that creates ScanReport objects."""

    def _factory(findings: list[Finding] | None = None) -> ScanReport:
        if findings is None:
            findings = [make_finding()]
        active = [f for f in findings if not f.suppressed and f.status == FindingStatus.FAIL]
        return ScanReport(
            metadata=ScanMetadata(
                scan_id="test-scan-abcd1234",
                started_at=datetime(2026, 7, 17, 12, 0, 0, tzinfo=UTC),
                finished_at=datetime(2026, 7, 17, 12, 1, 30, tzinfo=UTC),
                duration_seconds=90.0,
                scope_type="project_list",
                organization_id="123456789",
                project_ids=["proj-1", "proj-2"],
                service_account="scanner@proj-1.iam.gserviceaccount.com",
                vectors_scanned=["crypto_mining", "gemini_abuse", "common"],
            ),
            executive_summary=ExecutiveSummary(
                posture_score=72.5,
                total_findings=len(active),
                by_severity=SeveritySummary(
                    critical=sum(1 for f in active if f.severity == Severity.CRITICAL),
                    high=sum(1 for f in active if f.severity == Severity.HIGH),
                    medium=sum(1 for f in active if f.severity == Severity.MEDIUM),
                    low=sum(1 for f in active if f.severity == Severity.LOW),
                    total=len(active),
                ),
                by_vector=[VectorSummary(vector="crypto_mining", findings_count=len(active))],
                top_findings=[],
            ),
            coverage=CoverageReport(
                projects_scanned=2,
                projects_inaccessible=0,
                checks_executed=43,
                checks_passed=40,
                checks_failed=len(active),
                checks_not_applicable=0,
                skipped_apis_by_project={},
                collector_errors=[],
            ),
            findings=findings,
        )

    return _factory


@pytest.fixture
def sample_report(make_report) -> ScanReport:
    """A minimal ScanReport with one HIGH finding."""
    return make_report()


# ─── File fixtures ────────────────────────────────────────────────────────────


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to tests/fixtures/."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def crypto_inventory_fixture(fixtures_dir) -> dict:
    """Raw dict from inventory_crypto_mining.json."""
    import json

    return json.loads((fixtures_dir / "inventory_crypto_mining.json").read_text())


@pytest.fixture
def gemini_inventory_fixture(fixtures_dir) -> dict:
    """Raw dict from inventory_gemini_abuse.json."""
    import json

    return json.loads((fixtures_dir / "inventory_gemini_abuse.json").read_text())
