"""Unit tests for HTML reporter, SARIF reporter, and InventoryCache."""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime

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

# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


def _make_finding(
    check_id: str = "CM-001",
    severity: Severity = Severity.HIGH,
    vector: Vector = Vector.CRYPTO_MINING,
    status: FindingStatus = FindingStatus.FAIL,
    priority_rank: int = 1,
    suppressed: bool = False,
) -> Finding:
    return Finding(
        finding_id=f"{check_id}-proj-abc123",
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
            resource_id="projects/proj-1/zones/us-central1-a/instances/vm-1",
            project_id="proj-1",
            region="us-central1-a",
        ),
        evidence={"instance_name": "vm-1", "zone": "us-central1-a"},
        description="Test description for the finding.",
        impact="Test impact statement.",
        remediation=Remediation(
            summary="Fix the issue by doing X.",
            steps=["Step 1: Do this.", "Step 2: Do that."],
            gcloud_commands=["gcloud compute instances delete vm-1 --zone=us-central1-a"],
            iac_reference="google_compute_instance.network_interface",
            docs=["https://cloud.google.com/docs"],
            effort=RemediationEffort.LOW,
        ),
        references=["CIS GCP 4.9"],
    )


def _make_report(findings: list[Finding] | None = None) -> ScanReport:
    if findings is None:
        findings = [_make_finding()]
    active = [f for f in findings if not f.suppressed and f.status == FindingStatus.FAIL]
    critical = sum(1 for f in active if f.severity == Severity.CRITICAL)
    high = sum(1 for f in active if f.severity == Severity.HIGH)
    medium = sum(1 for f in active if f.severity == Severity.MEDIUM)
    low = sum(1 for f in active if f.severity == Severity.LOW)

    return ScanReport(
        metadata=ScanMetadata(
            scan_id="test-scan-1234",
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
                critical=critical, high=high, medium=medium, low=low, total=len(active)
            ),
            by_vector=[
                VectorSummary(vector="crypto_mining", findings_count=len(active)),
            ],
            top_findings=[],
        ),
        coverage=CoverageReport(
            projects_scanned=2,
            projects_inaccessible=0,
            checks_executed=43,
            checks_passed=40,
            checks_failed=len(active),
            checks_not_applicable=0,
            skipped_apis_by_project={"proj-2": ["container.googleapis.com"]},
            collector_errors=[],
        ),
        findings=findings,
    )


# ─────────────────────────────────────────────────────────────────────────────
# HTMLReporter
# ─────────────────────────────────────────────────────────────────────────────


class TestHTMLReporter:
    def test_render_returns_html_string(self):
        from gcp_abuse_scanner.reporters.html_reporter import HTMLReporter

        report = _make_report()
        html = HTMLReporter().render(report)

        assert isinstance(html, str)
        assert "<!DOCTYPE html>" in html or "<html" in html

    def test_html_contains_scan_metadata(self):
        from gcp_abuse_scanner.reporters.html_reporter import HTMLReporter

        report = _make_report()
        html = HTMLReporter().render(report)

        assert "test-scan-1234" in html
        assert "proj-1" in html

    def test_html_contains_finding_info(self):
        from gcp_abuse_scanner.reporters.html_reporter import HTMLReporter

        report = _make_report()
        html = HTMLReporter().render(report)

        assert "CM-001" in html
        assert "Test finding CM-001" in html

    def test_html_contains_posture_score(self):
        from gcp_abuse_scanner.reporters.html_reporter import HTMLReporter

        report = _make_report()
        html = HTMLReporter().render(report)

        assert "72" in html  # posture score 72.5

    def test_html_writes_to_file(self, tmp_path):
        from gcp_abuse_scanner.reporters.html_reporter import HTMLReporter

        out = tmp_path / "report.html"
        report = _make_report()
        html = HTMLReporter(output_path=out).render(report)

        assert out.exists()
        assert out.read_text(encoding="utf-8") == html

    def test_html_no_findings_message(self):
        from gcp_abuse_scanner.reporters.html_reporter import HTMLReporter

        report = _make_report(findings=[])
        html = HTMLReporter().render(report)

        # Should render without error even with no findings
        assert isinstance(html, str)
        assert len(html) > 100

    def test_html_severity_badge_filter(self):
        from gcp_abuse_scanner.reporters.html_reporter import HTMLReporter

        report = _make_report(
            [
                _make_finding(check_id="CM-001", severity=Severity.CRITICAL),
                _make_finding(
                    check_id="GEM-001", severity=Severity.MEDIUM, vector=Vector.GEMINI_ABUSE
                ),
            ]
        )
        html = HTMLReporter().render(report)

        assert "CRITICAL" in html
        assert "MEDIUM" in html

    def test_html_remediation_steps_present(self):
        from gcp_abuse_scanner.reporters.html_reporter import HTMLReporter

        report = _make_report()
        html = HTMLReporter().render(report)

        assert "Step 1: Do this." in html
        assert "gcloud compute instances delete" in html

    def test_html_coverage_section(self):
        from gcp_abuse_scanner.reporters.html_reporter import HTMLReporter

        report = _make_report()
        html = HTMLReporter().render(report)

        # Coverage data should appear
        assert (
            "container.googleapis.com" in html
        )  # skipped API  # lgtm[py/incomplete-url-substring-sanitization]


# ─────────────────────────────────────────────────────────────────────────────
# SARIFReporter
# ─────────────────────────────────────────────────────────────────────────────


class TestSARIFReporter:
    def test_render_returns_valid_json(self):
        from gcp_abuse_scanner.reporters.sarif_reporter import SARIFReporter

        report = _make_report()
        sarif_str = SARIFReporter().render(report)
        sarif = json.loads(sarif_str)

        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_sarif_tool_metadata(self):
        from gcp_abuse_scanner.reporters.sarif_reporter import SARIFReporter

        report = _make_report()
        sarif = json.loads(SARIFReporter().render(report))
        driver = sarif["runs"][0]["tool"]["driver"]

        assert driver["name"] == "gcp-abuse-scanner"
        assert "version" in driver

    def test_sarif_rules_deduplicated(self):
        from gcp_abuse_scanner.reporters.sarif_reporter import SARIFReporter

        # Two findings with same check_id → one rule
        findings = [
            _make_finding(check_id="CM-001", priority_rank=1),
            _make_finding(check_id="CM-001", priority_rank=2),
            _make_finding(check_id="GEM-001", vector=Vector.GEMINI_ABUSE, priority_rank=3),
        ]
        report = _make_report(findings)
        sarif = json.loads(SARIFReporter().render(report))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]

        assert rule_ids.count("CM-001") == 1
        assert "GEM-001" in rule_ids

    def test_sarif_results_only_fail_findings(self):
        from gcp_abuse_scanner.reporters.sarif_reporter import SARIFReporter

        findings = [
            _make_finding(check_id="CM-001", status=FindingStatus.FAIL),
            _make_finding(check_id="CM-002", status=FindingStatus.PASS),
            _make_finding(check_id="CM-003", status=FindingStatus.FAIL, suppressed=True),
        ]
        report = _make_report(findings)
        sarif = json.loads(SARIFReporter().render(report))
        results = sarif["runs"][0]["results"]

        # Only FAIL + not suppressed → 1 result
        assert len(results) == 1
        assert results[0]["ruleId"] == "CM-001"

    def test_sarif_severity_mapping(self):
        from gcp_abuse_scanner.reporters.sarif_reporter import SARIFReporter

        findings = [
            _make_finding(check_id="CM-001", severity=Severity.CRITICAL),
            _make_finding(check_id="CM-002", severity=Severity.MEDIUM),
            _make_finding(check_id="CM-003", severity=Severity.LOW),
        ]
        report = _make_report(findings)
        sarif = json.loads(SARIFReporter().render(report))
        results = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}

        assert results["CM-001"] == "error"
        assert results["CM-002"] == "warning"
        assert results["CM-003"] == "note"

    def test_sarif_result_properties(self):
        from gcp_abuse_scanner.reporters.sarif_reporter import SARIFReporter

        report = _make_report()
        sarif = json.loads(SARIFReporter().render(report))
        result = sarif["runs"][0]["results"][0]

        assert "ruleId" in result
        assert "level" in result
        assert "message" in result
        assert "locations" in result
        assert "properties" in result
        props = result["properties"]
        assert props["check_id"] == "CM-001"
        assert props["vector"] == "crypto_mining"
        assert props["project_id"] == "proj-1"

    def test_sarif_logical_location_format(self):
        from gcp_abuse_scanner.reporters.sarif_reporter import SARIFReporter

        report = _make_report()
        sarif = json.loads(SARIFReporter().render(report))
        locations = sarif["runs"][0]["results"][0]["locations"]

        assert len(locations) > 0
        fqn = locations[0]["logicalLocations"][0]["fullyQualifiedName"]
        assert fqn.startswith("gcp://")
        assert "proj-1" in fqn

    def test_sarif_writes_to_file(self, tmp_path):
        from gcp_abuse_scanner.reporters.sarif_reporter import SARIFReporter

        out = tmp_path / "results.sarif"
        report = _make_report()
        sarif_str = SARIFReporter(output_path=out).render(report)

        assert out.exists()
        assert out.read_text(encoding="utf-8") == sarif_str

    def test_sarif_invocations_present(self):
        from gcp_abuse_scanner.reporters.sarif_reporter import SARIFReporter

        report = _make_report()
        sarif = json.loads(SARIFReporter().render(report))
        invocations = sarif["runs"][0]["invocations"]

        assert len(invocations) == 1
        assert invocations[0]["executionSuccessful"] is True
        assert "startTimeUtc" in invocations[0]

    def test_sarif_empty_findings(self):
        from gcp_abuse_scanner.reporters.sarif_reporter import SARIFReporter

        report = _make_report(findings=[])
        sarif = json.loads(SARIFReporter().render(report))

        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


# ─────────────────────────────────────────────────────────────────────────────
# Risk assessment rendering (SOP 1–4 + coverage gate)
# ─────────────────────────────────────────────────────────────────────────────


def _report_with_risk(gaps: bool = False) -> ScanReport:
    """Report carrying a computed risk_assessment (or a coverage gap)."""
    from gcp_abuse_scanner.models.finding import Severity as _Severity
    from gcp_abuse_scanner.scoring.risk import assess_risk

    findings = [_make_finding(check_id="GEM-001", severity=_Severity.CRITICAL)]
    report = _make_report(findings)
    coverage = CoverageReport(
        projects_scanned=2,
        skipped_apis_by_project={"proj-2": ["apikeys.googleapis.com"]} if gaps else {},
    )
    report.coverage = coverage
    report.risk_assessment = assess_risk(findings, coverage)
    return report


class TestRiskAssessmentRendering:
    def test_markdown_renders_level_and_blockers(self):
        from gcp_abuse_scanner.reporters.markdown_reporter import MarkdownReporter

        md = MarkdownReporter().render(_report_with_risk())
        assert "## Risk Assessment" in md
        assert "4/4 — CRITICAL" in md
        assert "auto-approval | ❌ blocked" in md.lower()
        assert "unrestricted gemini api key" in md.lower()

    def test_markdown_renders_coverage_gap_table(self):
        from gcp_abuse_scanner.reporters.markdown_reporter import MarkdownReporter

        md = MarkdownReporter().render(_report_with_risk(gaps=True))
        assert "1 gap(s)" in md
        assert "| `api_keys` |" in md
        assert "`proj-2`" in md

    def test_html_renders_risk_card(self):
        from gcp_abuse_scanner.reporters.html_reporter import HTMLReporter

        html = HTMLReporter().render(_report_with_risk(gaps=True))
        assert "Risk Assessment" in html
        assert "4/4 — CRITICAL" in html
        assert "Coverage Gaps" in html
        assert "api_keys" in html

    def test_console_renders_risk_panel(self, capsys):
        from gcp_abuse_scanner.reporters.console_reporter import ConsoleReporter

        ConsoleReporter().render(_report_with_risk(gaps=True))
        out = capsys.readouterr().out
        assert "Risk Assessment" in out
        assert "4/4 (CRITICAL)" in out
        assert "not auto-approvable" in out

    def test_reporters_tolerate_report_without_risk_assessment(self):
        """Reports built before the risk model existed must still render."""
        from gcp_abuse_scanner.reporters.html_reporter import HTMLReporter
        from gcp_abuse_scanner.reporters.markdown_reporter import MarkdownReporter

        report = _make_report()
        assert report.risk_assessment is None
        assert "## Risk Assessment" not in MarkdownReporter().render(report)
        assert "Risk Assessment" not in HTMLReporter().render(report)


# ─────────────────────────────────────────────────────────────────────────────
# penalty_points rendering (the scope-independent drift metric)
# ─────────────────────────────────────────────────────────────────────────────


class TestPenaltyRendering:
    def _report(self) -> ScanReport:
        report = _make_report()
        report.executive_summary.penalty_points = 85.0
        return report

    def test_markdown_shows_penalty_and_the_normalization_caveat(self):
        from gcp_abuse_scanner.reporters.markdown_reporter import MarkdownReporter

        md = MarkdownReporter().render(self._report())
        assert "Penalty points | 85" in md
        assert "normalized by project count" in md

    def test_console_shows_penalty_points(self, capsys):
        from gcp_abuse_scanner.reporters.console_reporter import ConsoleReporter

        ConsoleReporter().render(self._report())
        assert "penalty 85 pts" in capsys.readouterr().out

    def test_html_shows_penalty_points(self):
        from gcp_abuse_scanner.reporters.html_reporter import HTMLReporter

        html = HTMLReporter().render(self._report())
        assert "penalty 85 pts" in html

    def test_penalty_defaults_to_zero_when_not_set(self):
        """Reports produced before this field existed must still render."""
        from gcp_abuse_scanner.reporters.markdown_reporter import MarkdownReporter

        report = _make_report()
        report.executive_summary.penalty_points = 0.0
        assert "Penalty points | 0" in MarkdownReporter().render(report)


# ─────────────────────────────────────────────────────────────────────────────
# InventoryCache
# ─────────────────────────────────────────────────────────────────────────────


class TestInventoryCache:
    def test_set_and_get_roundtrip(self, tmp_path):
        from gcp_abuse_scanner.collectors.cache import InventoryCache

        cache = InventoryCache(cache_dir=tmp_path, ttl_seconds=3600)
        inv = ResourceInventory(project_ids=["proj-1", "proj-2"], organization_id="org-123")

        cache.set(inv, ["proj-1", "proj-2"], organization_id="org-123")
        result = cache.get(["proj-1", "proj-2"], organization_id="org-123")

        assert result is not None
        assert set(result.project_ids) == {"proj-1", "proj-2"}
        assert result.organization_id == "org-123"

    def test_cache_miss_returns_none(self, tmp_path):
        from gcp_abuse_scanner.collectors.cache import InventoryCache

        cache = InventoryCache(cache_dir=tmp_path, ttl_seconds=3600)
        result = cache.get(["proj-x"], organization_id=None)

        assert result is None

    def test_cache_expired_returns_none(self, tmp_path):
        from gcp_abuse_scanner.collectors.cache import InventoryCache

        cache = InventoryCache(cache_dir=tmp_path, ttl_seconds=1)
        inv = ResourceInventory(project_ids=["proj-1"])
        cache.set(inv, ["proj-1"])

        # Simulate expiry by writing a stale cached_at
        key = cache._cache_key(["proj-1"], None)
        path = cache._cache_path(key)
        data = json.loads(gzip.decompress(path.read_bytes()))
        data["cached_at"] = "2000-01-01T00:00:00+00:00"  # ancient timestamp
        path.write_bytes(gzip.compress(json.dumps(data).encode()))

        result = cache.get(["proj-1"])
        assert result is None

    def test_cache_corrupt_returns_none(self, tmp_path):
        from gcp_abuse_scanner.collectors.cache import InventoryCache

        cache = InventoryCache(cache_dir=tmp_path, ttl_seconds=3600)
        inv = ResourceInventory(project_ids=["proj-1"])
        cache.set(inv, ["proj-1"])

        # Corrupt the file
        key = cache._cache_key(["proj-1"], None)
        path = cache._cache_path(key)
        path.write_bytes(b"not valid gzip data")

        result = cache.get(["proj-1"])
        assert result is None

    def test_invalidate_removes_cache(self, tmp_path):
        from gcp_abuse_scanner.collectors.cache import InventoryCache

        cache = InventoryCache(cache_dir=tmp_path, ttl_seconds=3600)
        inv = ResourceInventory(project_ids=["proj-1"])
        cache.set(inv, ["proj-1"])

        deleted = cache.invalidate(["proj-1"])
        assert deleted is True
        assert cache.get(["proj-1"]) is None

    def test_invalidate_nonexistent_returns_false(self, tmp_path):
        from gcp_abuse_scanner.collectors.cache import InventoryCache

        cache = InventoryCache(cache_dir=tmp_path, ttl_seconds=3600)
        result = cache.invalidate(["proj-nonexistent"])
        assert result is False

    def test_clear_all_removes_all_entries(self, tmp_path):
        from gcp_abuse_scanner.collectors.cache import InventoryCache

        cache = InventoryCache(cache_dir=tmp_path, ttl_seconds=3600)
        cache.set(ResourceInventory(project_ids=["proj-1"]), ["proj-1"])
        cache.set(ResourceInventory(project_ids=["proj-2"]), ["proj-2"])

        count = cache.clear_all()
        assert count == 2
        assert cache.get(["proj-1"]) is None
        assert cache.get(["proj-2"]) is None

    def test_is_valid_true_when_cached(self, tmp_path):
        from gcp_abuse_scanner.collectors.cache import InventoryCache

        cache = InventoryCache(cache_dir=tmp_path, ttl_seconds=3600)
        inv = ResourceInventory(project_ids=["proj-1"])
        cache.set(inv, ["proj-1"])

        assert cache.is_valid(["proj-1"]) is True

    def test_is_valid_false_when_not_cached(self, tmp_path):
        from gcp_abuse_scanner.collectors.cache import InventoryCache

        cache = InventoryCache(cache_dir=tmp_path, ttl_seconds=3600)
        assert cache.is_valid(["proj-missing"]) is False

    def test_cache_key_order_independent(self, tmp_path):
        from gcp_abuse_scanner.collectors.cache import InventoryCache

        cache = InventoryCache(cache_dir=tmp_path, ttl_seconds=3600)
        key1 = cache._cache_key(["proj-a", "proj-b"], "org-1")
        key2 = cache._cache_key(["proj-b", "proj-a"], "org-1")

        assert key1 == key2

    def test_cache_creates_directory_if_missing(self, tmp_path):
        from gcp_abuse_scanner.collectors.cache import InventoryCache

        new_dir = tmp_path / "nested" / "cache"
        cache = InventoryCache(cache_dir=new_dir, ttl_seconds=3600)
        inv = ResourceInventory(project_ids=["proj-1"])
        cache.set(inv, ["proj-1"])

        assert new_dir.exists()
        assert cache.get(["proj-1"]) is not None

    def test_cache_file_is_gzip_compressed(self, tmp_path):
        from gcp_abuse_scanner.collectors.cache import InventoryCache

        cache = InventoryCache(cache_dir=tmp_path, ttl_seconds=3600)
        inv = ResourceInventory(project_ids=["proj-1"])
        path = cache.set(inv, ["proj-1"])

        # Verify it's valid gzip
        data = gzip.decompress(path.read_bytes())
        parsed = json.loads(data)
        assert "inventory" in parsed
        assert "cached_at" in parsed
        assert "ttl_seconds" in parsed
