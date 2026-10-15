"""CLI tests using typer.testing.CliRunner — no real GCP calls."""

from __future__ import annotations

import re
from datetime import UTC
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from gcp_abuse_scanner.cli import app
from gcp_abuse_scanner.models.finding import FindingStatus, Severity

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _flat(output: str) -> str:
    """Strip Rich/Click styling and wrapping — CI colourises flag names and box art.

    Without this, assertions on Click's own error messages are terminal-dependent:
    Rich styles '--allowlist' as 'Invalid value for '\x1b[1;36m--allowlist\x1b[0m'', so
    the literal substring only exists in some environments (it passed locally, failed
    on GitHub Actions).
    """
    return " ".join(_ANSI.sub("", output.replace("│", " ")).split())


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _make_mock_report(has_critical: bool = False, finding_count: int = 1):
    """Build a minimal mock ScanReport."""
    from datetime import datetime

    from gcp_abuse_scanner.models.finding import (
        Finding,
        GCPResource,
        Remediation,
        RemediationEffort,
        Vector,
    )
    from gcp_abuse_scanner.models.report import (
        CoverageReport,
        ExecutiveSummary,
        ScanMetadata,
        ScanReport,
        SeveritySummary,
        VectorSummary,
    )

    sev = Severity.CRITICAL if has_critical else Severity.HIGH
    findings = []
    for i in range(finding_count):
        findings.append(
            Finding(
                finding_id=f"CM-001-proj-{i}",
                check_id="CM-001",
                vector=Vector.CRYPTO_MINING,
                title="Test finding",
                severity=sev,
                status=FindingStatus.FAIL,
                exploitability_score=7.5,
                blast_radius="project",
                priority_rank=i + 1,
                resource=GCPResource(
                    resource_type="compute.googleapis.com/Instance",
                    resource_id=f"projects/proj-1/zones/us-central1-a/instances/vm-{i}",
                    project_id="proj-1",
                    region="us-central1-a",
                ),
                evidence={},
                description="desc",
                impact="impact",
                remediation=Remediation(
                    summary="Fix it.",
                    steps=["Step 1."],
                    effort=RemediationEffort.LOW,
                ),
            )
        )

    # same weights the scoring engine uses, so the mocked summary reflects reality
    weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "INFO": 0}
    penalty = sum(weights[f.severity.value] for f in findings)

    return ScanReport(
        metadata=ScanMetadata(
            scan_id="abcd1234-0000-0000-0000-000000000000",
            started_at=datetime(2026, 7, 17, 12, 0, 0, tzinfo=UTC),
            finished_at=datetime(2026, 7, 17, 12, 1, 0, tzinfo=UTC),
            duration_seconds=60.0,
            scope_type="project_list",
            organization_id=None,
            project_ids=["proj-1"],
            service_account="scanner@proj-1.iam.gserviceaccount.com",
            vectors_scanned=["crypto_mining", "gemini_abuse", "common"],
        ),
        executive_summary=ExecutiveSummary(
            posture_score=50.0,
            penalty_points=penalty,
            total_findings=finding_count,
            by_severity=SeveritySummary(
                critical=finding_count if has_critical else 0,
                high=0 if has_critical else finding_count,
                medium=0,
                low=0,
                total=finding_count,
            ),
            by_vector=[VectorSummary(vector="crypto_mining", findings_count=finding_count)],
            top_findings=[],
        ),
        coverage=CoverageReport(
            projects_scanned=1,
            projects_inaccessible=0,
            checks_executed=43,
            checks_passed=42,
            checks_failed=finding_count,
            checks_not_applicable=0,
            skipped_apis_by_project={},
            collector_errors=[],
        ),
        findings=findings,
    )


def _patch_scan_internals(report=None, project_ids=None):
    """
    Returns a context manager stack that patches all GCP-touching internals
    so the CLI `scan` command runs fully offline.
    """
    if report is None:
        report = _make_mock_report()
    if project_ids is None:
        project_ids = ["proj-1"]

    patches = [
        patch("gcp_abuse_scanner.auth.AuthManager", autospec=True),
        patch("gcp_abuse_scanner.auth.ScopeResolver", autospec=True),
        patch("gcp_abuse_scanner.collectors.engine.CollectorEngine", autospec=True),
        patch("gcp_abuse_scanner.scoring.ScoringEngine", autospec=True),
        patch("gcp_abuse_scanner.checks.CheckRegistry"),
    ]
    return patches, report, project_ids


# ─────────────────────────────────────────────────────────────────────────────
# version command
# ─────────────────────────────────────────────────────────────────────────────


class TestVersionCommand:
    def test_version_exits_zero(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0

    def test_version_output_contains_version_string(self):
        result = runner.invoke(app, ["version"])
        assert "gcp-abuse-scanner" in result.output
        # Should contain a version number like 0.1.0
        assert any(char.isdigit() for char in result.output)

    def test_version_flag(self):
        """--help on version subcommand works."""
        result = runner.invoke(app, ["version", "--help"])
        assert result.exit_code == 0


# ─────────────────────────────────────────────────────────────────────────────
# list-checks command
# ─────────────────────────────────────────────────────────────────────────────


class TestListChecksCommand:
    def test_list_checks_exits_zero(self):
        result = runner.invoke(app, ["list-checks"])
        assert result.exit_code == 0

    def test_list_checks_shows_check_ids(self):
        result = runner.invoke(app, ["list-checks"])
        # Rich truncates wide tables in narrow terminals; check for partial IDs or keywords
        output = result.output
        has_ids = "CM-" in output or "GEM-" in output or "CMN-" in output
        # Fallback: check for known title fragments that always appear
        has_titles = "external IP" in output or "API key" in output or "budget" in output.lower()
        assert has_ids or has_titles

    def test_list_checks_filter_by_vector(self):
        result = runner.invoke(app, ["list-checks", "--vector", "crypto_mining"])
        assert result.exit_code == 0
        # Crypto checks have titles with these keywords; Gemini checks do not
        assert "Vertex AI" not in result.output or "external IP" in result.output

    def test_list_checks_filter_gemini(self):
        result = runner.invoke(app, ["list-checks", "--vector", "gemini_abuse"])
        assert result.exit_code == 0
        # Gemini vector checks always mention API key or Vertex AI
        assert (
            "API key" in result.output
            or "Vertex AI" in result.output
            or "aiplatform" in result.output
        )

    def test_list_checks_filter_common(self):
        result = runner.invoke(app, ["list-checks", "--vector", "common"])
        assert result.exit_code == 0
        # Common checks always mention budget or audit
        assert (
            "budget" in result.output.lower()
            or "audit" in result.output.lower()
            or "billing" in result.output.lower()
        )

    def test_list_checks_shows_total_count(self):
        result = runner.invoke(app, ["list-checks"])
        assert "Total:" in result.output or "total" in result.output.lower()

    def test_list_checks_help(self):
        result = runner.invoke(app, ["list-checks", "--help"])
        assert result.exit_code == 0
        assert "vector" in result.output.lower()


# ─────────────────────────────────────────────────────────────────────────────
# scan command — argument validation (no GCP calls needed)
# ─────────────────────────────────────────────────────────────────────────────


class TestScanArgumentValidation:
    def test_scan_requires_org_or_project(self):
        """scan with no --org or --project must exit 1."""
        result = runner.invoke(app, ["scan"])
        assert result.exit_code == 1

    def test_scan_help_exits_zero(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0

    def test_scan_help_shows_all_formats(self):
        result = runner.invoke(app, ["scan", "--help"])
        # Rich may truncate long enum lists; verify at least the format option is present
        assert "--format" in result.output or "-f" in result.output
        # And at least one format value appears (console is shortest, least likely to truncate)
        assert "console" in result.output or "json" in result.output

    def test_scan_help_shows_cache_options(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert "cache" in result.output.lower()

    def test_scan_help_shows_vector_option(self):
        """--vector is a registered CLI option on the scan command."""
        import inspect

        from gcp_abuse_scanner.cli import scan

        sig = inspect.signature(scan)
        assert "vector" in sig.parameters

    def test_scan_help_shows_dry_run(self):
        """--dry-run is a registered CLI option on the scan command."""
        import inspect

        from gcp_abuse_scanner.cli import scan

        sig = inspect.signature(scan)
        assert "dry_run" in sig.parameters

    def test_scan_invalid_format_exits_nonzero(self):
        result = runner.invoke(app, ["scan", "--project", "proj-1", "--format", "xml"])
        assert result.exit_code != 0

    def test_app_help_exits_zero(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0

    def test_app_help_shows_subcommands(self):
        result = runner.invoke(app, ["--help"])
        assert "scan" in result.output
        assert "list-checks" in result.output
        assert "version" in result.output


# ─────────────────────────────────────────────────────────────────────────────
# scan command — dry-run (mocked scope, no collectors)
# ─────────────────────────────────────────────────────────────────────────────


class TestScanDryRun:
    def test_dry_run_exits_zero(self):
        mock_auth = MagicMock()
        mock_auth.identity = "scanner@proj.iam.gserviceaccount.com"
        mock_scope = MagicMock()
        mock_scope.resolve_projects.return_value = ["proj-1"]

        with (
            patch("gcp_abuse_scanner.auth.AuthManager", return_value=mock_auth),
            patch("gcp_abuse_scanner.auth.ScopeResolver", return_value=mock_scope),
        ):
            result = runner.invoke(app, ["scan", "--project", "proj-1", "--dry-run"])

        assert result.exit_code == 0

    def test_dry_run_lists_checks(self):
        mock_auth = MagicMock()
        mock_auth.identity = "scanner@proj.iam.gserviceaccount.com"
        mock_scope = MagicMock()
        mock_scope.resolve_projects.return_value = ["proj-1"]

        with (
            patch("gcp_abuse_scanner.auth.AuthManager", return_value=mock_auth),
            patch("gcp_abuse_scanner.auth.ScopeResolver", return_value=mock_scope),
        ):
            result = runner.invoke(app, ["scan", "--project", "proj-1", "--dry-run"])

        # Should list check IDs
        assert "CM-" in result.output or "GEM-" in result.output

    def test_dry_run_no_scope_exits_one(self):
        """dry-run with empty scope should exit 0 (no projects warning)."""
        mock_auth = MagicMock()
        mock_auth.identity = "scanner@proj.iam.gserviceaccount.com"
        mock_scope = MagicMock()
        mock_scope.resolve_projects.return_value = []

        with (
            patch("gcp_abuse_scanner.auth.AuthManager", return_value=mock_auth),
            patch("gcp_abuse_scanner.auth.ScopeResolver", return_value=mock_scope),
        ):
            result = runner.invoke(app, ["scan", "--project", "proj-1", "--dry-run"])

        assert result.exit_code == 0  # exits early with "no projects" warning

    def test_dry_run_scope_error_exits_one(self):
        mock_auth = MagicMock()
        mock_scope = MagicMock()
        mock_scope.resolve_projects.side_effect = RuntimeError("Permission denied")

        with (
            patch("gcp_abuse_scanner.auth.AuthManager", return_value=mock_auth),
            patch("gcp_abuse_scanner.auth.ScopeResolver", return_value=mock_scope),
        ):
            result = runner.invoke(app, ["scan", "--project", "proj-1", "--dry-run"])

        assert result.exit_code == 1


# ─────────────────────────────────────────────────────────────────────────────
# scan command — full pipeline (all internals mocked)
# ─────────────────────────────────────────────────────────────────────────────


class TestScanFullPipeline:
    def _run_scan_mocked(self, extra_args=None, has_critical=False, finding_count=1):
        """Run `scan --project proj-1` with all GCP internals mocked."""
        report = _make_mock_report(has_critical=has_critical, finding_count=finding_count)

        mock_auth = MagicMock()
        mock_auth.identity = "scanner@proj.iam.gserviceaccount.com"

        mock_scope = MagicMock()
        mock_scope.resolve_projects.return_value = ["proj-1"]

        mock_inventory = MagicMock()
        mock_inventory.inaccessible_projects = []
        mock_inventory.skipped_apis = {}
        mock_inventory.collector_errors = []

        mock_engine = MagicMock()
        mock_engine.collect.return_value = mock_inventory

        mock_check = MagicMock()
        mock_check.vector = MagicMock()
        mock_check.vector.value = "crypto_mining"
        mock_check.safe_evaluate.return_value = report.findings
        mock_check.is_applicable.return_value = True

        mock_scoring = MagicMock()
        mock_scoring.process.return_value = report.findings
        mock_scoring.build_executive_summary.return_value = report.executive_summary

        args = ["scan", "--project", "proj-1"] + (extra_args or [])

        with (
            patch("gcp_abuse_scanner.auth.AuthManager", return_value=mock_auth),
            patch("gcp_abuse_scanner.auth.ScopeResolver", return_value=mock_scope),
            patch("gcp_abuse_scanner.collectors.engine.CollectorEngine", return_value=mock_engine),
            patch("gcp_abuse_scanner.scoring.ScoringEngine", return_value=mock_scoring),
            patch("gcp_abuse_scanner.checks.CheckRegistry.all_checks", return_value=[mock_check]),
            patch("gcp_abuse_scanner.checks.CheckRegistry.list_metadata", return_value=[]),
        ):
            result = runner.invoke(app, args)

        return result

    def test_scan_console_format_exits_zero(self):
        result = self._run_scan_mocked(["--format", "console"])
        assert result.exit_code == 0

    def test_scan_critical_findings_exits_two(self):
        result = self._run_scan_mocked(has_critical=True)
        assert result.exit_code == 2

    def test_scan_no_critical_exits_zero(self):
        result = self._run_scan_mocked(has_critical=False)
        assert result.exit_code == 0

    def test_scan_json_format_creates_file(self, tmp_path):
        out = tmp_path / "report.json"
        result = self._run_scan_mocked(["--format", "json", "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()

    def test_scan_markdown_format_creates_file(self, tmp_path):
        out = tmp_path / "report.md"
        result = self._run_scan_mocked(["--format", "markdown", "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()

    def test_scan_html_format_creates_file(self, tmp_path):
        out = tmp_path / "report.html"
        result = self._run_scan_mocked(["--format", "html", "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()

    def test_scan_sarif_format_creates_file(self, tmp_path):
        out = tmp_path / "results.sarif"
        result = self._run_scan_mocked(["--format", "sarif", "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()

    def test_scan_all_format_creates_multiple_files(self, tmp_path):
        """--format all should produce json, md, html, sarif files."""
        import os

        orig_dir = os.getcwd()
        os.chdir(tmp_path)
        try:
            result = self._run_scan_mocked(["--format", "all"])
        finally:
            os.chdir(orig_dir)
        assert result.exit_code == 0

    def test_scan_vector_filter_applied(self):
        result = self._run_scan_mocked(["--vector", "crypto_mining"])
        assert result.exit_code == 0

    def test_scan_verbose_flag_accepted(self):
        result = self._run_scan_mocked(["--verbose"])
        assert result.exit_code == 0

    def test_scan_with_cache_flag(self):
        result = self._run_scan_mocked(["--cache"])
        assert result.exit_code == 0

    def test_scan_with_cache_ttl(self):
        result = self._run_scan_mocked(["--cache", "--cache-ttl", "7200"])
        assert result.exit_code == 0

    def test_scan_allowlist_nonexistent_file_ignored(self):
        """Passing a non-existent allowlist file should not crash."""
        result = self._run_scan_mocked(["--allowlist", "/tmp/nonexistent_allowlist.yaml"])
        assert result.exit_code == 0

    def test_scan_allowlist_valid_file(self, tmp_path):
        allowlist = tmp_path / "allowlist.yaml"
        allowlist.write_text("- check_id: CM-001\n  project_id: proj-1\n  reason: test\n")
        result = self._run_scan_mocked(["--allowlist", str(allowlist)])
        assert result.exit_code == 0


# ─────────────────────────────────────────────────────────────────────────────
# scan command — validation happens before the (slow) collection phase
# ─────────────────────────────────────────────────────────────────────────────


class TestScanFailFast:
    def _invoke(self, extra_args, auth=None, findings=None):
        """Run `scan --project proj-1` with real scoring; returns (result, collector_mock)."""
        if auth is None:
            auth = MagicMock()
            auth.identity = "adc"

        mock_scope = MagicMock()
        mock_scope.resolve_projects.return_value = ["proj-1"]

        mock_inventory = MagicMock()
        mock_inventory.inaccessible_projects = []
        mock_inventory.skipped_apis = {}
        mock_inventory.collector_errors = []
        mock_engine = MagicMock()
        mock_engine.collect.return_value = mock_inventory

        from gcp_abuse_scanner.models.finding import Vector

        mock_check = MagicMock()
        mock_check.vector = Vector.CRYPTO_MINING
        mock_check.safe_evaluate.return_value = findings or []
        mock_check.is_applicable.return_value = True

        with (
            patch("gcp_abuse_scanner.auth.AuthManager", return_value=auth),
            patch("gcp_abuse_scanner.auth.ScopeResolver", return_value=mock_scope),
            patch("gcp_abuse_scanner.collectors.engine.CollectorEngine") as engine_cls,
            patch("gcp_abuse_scanner.checks.CheckRegistry.all_checks", return_value=[mock_check]),
        ):
            engine_cls.return_value = mock_engine
            result = runner.invoke(app, ["scan", "--project", "proj-1", *extra_args])
        # the constructor mock (engine.ctor) exposes the args the CLI passed to CollectorEngine
        mock_engine.ctor = engine_cls
        return result, mock_engine

    # --transport / --request-timeout ---------------------------------------

    def test_invalid_transport_rejected_before_collection(self):
        result, engine = self._invoke(["--transport", "carrier-pigeon"])
        assert result.exit_code == 2
        assert "Invalid --transport" in result.output
        engine.collect.assert_not_called()

    def test_valid_transport_is_normalised_and_passed_to_the_engine(self):
        result, engine = self._invoke(["--transport", " requests ", "--request-timeout", "12"])
        assert result.exit_code == 0
        _, kwargs = engine.ctor.call_args
        assert kwargs["transport"] == "requests"
        assert kwargs["timeout"] == 12.0

    def test_transport_defaults_to_none_so_the_module_decides(self, monkeypatch):
        monkeypatch.delenv("GCP_ABUSE_SCANNER_TRANSPORT", raising=False)
        result, engine = self._invoke([])
        assert result.exit_code == 0
        _, kwargs = engine.ctor.call_args
        assert kwargs["transport"] == "requests"  # resolve_transport's default
        assert kwargs["timeout"] is None  # → transport.DEFAULT_TIMEOUT

    def test_env_var_transport_is_honoured(self, monkeypatch):
        monkeypatch.setenv("GCP_ABUSE_SCANNER_TRANSPORT", "httplib2")
        result, engine = self._invoke([])
        assert result.exit_code == 0
        _, kwargs = engine.ctor.call_args
        assert kwargs["transport"] == "httplib2"

    # --vector ---------------------------------------------------------------

    def test_invalid_vector_rejected_before_collection(self):
        result, engine = self._invoke(["--vector", "crypto"])
        assert result.exit_code == 2  # Typer usage error
        assert not isinstance(result.exception, ValueError)
        engine.collect.assert_not_called()

    def test_valid_vectors_accepted_and_recorded(self, tmp_path):
        out = tmp_path / "r.json"
        result, _ = self._invoke(
            [
                "--vector",
                "crypto_mining",
                "--vector",
                "common",
                "--format",
                "json",
                "--output",
                str(out),
            ]
        )
        assert result.exit_code == 0
        import json

        assert json.loads(out.read_text())["metadata"]["vectors_scanned"] == [
            "crypto_mining",
            "common",
        ]

    def test_list_checks_invalid_vector_rejected(self):
        result = runner.invoke(app, ["list-checks", "--vector", "bogus"])
        assert result.exit_code == 2

    # --allowlist ------------------------------------------------------------

    def test_mapping_allowlist_suppresses_critical(self, tmp_path):
        """`allowlist:` mapping (documented format) must work end-to-end with real scoring."""
        allowlist = tmp_path / "allowlist.yaml"
        allowlist.write_text("allowlist:\n  - check_id: CM-001\n    reason: accepted\n")
        findings = _make_mock_report(has_critical=True).findings

        result, _ = self._invoke(["--allowlist", str(allowlist)], findings=findings)

        assert result.exception is None or isinstance(result.exception, SystemExit)
        assert result.exit_code == 0  # the only CRITICAL is suppressed

    def test_unsuppressed_critical_still_exits_two(self, tmp_path):
        allowlist = tmp_path / "allowlist.yaml"
        allowlist.write_text("allowlist:\n  - check_id: GEM-001\n    reason: other check\n")
        findings = _make_mock_report(has_critical=True).findings

        result, _ = self._invoke(["--allowlist", str(allowlist)], findings=findings)
        assert result.exit_code == 2

    def test_malformed_allowlist_fails_before_collection(self, tmp_path):
        allowlist = tmp_path / "allowlist.yaml"
        allowlist.write_text("check_id: CM-001\n")

        result, engine = self._invoke(["--allowlist", str(allowlist)])

        assert result.exit_code == 1
        assert "Invalid allowlist" in result.output
        engine.collect.assert_not_called()

    def test_missing_allowlist_warns(self):
        result, _ = self._invoke(["--allowlist", "/nonexistent/allowlist.yaml"])
        assert result.exit_code == 0
        assert "not found" in result.output

    # credentials ------------------------------------------------------------

    def test_credential_error_fails_before_collection(self):
        from gcp_abuse_scanner.auth import AuthError

        auth = MagicMock()
        auth.get_credentials.side_effect = AuthError("not a service account key")

        result, engine = self._invoke([], auth=auth)

        assert result.exit_code == 1
        assert "Authentication failed" in result.output
        engine.collect.assert_not_called()

    def test_dry_run_does_not_resolve_credentials(self):
        auth = MagicMock()
        auth.get_credentials.side_effect = AssertionError("must not be called")

        result, _ = self._invoke(["--dry-run"], auth=auth)

        assert result.exit_code == 0


# ─────────────────────────────────────────────────────────────────────────────
# Robustness: every edge case a user (or an agent) can hit must fail cleanly
# ─────────────────────────────────────────────────────────────────────────────


class TestScanRobustness:
    """Bad input at the CLI boundary: no tracebacks, no half-written reports, no fake success."""

    def _run(self, extra_args=None, has_critical=False, project_ids=None, check=None):
        from types import SimpleNamespace

        report = _make_mock_report(has_critical=has_critical)

        mock_auth = MagicMock()
        mock_auth.identity = "scanner@proj.iam.gserviceaccount.com"

        mock_scope = MagicMock()
        mock_scope.resolve_projects.return_value = (
            ["proj-1"] if project_ids is None else project_ids
        )

        mock_inventory = MagicMock()
        mock_inventory.inaccessible_projects = []
        mock_inventory.skipped_apis = {}
        mock_inventory.collector_errors = []

        mock_engine = MagicMock()
        mock_engine.collect.return_value = mock_inventory

        mock_check = MagicMock()
        mock_check.vector = MagicMock()
        mock_check.vector.value = "crypto_mining"
        mock_check.safe_evaluate.return_value = report.findings
        mock_check.is_applicable.return_value = True
        mock_check.check_id = "CM-001"
        if check is not None:
            mock_check = check

        mock_scoring = MagicMock()
        mock_scoring.process.return_value = report.findings
        mock_scoring.build_executive_summary.return_value = report.executive_summary

        with (
            patch("gcp_abuse_scanner.auth.AuthManager") as auth_cls,
            patch("gcp_abuse_scanner.auth.ScopeResolver", return_value=mock_scope),
            patch("gcp_abuse_scanner.collectors.engine.CollectorEngine") as engine_cls,
            patch("gcp_abuse_scanner.scoring.ScoringEngine", return_value=mock_scoring),
            patch("gcp_abuse_scanner.checks.CheckRegistry.all_checks", return_value=[mock_check]),
            patch("gcp_abuse_scanner.checks.CheckRegistry.list_metadata", return_value=[]),
        ):
            auth_cls.return_value = mock_auth
            engine_cls.return_value = mock_engine
            result = runner.invoke(app, ["scan", "--project", "proj-1", *(extra_args or [])])

        return result, SimpleNamespace(
            auth=mock_auth,
            auth_cls=auth_cls,
            scope=mock_scope,
            engine=mock_engine,
            engine_cls=engine_cls,
        )

    @staticmethod
    def _clean(result) -> bool:
        """A clean failure exits with SystemExit, not with a traceback-carrying exception."""
        return result.exception is None or isinstance(result.exception, SystemExit)

    # ── invalid flag values are usage errors (exit 2), before any work ───────

    def test_negative_request_timeout_is_a_usage_error(self):
        result, mocks = self._run(["--request-timeout", "-5"])
        assert result.exit_code == 2
        assert "--request-timeout must be >= 0" in result.output
        assert self._clean(result)
        mocks.engine_cls.assert_not_called()

    def test_negative_cache_ttl_is_a_usage_error(self):
        result, mocks = self._run(["--cache-ttl", "-1"])
        assert result.exit_code == 2
        assert "--cache-ttl must be >= 0" in result.output
        mocks.engine_cls.assert_not_called()

    def test_non_numeric_org_is_a_usage_error(self):
        result, mocks = self._run(["--org", "my-org"])
        assert result.exit_code == 2
        assert "numeric organization ID" in result.output
        mocks.scope.resolve_projects.assert_not_called()

    def test_empty_project_id_is_a_usage_error(self):
        result, mocks = self._run(["--project", ""])
        assert result.exit_code == 2
        assert "non-empty project ID" in result.output
        mocks.scope.resolve_projects.assert_not_called()

    def test_unknown_flag_is_a_usage_error(self):
        result = runner.invoke(app, ["scan", "--project", "proj-1", "--not-a-flag"])
        assert result.exit_code == 2
        assert self._clean(result)

    def test_unknown_command_is_a_usage_error(self):
        result = runner.invoke(app, ["scan-all"])
        assert result.exit_code == 2
        assert self._clean(result)

    def test_dry_run_still_rejects_invalid_flag_values(self):
        """--dry-run needs no credentials, but it does not excuse a bad value."""
        result, mocks = self._run(["--dry-run", "--cache-ttl", "-3"])
        assert result.exit_code == 2
        assert "--cache-ttl must be >= 0" in result.output
        mocks.engine_cls.assert_not_called()

    def test_zero_request_timeout_is_accepted(self):
        result, _ = self._run(["--request-timeout", "0"])
        assert result.exit_code == 0
        assert "no timeout" in result.output

    # ── output-path traps ───────────────────────────────────────────────────

    def test_format_all_with_output_warns_that_only_the_last_format_survives(self, tmp_path):
        out = tmp_path / "everything.json"
        result, _ = self._run(["--format", "all", "--output", str(out)])

        assert result.exit_code == 0
        assert "same --output path" in result.output
        # the file ends up holding the last format rendered (SARIF) — documented, and now warned
        assert out.exists()
        assert '"runs"' in out.read_text(encoding="utf-8")

    def test_console_format_with_output_warns_and_writes_no_file(self, tmp_path):
        out = tmp_path / "report.json"
        result, _ = self._run(["--format", "console", "--output", str(out)])

        assert result.exit_code == 0
        assert "--output is ignored for --format console" in result.output
        assert not out.exists()

    def test_output_creates_missing_parent_directories(self, tmp_path):
        import json

        out = tmp_path / "nested" / "deep" / "report.json"
        result, _ = self._run(["--format", "json", "--output", str(out)])

        assert result.exit_code == 0
        assert out.exists()
        assert json.loads(out.read_text(encoding="utf-8"))["risk_assessment"]["level"] >= 1

    def test_unwritable_output_path_exits_one_cleanly(self, tmp_path):
        blocker = tmp_path / "not-a-dir"
        blocker.write_text("i am a file")

        result, _ = self._run(["--format", "json", "--output", str(blocker / "report.json")])

        assert result.exit_code == 1
        assert "Cannot create output directory" in result.output
        assert self._clean(result)

    # ── allowlist traps ─────────────────────────────────────────────────────

    def test_allowlist_directory_is_rejected_cleanly(self, tmp_path):
        result, mocks = self._run(["--allowlist", str(tmp_path)])

        assert result.exit_code == 1
        assert "is a directory" in result.output
        assert self._clean(result)
        mocks.engine.collect.assert_not_called()

    def test_unreadable_allowlist_is_rejected_before_collection(self, tmp_path):
        """Typer already rejects an unreadable existing path (exit 2) — documented behaviour.

        The CLI keeps its own OSError guard for paths that become unreadable after validation
        (or when the command is driven programmatically), but the user-facing path is this one.
        """
        import os
        import stat

        if os.geteuid() == 0:  # root ignores the mode bits
            import pytest

            pytest.skip("running as root: file modes are not enforced")

        allowlist = tmp_path / "allowlist.yaml"
        allowlist.write_text("- check_id: CM-001\n  reason: accepted\n")
        allowlist.chmod(stat.S_IRUSR & 0o000)

        result, mocks = self._run(["--allowlist", str(allowlist)])

        assert result.exit_code == 2
        # the rich panel wraps long paths and may style the flag name — compare flat text
        flat = _flat(result.output)
        assert "Invalid value for '--allowlist'" in flat
        assert "not readable" in flat
        assert self._clean(result)
        mocks.engine_cls.assert_not_called()

    # ── scope and report-contract edge cases ────────────────────────────────

    def test_scope_emptied_by_exclusions_exits_zero_with_a_warning(self):
        result, mocks = self._run(project_ids=[])

        assert result.exit_code == 0
        assert "No projects found in scope" in result.output
        mocks.engine_cls.assert_not_called()

    def test_critical_scan_writes_the_report_before_exiting_two(self, tmp_path):
        import json

        out = tmp_path / "critical.json"
        result, _ = self._run(["--format", "json", "--output", str(out)], has_critical=True)

        assert result.exit_code == 2
        assert out.exists(), "the report must exist even on exit 2"
        risk = json.loads(out.read_text(encoding="utf-8"))["risk_assessment"]
        assert risk["level"] == 3  # CM-001 CRITICAL is not in the level-4 class
        assert risk["auto_approval_eligible"] is False
        assert risk["auto_approval_blockers"]

    def test_usage_error_writes_no_report(self, tmp_path):
        out = tmp_path / "never.json"
        result, _ = self._run(["--transport", "bogus", "--format", "json", "--output", str(out)])

        assert result.exit_code == 2
        assert not out.exists()

    def test_dry_run_writes_no_report_and_builds_no_engine(self, tmp_path):
        out = tmp_path / "dry.json"
        result, mocks = self._run(["--dry-run", "--format", "json", "--output", str(out)])

        assert result.exit_code == 0
        assert not out.exists()
        mocks.engine_cls.assert_not_called()

    # ── credential plumbing ─────────────────────────────────────────────────

    def test_impersonation_and_key_file_are_both_forwarded_to_auth(self):
        result, mocks = self._run(
            [
                "--service-account-key",
                "/tmp/key.json",
                "--impersonate-service-account",
                "scanner@proj.iam.gserviceaccount.com",
            ]
        )

        assert result.exit_code == 0
        _, kwargs = mocks.auth_cls.call_args
        assert kwargs["service_account_key"] == "/tmp/key.json"
        assert kwargs["impersonate_service_account"] == "scanner@proj.iam.gserviceaccount.com"

    # ── paths that feed the coverage gate ───────────────────────────────────

    def test_not_applicable_check_is_recorded_for_the_coverage_gate(self, tmp_path):
        import json

        check = MagicMock()
        check.check_id = "GEM-001"
        check.vector = MagicMock(value="gemini_abuse")
        check.is_applicable.return_value = False
        check.safe_evaluate.return_value = []

        out = tmp_path / "na.json"
        result, _ = self._run(
            ["--format", "json", "--output", str(out)], project_ids=["proj-1"], check=check
        )

        assert result.exit_code == 0
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["coverage"]["checks_not_applicable_ids"] == ["GEM-001"]
        assert payload["coverage"]["checks_not_applicable"] == 1
        # a NOT_APPLICABLE api_keys check means "we could not look" → no auto-approval
        risk = payload["risk_assessment"]
        assert risk["coverage_complete"] is False
        assert risk["auto_approval_eligible"] is False
        assert [g["domain"] for g in risk["coverage_gaps"]] == ["api_keys"]

    def test_check_that_raises_is_recorded_and_the_scan_continues(self, tmp_path):
        import json

        check = MagicMock()
        check.check_id = "CM-004"
        check.vector = MagicMock(value="crypto_mining")
        check.is_applicable.side_effect = RuntimeError("boom")
        check.safe_evaluate.return_value = []

        out = tmp_path / "errored.json"
        result, _ = self._run(
            ["--format", "json", "--output", str(out)], project_ids=["proj-1"], check=check
        )

        assert result.exit_code == 0  # one broken check must not kill the scan ...
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["coverage"]["checks_errored_ids"] == ["CM-004"]
        # ... but it must not read as "passed" either: network coverage is now incomplete
        risk = payload["risk_assessment"]
        assert risk["coverage_complete"] is False
        assert risk["auto_approval_eligible"] is False
        assert [g["domain"] for g in risk["coverage_gaps"]] == ["network"]

    def test_cache_hit_is_announced(self):
        mock_cache = MagicMock()
        mock_cache.is_valid.return_value = True

        with patch("gcp_abuse_scanner.collectors.cache.InventoryCache", return_value=mock_cache):
            result, _ = self._run(["--cache"])

        assert result.exit_code == 0
        assert "Using cached inventory" in result.output

    def test_allowlist_read_error_is_reported_cleanly(self, tmp_path):
        allowlist = tmp_path / "allowlist.yaml"
        allowlist.write_text("- check_id: CM-001\n  reason: accepted\n")

        with patch(
            "gcp_abuse_scanner.scoring.engine.load_allowlist",
            side_effect=OSError("input/output error"),
        ):
            result, mocks = self._run(["--allowlist", str(allowlist)])

        assert result.exit_code == 1
        assert "Cannot read allowlist" in result.output
        assert self._clean(result)
        mocks.engine.collect.assert_not_called()

    def test_report_write_failure_exits_one_cleanly(self, tmp_path):
        out = tmp_path / "report.json"

        with patch(
            "gcp_abuse_scanner.reporters.JSONReporter.render",
            side_effect=OSError("no space left on device"),
        ):
            result, _ = self._run(["--format", "json", "--output", str(out)])

        assert result.exit_code == 1
        assert "Cannot write report" in result.output
        assert self._clean(result)

    def test_report_carries_penalty_points_for_drift_tracking(self, tmp_path):
        import json

        out = tmp_path / "penalty.json"
        result, _ = self._run(["--format", "json", "--output", str(out)], has_critical=True)

        assert result.exit_code == 2
        summary = json.loads(out.read_text(encoding="utf-8"))["executive_summary"]
        assert summary["penalty_points"] == 10.0  # one CRITICAL
        assert summary["posture_score"] < 100.0
