"""Console reporter — rich terminal output."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from gcp_abuse_scanner.models.finding import Severity
from gcp_abuse_scanner.models.report import ScanReport

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


class ConsoleReporter:
    def __init__(self, verbose: bool = False) -> None:
        self._console = Console()
        self._verbose = verbose

    def render(self, report: ScanReport) -> None:
        self._render_header(report)
        self._render_executive_summary(report)
        self._render_risk(report)
        self._render_coverage(report)
        self._render_findings_table(report)
        self._render_remediation_plan(report)

    def _render_header(self, report: ScanReport) -> None:
        meta = report.metadata
        self._console.print()
        self._console.print(
            Panel(
                (
                    f"[bold cyan]gcp-abuse-scanner[/] v{meta.tool_version}\n"
                    f"Scan ID: [dim]{meta.scan_id}[/]\n"
                    f"Scope: [bold]{meta.scope_type}[/] — "
                    f"{'org ' + meta.organization_id if meta.organization_id else ', '.join(meta.project_ids[:3]) + ('...' if len(meta.project_ids) > 3 else '')}\n"
                    f"Identity: [dim]{meta.service_account or 'ADC'}[/]\n"
                    f"Duration: {meta.duration_seconds:.1f}s"
                    if meta.duration_seconds
                    else ""
                ),
                title="[bold]GCP Security Scan Report[/]",
                border_style="cyan",
            )
        )

    def _render_executive_summary(self, report: ScanReport) -> None:
        summary = report.executive_summary
        score = summary.posture_score
        score_color = "green" if score >= 80 else "yellow" if score >= 50 else "red"

        self._console.print(
            Panel(
                f"Posture Score: [{score_color}]{score}/100[/]  "
                f"[dim](penalty {summary.penalty_points:g} pts — scope-normalized)[/]\n"
                f"Total Findings: [bold]{summary.total_findings}[/]\n\n"
                f"  {_SEVERITY_ICONS[Severity.CRITICAL]} CRITICAL: [bold red]{summary.by_severity.critical}[/]   "
                f"{_SEVERITY_ICONS[Severity.HIGH]} HIGH: [red]{summary.by_severity.high}[/]   "
                f"{_SEVERITY_ICONS[Severity.MEDIUM]} MEDIUM: [yellow]{summary.by_severity.medium}[/]   "
                f"{_SEVERITY_ICONS[Severity.LOW]} LOW: [cyan]{summary.by_severity.low}[/]",
                title="[bold]Executive Summary[/]",
                border_style="blue",
            )
        )

    def _render_risk(self, report: ScanReport) -> None:
        """Render the SOP risk level (1–4) and the coverage gate."""
        risk = report.risk_assessment
        if risk is None:
            return
        colors = {1: "green", 2: "yellow", 3: "red", 4: "bold red"}
        color = colors.get(risk.level, "white")
        gate = (
            "[green]coverage complete — auto-approval eligible[/]"
            if risk.auto_approval_eligible
            else "[yellow]not auto-approvable[/]"
        )
        block = (
            f"Risk Level: [{color}]{risk.level}/4 ({risk.label})[/]\n"
            f"Coverage: {'[green]complete[/]' if risk.coverage_complete else f'[yellow]{len(risk.coverage_gaps)} gap(s)[/]'}"
            f" — {gate}\n"
            f"[dim]{risk.rationale}[/]"
        )
        if risk.auto_approval_blockers:
            block += "\n" + "\n".join(f"  [yellow]•[/] {b}" for b in risk.auto_approval_blockers)
        self._console.print(Panel(block, title="[bold]Risk Assessment[/]", border_style=color))

    def _render_coverage(self, report: ScanReport) -> None:
        cov = report.coverage
        self._console.print(
            f"[dim]Coverage: {cov.projects_scanned} projects scanned"
            + (f", {cov.projects_inaccessible} inaccessible" if cov.projects_inaccessible else "")
            + f" | Checks: {cov.checks_executed} executed, {cov.checks_failed} failed, "
            f"{cov.checks_not_applicable} N/A[/]"
        )
        self._console.print()

    def _render_findings_table(self, report: ScanReport) -> None:
        findings = report.prioritized_findings()
        if not findings:
            self._console.print("[green]✅ No findings — all checks passed![/]")
            return

        table = Table(
            title=f"Findings ({len(findings)} total)",
            box=box.ROUNDED,
            show_lines=True,
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Severity", width=10)
        table.add_column("Check", width=10)
        table.add_column("Title", width=45)
        table.add_column("Project", width=25)
        table.add_column("Vector", width=14)

        for finding in findings:
            sev_color = _SEVERITY_COLORS.get(finding.severity, "white")
            table.add_row(
                str(finding.priority_rank),
                Text(
                    f"{_SEVERITY_ICONS[finding.severity]} {finding.severity.value}",
                    style=sev_color,
                ),
                finding.check_id,
                finding.title[:44],
                finding.resource.project_id or "—",
                finding.vector.value.replace("_", " "),
            )

        self._console.print(table)

    def _render_remediation_plan(self, report: ScanReport) -> None:
        findings = [
            f
            for f in report.prioritized_findings()
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        if not findings:
            return

        self._console.print()
        self._console.print("[bold]🔧 Priority Remediation Plan (CRITICAL & HIGH)[/]")
        self._console.print()

        for finding in findings[:10]:
            sev_color = _SEVERITY_COLORS.get(finding.severity, "white")
            self._console.print(
                f"[{sev_color}][{finding.priority_rank}] {finding.check_id} — {finding.title}[/]"
            )
            self._console.print(f"    Project: {finding.resource.project_id}")
            self._console.print(f"    → {finding.remediation.summary}")
            if self._verbose and finding.remediation.steps:
                for i, step in enumerate(finding.remediation.steps, 1):
                    self._console.print(f"       {i}. {step}")
            self._console.print()
