"""Markdown reporter — for PRs, tickets, and documentation."""

from __future__ import annotations

from pathlib import Path

from gcp_abuse_scanner.models.finding import Severity
from gcp_abuse_scanner.models.report import ScanReport

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


class MarkdownReporter:
    def __init__(self, output_path: str | Path | None = None) -> None:
        self._output_path = Path(output_path) if output_path else None

    def render(self, report: ScanReport) -> str:
        lines: list[str] = []
        meta = report.metadata
        summary = report.executive_summary
        cov = report.coverage

        # Header
        lines += [
            "# GCP Security Scan Report",
            "",
            f"**Tool**: `gcp-abuse-scanner` v{meta.tool_version}  ",
            f"**Scan ID**: `{meta.scan_id}`  ",
            f"**Scope**: {meta.scope_type} — "
            + (
                f"org `{meta.organization_id}`"
                if meta.organization_id
                else ", ".join(f"`{p}`" for p in meta.project_ids[:5])
            ),
            f"**Identity**: `{meta.service_account or 'ADC'}`  ",
            f"**Duration**: {meta.duration_seconds:.1f}s" if meta.duration_seconds else "",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Posture Score | **{summary.posture_score}/100** (normalized by project count) |",
            f"| Penalty points | {summary.penalty_points:g} (scope-independent — use this to compare two scans) |",
            f"| Total Findings | {summary.total_findings} |",
            f"| 🔴 CRITICAL | {summary.by_severity.critical} |",
            f"| 🟠 HIGH | {summary.by_severity.high} |",
            f"| 🟡 MEDIUM | {summary.by_severity.medium} |",
            f"| 🔵 LOW | {summary.by_severity.low} |",
            "",
            "---",
            "",
            "## Coverage",
            "",
            f"- Projects scanned: **{cov.projects_scanned}**",
            f"- Projects inaccessible: {cov.projects_inaccessible}",
            f"- Checks executed: {cov.checks_executed} | Failed: {cov.checks_failed} | N/A: {cov.checks_not_applicable}",
            "",
        ]

        if cov.inaccessible_project_ids:
            lines += [
                "### Inaccessible Projects",
                "",
                "The scanner could not access the following projects (check SA permissions):",
                "",
            ]
            for pid in cov.inaccessible_project_ids:
                lines.append(f"- `{pid}`")
            lines.append("")

        # Risk assessment (SOP 1–4 + coverage gate)
        risk = report.risk_assessment
        if risk is not None:
            lines += [
                "---",
                "",
                "## Risk Assessment",
                "",
                "| Field | Value |",
                "|-------|-------|",
                f"| SOP Risk Level | **{risk.level}/4 — {risk.label}** |",
                f"| Coverage | {'✅ complete' if risk.coverage_complete else f'⚠️ {len(risk.coverage_gaps)} gap(s)'} |",
                f"| Auto-approval | {'✅ eligible' if risk.auto_approval_eligible else '❌ blocked'} |",
                "",
                risk.rationale,
                "",
            ]
            if risk.auto_approval_blockers:
                lines += ["**Blockers:**", ""]
                lines += [f"- {b}" for b in risk.auto_approval_blockers]
                lines.append("")
            if risk.coverage_gaps:
                lines += [
                    "| Domain | Reason | Projects |",
                    "|--------|--------|----------|",
                ]
                for gap in risk.coverage_gaps:
                    projects = ", ".join(f"`{p}`" for p in gap.projects) or "—"
                    lines.append(f"| `{gap.domain}` | {gap.reason} | {projects} |")
                lines.append("")

        # Findings
        lines += [
            "---",
            "",
            "## Findings",
            "",
        ]

        findings = report.prioritized_findings()
        if not findings:
            lines.append("✅ **No findings — all checks passed!**")
        else:
            lines += [
                "| # | Severity | Check | Title | Project | Vector |",
                "|---|----------|-------|-------|---------|--------|",
            ]
            for f in findings:
                icon = _SEVERITY_EMOJI.get(f.severity, "")
                lines.append(
                    f"| {f.priority_rank} | {icon} {f.severity.value} | `{f.check_id}` | "
                    f"{f.title} | `{f.resource.project_id}` | {f.vector.value} |"
                )

        lines += ["", "---", "", "## Remediation Plan", ""]

        for f in findings:
            icon = _SEVERITY_EMOJI.get(f.severity, "")
            lines += [
                f"### [{f.priority_rank}] {icon} `{f.check_id}` — {f.title}",
                "",
                f"**Severity**: {f.severity.value} | **Project**: `{f.resource.project_id}` | "
                f"**Effort**: {f.remediation.effort.value}",
                "",
                f"**Description**: {f.description}",
                "",
                f"**Impact**: {f.impact}",
                "",
                f"**Remediation**: {f.remediation.summary}",
                "",
            ]
            if f.remediation.steps:
                for i, step in enumerate(f.remediation.steps, 1):
                    lines.append(f"{i}. {step}")
                lines.append("")
            if f.remediation.gcloud_commands:
                lines += ["**Commands**:", "```bash"]
                for cmd in f.remediation.gcloud_commands:
                    lines.append(cmd)
                lines += ["```", ""]
            if f.remediation.docs:
                lines.append("**References**:")
                for doc in f.remediation.docs:
                    lines.append(f"- {doc}")
                lines.append("")
            lines.append("---")
            lines.append("")

        output = "\n".join(lines)
        if self._output_path:
            self._output_path.write_text(output, encoding="utf-8")
        return output
