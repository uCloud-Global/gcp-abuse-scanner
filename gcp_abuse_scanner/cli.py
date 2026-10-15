"""
gcp-abuse-scanner CLI

Entry point for the GCP security scanner.

Usage:
    gcp-abuse-scanner scan --org 123456789 --format html --output report.html
    gcp-abuse-scanner scan --project my-project-id --format json
    gcp-abuse-scanner list-checks
    gcp-abuse-scanner version
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

if TYPE_CHECKING:
    from gcp_abuse_scanner.models.report import ScanReport

import typer
from rich.console import Console
from rich.logging import RichHandler

from gcp_abuse_scanner.models.finding import Vector

app = typer.Typer(
    name="gcp-abuse-scanner",
    help=(
        "Preventive GCP security scanner for crypto mining and Gemini API abuse vectors. "
        "Read-only — never modifies resources."
    ),
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()
err_console = Console(stderr=True)


class OutputFormat(str, Enum):
    console = "console"
    json = "json"
    markdown = "markdown"
    html = "html"
    sarif = "sarif"
    all = "all"


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    )
    # Suppress noisy internal loggers from google-api-python-client.
    # These emit "Encountered 403 Forbidden" etc. before our collectors
    # log the same error with proper context (project_id, collector name).
    for _noisy in (
        "googleapiclient.discovery",
        "googleapiclient.discovery_cache",
        "googleapiclient.http",
        "google.auth.transport.requests",
        "google.auth._default",
        "urllib3.connectionpool",
    ):
        logging.getLogger(_noisy).setLevel(logging.ERROR if verbose else logging.CRITICAL)


@app.command()
def scan(
    org: Annotated[
        str | None,
        typer.Option("--org", "-o", help="GCP Organization ID (digits only). Scans all projects."),
    ] = None,
    project: Annotated[
        list[str] | None,
        typer.Option("--project", "-p", help="GCP Project ID. Repeatable for multiple projects."),
    ] = None,
    exclude_project: Annotated[
        list[str] | None,
        typer.Option("--exclude-project", help="Project IDs to exclude from scan."),
    ] = None,
    service_account_key: Annotated[
        str | None,
        typer.Option(
            "--service-account-key",
            envvar="GOOGLE_APPLICATION_CREDENTIALS",
            help="Path to service account JSON key file.",
        ),
    ] = None,
    impersonate_service_account: Annotated[
        str | None,
        typer.Option(
            "--impersonate-service-account",
            help="Service account email to impersonate (recommended over key files).",
        ),
    ] = None,
    format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format."),
    ] = OutputFormat.console,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Output file path (default: stdout / auto-named)."),
    ] = None,
    vector: Annotated[
        list[Vector] | None,
        typer.Option(
            "--vector",
            help="Limit scan to specific vectors. Repeatable.",
        ),
    ] = None,
    allowlist_file: Annotated[
        Path | None,
        typer.Option("--allowlist", help="YAML file with suppression rules."),
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable debug logging.")] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Resolve scope and list checks without executing them."),
    ] = False,
    use_cache: Annotated[
        bool,
        typer.Option(
            "--cache/--no-cache", help="Cache inventory to disk (TTL 1h). Speeds up re-runs."
        ),
    ] = False,
    cache_ttl: Annotated[
        int,
        typer.Option("--cache-ttl", help="Cache TTL in seconds (default: 3600)."),
    ] = 3600,
    transport: Annotated[
        str | None,
        typer.Option(
            "--transport",
            help=(
                "HTTP transport for the discovery-based collectors: 'requests' (default) or "
                "'httplib2' (legacy). Overrides GCP_ABUSE_SCANNER_TRANSPORT."
            ),
        ),
    ] = None,
    request_timeout: Annotated[
        float | None,
        typer.Option(
            "--request-timeout",
            help="Timeout in seconds for each GCP API request (0 = no timeout, default: 30).",
        ),
    ] = None,
) -> None:
    """
    Scan a GCP organization or project(s) for security misconfigurations.

    Requires a service account with read-only roles (see docs/iam-setup.md).
    Never modifies any GCP resources.
    """
    _setup_logging(verbose)

    if not org and not project:
        err_console.print(
            "[red]Error:[/] Provide --org ORG_ID or at least one --project PROJECT_ID"
        )
        raise typer.Exit(code=1)

    # ── Usage validation, before any credentials, network I/O or cost ─────────
    # A bad value here would otherwise surface as a cryptic downstream failure (or, worse,
    # as a scan that "succeeds" while every collector records a coverage gap).
    def _usage_error(message: str) -> None:
        err_console.print(f"[red]Error:[/] {message}")
        raise typer.Exit(code=2)

    if org is not None and not org.strip().isdigit():
        _usage_error(f"--org must be a numeric organization ID (digits only), got {org!r}")

    project_ids_input = [p.strip() for p in (project or [])]
    if any(not p for p in project_ids_input):
        _usage_error("--project requires a non-empty project ID")

    if request_timeout is not None and request_timeout < 0:
        _usage_error(f"--request-timeout must be >= 0 (0 = no timeout), got {request_timeout:g}")

    if cache_ttl < 0:
        _usage_error(f"--cache-ttl must be >= 0, got {cache_ttl}")

    if format == OutputFormat.all and output is not None:
        err_console.print(
            "[yellow]Warning:[/] --format all writes every format to the same --output path "
            "(only the last one survives). Use --format all without --output, or run once per format."
        )
    if format == OutputFormat.console and output is not None:
        err_console.print(
            "[yellow]Warning:[/] --output is ignored for --format console (output goes to stdout). "
            "Use --format json|markdown|html|sarif to write a file."
        )

    # Lazy imports to keep startup fast
    from gcp_abuse_scanner.auth import AuthManager, ScopeResolver
    from gcp_abuse_scanner.checks import CheckRegistry
    from gcp_abuse_scanner.models.report import CoverageReport, ScanMetadata, ScanReport
    from gcp_abuse_scanner.scoring import ScoringEngine
    from gcp_abuse_scanner.scoring.risk import assess_risk

    # Validate the transport name before any other work: an unknown value would make every
    # discovery client fail, be recorded as a coverage gap, and exit 0 with an empty report.
    from gcp_abuse_scanner.utils.transport import resolve_transport

    try:
        selected_transport = resolve_transport(transport)
    except ValueError as exc:
        err_console.print(f"[red]Invalid --transport:[/] {exc}")
        raise typer.Exit(code=2)

    scan_id = str(uuid.uuid4())
    started_at = datetime.now(UTC)

    console.print(f"[cyan]Starting scan[/] (id: [dim]{scan_id}[/])")

    # Auth
    auth = AuthManager(
        service_account_key=service_account_key,
        impersonate_service_account=impersonate_service_account,
    )

    # Scope resolution
    scope_resolver = ScopeResolver(auth)
    try:
        project_ids = scope_resolver.resolve_projects(
            organization_id=org,
            project_ids=list(project_ids_input),
            exclude_project_ids=list(exclude_project or []),
        )
    except Exception as exc:
        err_console.print(f"[red]Scope resolution failed:[/] {exc}")
        raise typer.Exit(code=1)

    if not project_ids:
        err_console.print("[yellow]Warning:[/] No projects found in scope. Exiting.")
        raise typer.Exit(code=0)

    console.print(f"[green]Scope resolved:[/] {len(project_ids)} project(s)")
    _timeout_label = "no timeout" if request_timeout == 0 else f"{request_timeout or 30:g}s"
    console.print(f"[dim]Transport: {selected_transport} (timeout {_timeout_label})[/]")

    if dry_run:
        console.print("[yellow]Dry run — listing checks only:[/]")
        for meta in CheckRegistry.list_metadata():
            console.print(f"  [{meta['severity']}] {meta['check_id']} — {meta['title']}")
        raise typer.Exit(code=0)

    # Fail fast on credentials that cannot be loaded (e.g. a malformed key file),
    # instead of letting every collector fail and producing an empty report.
    try:
        auth.get_credentials()
    except Exception as exc:
        err_console.print(f"[red]Authentication failed:[/] {exc}")
        raise typer.Exit(code=1)

    # Load allowlist (validated before the slow collection phase)
    allowlist: list[dict] = []
    if allowlist_file:
        if allowlist_file.is_dir():
            err_console.print(
                f"[red]Invalid allowlist:[/] {allowlist_file} is a directory, expected a YAML file."
            )
            raise typer.Exit(code=1)
        if allowlist_file.exists():
            from gcp_abuse_scanner.scoring.engine import load_allowlist

            try:
                allowlist = load_allowlist(allowlist_file)
            except ValueError as exc:
                err_console.print(f"[red]Invalid allowlist {allowlist_file}:[/] {exc}")
                raise typer.Exit(code=1)
            except OSError as exc:
                err_console.print(f"[red]Cannot read allowlist {allowlist_file}:[/] {exc}")
                raise typer.Exit(code=1)
        else:
            err_console.print(
                f"[yellow]Warning:[/] allowlist file {allowlist_file} not found — ignoring."
            )

    # Collect inventory (with optional cache)
    console.print("[cyan]Collecting resource inventory...[/]")
    from gcp_abuse_scanner.collectors.cache import InventoryCache
    from gcp_abuse_scanner.collectors.engine import CollectorEngine

    cache = InventoryCache(ttl_seconds=cache_ttl) if use_cache else None
    if cache and cache.is_valid(project_ids, org):
        console.print("[dim]Using cached inventory (--cache)[/]")
    collector_engine = CollectorEngine(
        auth_manager=auth,
        cache=cache,
        timeout=request_timeout,
        transport=selected_transport,
    )
    inventory = collector_engine.collect(project_ids=project_ids, organization_id=org)

    # Run checks
    console.print("[cyan]Running security checks...[/]")
    checks = CheckRegistry.all_checks()

    # Filter by vector if specified
    if vector:
        allowed_vectors = set(vector)
        checks = [c for c in checks if c.vector in allowed_vectors]

    all_findings = []
    checks_executed = checks_passed = checks_failed = checks_na = checks_errored = 0
    not_applicable_ids: list[str] = []
    errored_ids: list[str] = []

    for check in checks:
        checks_executed += 1
        try:
            findings = check.safe_evaluate(inventory)
            if not check.is_applicable(inventory):
                checks_na += 1
                not_applicable_ids.append(check.check_id)
            elif findings:
                checks_failed += 1
                all_findings.extend(findings)
            else:
                checks_passed += 1
        except Exception:
            checks_errored += 1
            errored_ids.append(check.check_id)

    # Score and prioritize
    scoring = ScoringEngine(allowlist=allowlist)
    all_findings = scoring.process(all_findings)
    executive_summary = scoring.build_executive_summary(all_findings, max_projects=len(project_ids))

    finished_at = datetime.now(UTC)
    duration = (finished_at - started_at).total_seconds()

    # Build report
    metadata = ScanMetadata(
        scan_id=scan_id,
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=duration,
        scope_type="organization" if org else "project_list",
        organization_id=org,
        project_ids=project_ids,
        service_account=auth.identity,
        vectors_scanned=[v.value for v in (vector or list(Vector))],
    )

    coverage = CoverageReport(
        projects_scanned=len(project_ids),
        projects_inaccessible=len(inventory.inaccessible_projects),
        inaccessible_project_ids=inventory.inaccessible_projects,
        checks_executed=checks_executed,
        checks_passed=checks_passed,
        checks_failed=checks_failed,
        checks_not_applicable=checks_na,
        checks_errored=checks_errored,
        checks_not_applicable_ids=not_applicable_ids,
        checks_errored_ids=errored_ids,
        skipped_apis_by_project=inventory.skipped_apis,
        unreadable_budget_accounts=inventory.budgets_unreadable,
        collector_errors=inventory.collector_errors,
    )

    risk_assessment = assess_risk(all_findings, coverage)

    report = ScanReport(
        metadata=metadata,
        executive_summary=executive_summary,
        coverage=coverage,
        findings=all_findings,
        risk_assessment=risk_assessment,
    )

    # Output
    _write_output(report, format, output)

    # Risk level (SOP 1–4) and the coverage gate — see docs/risk-model.md
    console.print(
        f"\n[bold]Risk level: {risk_assessment.level}/4 ({risk_assessment.label})[/] — "
        + (
            "[green]coverage complete, auto-approval eligible[/]"
            if risk_assessment.auto_approval_eligible
            else "[yellow]not auto-approvable[/]"
        )
    )
    if risk_assessment.auto_approval_blockers:
        for blocker in risk_assessment.auto_approval_blockers:
            console.print(f"  [yellow]•[/] {blocker}")

    # Exit code: non-zero if CRITICAL findings
    critical_count = executive_summary.by_severity.critical
    if critical_count > 0:
        console.print(
            f"\n[bold red]⚠️  {critical_count} CRITICAL finding(s) require immediate attention.[/]"
        )
        raise typer.Exit(code=2)


def _write_output(report: ScanReport, format: OutputFormat, output: Path | None) -> None:

    scan_prefix = f"gcp-scan-{report.metadata.scan_id[:8]}"

    if output is not None:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            err_console.print(f"[red]Cannot create output directory {output.parent}:[/] {exc}")
            raise typer.Exit(code=1)

    formats_to_render: list[OutputFormat] = (
        [
            OutputFormat.console,
            OutputFormat.json,
            OutputFormat.markdown,
            OutputFormat.html,
            OutputFormat.sarif,
        ]
        if format == OutputFormat.all
        else [format]
    )

    try:
        _render_formats(report, formats_to_render, output, scan_prefix)
    except OSError as exc:
        err_console.print(f"[red]Cannot write report to {output}:[/] {exc}")
        raise typer.Exit(code=1)


def _render_formats(
    report: ScanReport,
    formats_to_render: list[OutputFormat],
    output: Path | None,
    scan_prefix: str,
) -> None:
    from gcp_abuse_scanner.reporters import (
        ConsoleReporter,
        HTMLReporter,
        JSONReporter,
        MarkdownReporter,
        SARIFReporter,
    )

    for fmt in formats_to_render:
        if fmt == OutputFormat.console:
            ConsoleReporter(verbose=False).render(report)
        elif fmt == OutputFormat.json:
            path = output or Path(f"{scan_prefix}.json")
            JSONReporter(output_path=path).render(report)
            console.print(f"[green]JSON report:[/] {path}")
        elif fmt == OutputFormat.markdown:
            path = output or Path(f"{scan_prefix}.md")
            MarkdownReporter(output_path=path).render(report)
            console.print(f"[green]Markdown report:[/] {path}")
        elif fmt == OutputFormat.html:
            path = output or Path(f"{scan_prefix}.html")
            HTMLReporter(output_path=path).render(report)
            console.print(f"[green]HTML report:[/] {path}")
        elif fmt == OutputFormat.sarif:
            path = output or Path(f"{scan_prefix}.sarif")
            SARIFReporter(output_path=path).render(report)
            console.print(f"[green]SARIF report:[/] {path}")


@app.command(name="list-checks")
def list_checks(
    vector: Annotated[
        Vector | None,
        typer.Option("--vector", help="Filter by vector."),
    ] = None,
) -> None:
    """List all available security checks."""
    from rich import box
    from rich.table import Table

    from gcp_abuse_scanner.checks import CheckRegistry

    checks = CheckRegistry.list_metadata()
    if vector:
        checks = [c for c in checks if c["vector"] == vector.value]

    table = Table(title="Available Security Checks", box=box.ROUNDED)
    table.add_column("ID", style="bold cyan", width=10)
    table.add_column("Vector", width=14)
    table.add_column("Severity", width=10)
    table.add_column("Title", width=55)
    table.add_column("Required APIs", width=35)

    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
    }

    for check in sorted(checks, key=lambda c: c["check_id"]):
        sev = check["severity"]
        table.add_row(
            check["check_id"],
            check["vector"],
            f"[{severity_colors.get(sev, 'white')}]{sev}[/]",
            check["title"],
            check["required_apis"] or "—",
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(checks)} checks[/]")


@app.command()
def version() -> None:
    """Show version information."""
    from gcp_abuse_scanner import __version__

    console.print(f"gcp-abuse-scanner v{__version__}")


if __name__ == "__main__":
    app()
