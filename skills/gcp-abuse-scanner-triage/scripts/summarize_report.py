#!/usr/bin/env python3
"""Compact, token-efficient summary of a gcp-abuse-scanner JSON report.

Usage:
    python summarize_report.py REPORT.json [--top N] [--severity CRITICAL,HIGH]
                               [--project ID] [--check CM-004] [--remediation] [--json]

Default output: scope, SOP risk level (1–4) + coverage gate, posture, severity counts, coverage gaps,
findings grouped by check (count + affected projects), and the top-N findings by priority_rank.
--remediation adds steps and gcloud commands to the top-N list (these commands MODIFY
resources — present them to a human, never run them unattended).
--json emits the same summary as JSON for further processing.

The risk level and `auto_approval_eligible` come straight from the report's `risk_assessment`
(see docs/risk-model.md). Do not re-derive the level from severity counts: coverage gaps also
have to block approval, and this script reports them.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def load(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"Cannot read report {path}: {exc}")
    if not {"metadata", "executive_summary", "coverage", "findings"} <= data.keys():
        sys.exit(f"{path} is not a gcp-abuse-scanner JSON report (use --format json)")
    return data


def build(data: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    severities = {s.strip().upper() for s in args.severity.split(",")} if args.severity else None
    findings = [
        f
        for f in data["findings"]
        if not f.get("suppressed")
        and (severities is None or f["severity"] in severities)
        and (args.project is None or f["resource"]["project_id"] == args.project)
        and (args.check is None or f["check_id"] == args.check.upper())
    ]
    findings.sort(key=lambda f: (f.get("priority_rank") or 10**9, SEV_ORDER.get(f["severity"], 9)))

    by_check: dict[str, dict[str, Any]] = {}
    for f in findings:
        entry = by_check.setdefault(
            f["check_id"],
            {"severity": f["severity"], "title": f["title"], "count": 0, "projects": set()},
        )
        entry["count"] += 1
        entry["projects"].add(f["resource"]["project_id"] or "<org/billing>")

    cov = data["coverage"]
    meta = data["metadata"]
    es = data["executive_summary"]
    top = []
    for f in findings[: args.top]:
        item = {
            "rank": f.get("priority_rank"),
            "check_id": f["check_id"],
            "severity": f["severity"],
            "project_id": f["resource"]["project_id"],
            "resource_id": f["resource"]["resource_id"],
            "fix": f["remediation"]["summary"],
            "effort": f["remediation"].get("effort"),
        }
        if args.remediation:
            item["steps"] = f["remediation"].get("steps", [])
            item["gcloud_commands"] = f["remediation"].get("gcloud_commands", [])
            item["iac_reference"] = f["remediation"].get("iac_reference")
        top.append(item)

    return {
        "scan": {
            "scan_id": meta["scan_id"],
            "finished_at": meta.get("finished_at"),
            "scope": meta.get("organization_id") or meta.get("project_ids"),
            "vectors": meta.get("vectors_scanned"),
            "identity": meta.get("service_account"),
        },
        "risk": _risk(data.get("risk_assessment")),
        "posture_score": es["posture_score"],
        "penalty_points": es.get("penalty_points"),
        "by_severity": {k: v for k, v in es["by_severity"].items() if k != "total" and v},
        "active_findings": es["total_findings"],
        "suppressed_findings": sum(1 for f in data["findings"] if f.get("suppressed")),
        "coverage": {
            "projects_scanned": cov["projects_scanned"],
            "inaccessible_projects": cov["inaccessible_project_ids"],
            "checks": {
                k.removeprefix("checks_"): v for k, v in cov.items() if k.startswith("checks_")
            },
            "skipped_apis_by_project": cov["skipped_apis_by_project"],
            "collector_errors": cov["collector_errors"],
        },
        "filtered_findings": len(findings),
        "by_check": [
            {"check_id": cid, **{**e, "projects": sorted(e["projects"])}}
            for cid, e in sorted(
                by_check.items(), key=lambda kv: (SEV_ORDER.get(kv[1]["severity"], 9), kv[0])
            )
        ],
        "top_findings": top,
    }


def _risk(risk: dict[str, Any] | None) -> dict[str, Any] | None:
    """Condense risk_assessment (SOP level 1–4 + coverage gate) for the summary."""
    if not risk:
        return None
    return {
        "level": risk.get("level"),
        "label": risk.get("label"),
        "rationale": risk.get("rationale"),
        "coverage_complete": risk.get("coverage_complete"),
        "auto_approval_eligible": risk.get("auto_approval_eligible"),
        "blockers": risk.get("auto_approval_blockers", []),
        "gaps": [
            {
                "domain": g.get("domain"),
                "reason": g.get("reason"),
                "projects": g.get("projects", []),
                "missing_apis": g.get("missing_apis", []),
                "collectors": g.get("collectors", []),
                "affected_checks": g.get("affected_checks", []),
            }
            for g in risk.get("coverage_gaps", [])
        ],
    }


def render_text(s: dict[str, Any]) -> str:
    out: list[str] = []
    scan = s["scan"]
    out.append(
        f"Scan {scan['scan_id'][:8]}  finished {scan['finished_at']}  identity={scan['identity']}"
    )
    out.append(f"Scope: {scan['scope']}  vectors={','.join(scan['vectors'] or [])}")
    sev = ", ".join(f"{k.upper()}={v}" for k, v in s["by_severity"].items()) or "none"
    penalty = s.get("penalty_points")
    penalty_txt = f"  penalty={penalty:g} pts" if isinstance(penalty, (int, float)) else ""
    out.append(
        f"Posture score: {s['posture_score']}/100{penalty_txt}  "
        f"active={s['active_findings']} ({sev})  suppressed={s['suppressed_findings']}"
    )
    if isinstance(penalty, (int, float)) and s["posture_score"] == 0.0 and penalty > 0:
        out.append(
            "  posture is floored at 0 for this scope — compare scans with penalty points, "
            "decide with the risk level."
        )

    risk = s.get("risk")
    if risk:
        out.append(
            f"SOP risk level: {risk['level']}/4 ({risk['label']})  "
            f"auto_approval_eligible={str(risk['auto_approval_eligible']).lower()}"
        )
        out.append(f"  {risk['rationale']}")
        for blocker in risk["blockers"]:
            out.append(f"  ! {blocker}")
    else:
        out.append(
            "SOP risk level: not present in this report (pre-0.1.6 scan) — re-run to get it, "
            "or read docs/risk-model.md"
        )

    cov = s["coverage"]
    c = cov["checks"]
    out.append(
        f"\nCoverage: {cov['projects_scanned']} project(s); checks executed={c.get('executed')}"
        f" failed={c.get('failed')} passed={c.get('passed')} n/a={c.get('not_applicable')}"
        f" errored={c.get('errored')}"
    )
    gaps = False
    if cov["inaccessible_projects"]:
        gaps = True
        out.append(f"  ! Inaccessible projects: {', '.join(cov['inaccessible_projects'])}")
    for err in cov["collector_errors"]:
        gaps = True
        out.append(f"  ! Collector error [{err.get('collector')}]: {err.get('error', '')[:160]}")
    for proj, apis in sorted(cov["skipped_apis_by_project"].items()):
        gaps = True
        out.append(f"  - Skipped APIs in {proj}: {', '.join(sorted(set(apis)))}")
    if not gaps:
        out.append("  No coverage gaps reported.")

    out.append(f"\nFindings by check ({s['filtered_findings']} after filters):")
    for e in s["by_check"]:
        projs = e["projects"]
        shown = ", ".join(projs[:3]) + (f" +{len(projs) - 3}" if len(projs) > 3 else "")
        out.append(
            f"  [{e['severity']:<8}] {e['check_id']:<8} x{e['count']:<3} {e['title']}  ({shown})"
        )

    if s["top_findings"]:
        out.append(f"\nTop {len(s['top_findings'])} by priority:")
    for t in s["top_findings"]:
        out.append(
            f"  #{t['rank']} [{t['severity']}] {t['check_id']} {t['project_id']} :: {t['resource_id']}"
        )
        out.append(f"      fix ({t['effort']}): {t['fix']}")
        for step in t.get("steps", []):
            out.append(f"      - {step}")
        for cmd in t.get("gcloud_commands", []):
            out.append("      $ " + cmd.replace("\n", "\n        "))
        if t.get("iac_reference"):
            out.append(f"      IaC: {t['iac_reference']}")
    if any(t.get("gcloud_commands") for t in s["top_findings"]):
        out.append(
            "\n(gcloud commands above modify resources — require human approval before running.)"
        )
    return "\n".join(out)


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("report", type=Path)
    p.add_argument("--top", type=int, default=10)
    p.add_argument("--severity", help="Comma-separated, e.g. CRITICAL,HIGH")
    p.add_argument("--project")
    p.add_argument("--check")
    p.add_argument("--remediation", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    summary = build(load(args.report), args)
    print(json.dumps(summary, indent=2) if args.json else render_text(summary))


if __name__ == "__main__":
    main()
