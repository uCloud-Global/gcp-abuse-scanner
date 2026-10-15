#!/usr/bin/env python3
"""Compare two gcp-abuse-scanner JSON reports (before → after).

Usage:
    python diff_reports.py BEFORE.json AFTER.json [--json]

Findings are matched on finding_id (deterministic per check + project + resource).
Reports NEW, RESOLVED and PERSISTING active findings, plus posture/coverage deltas.
A finding that disappears because its project became inaccessible or its API was skipped
is flagged as "resolved?" — that is a coverage change, not a fix.
Exit code: 0 = no new findings, 3 = new findings appeared.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"Cannot read report {path}: {exc}")


def active(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {f["finding_id"]: f for f in report["findings"] if not f.get("suppressed")}


def brief(f: dict[str, Any]) -> dict[str, str]:
    r = f["resource"]
    return {
        "finding_id": f["finding_id"],
        "check_id": f["check_id"],
        "severity": f["severity"],
        "project_id": r["project_id"],
        "resource_id": r["resource_id"],
    }


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("before", type=Path)
    p.add_argument("after", type=Path)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    before, after = load(args.before), load(args.after)
    b, a = active(before), active(after)

    lost_coverage = set(after["coverage"]["inaccessible_project_ids"]) | set(
        after["coverage"]["skipped_apis_by_project"]
    )
    new = [brief(a[k]) for k in sorted(a.keys() - b.keys())]
    resolved, uncertain = [], []
    for k in sorted(b.keys() - a.keys()):
        (uncertain if b[k]["resource"]["project_id"] in lost_coverage else resolved).append(
            brief(b[k])
        )
    persisting = [brief(a[k]) for k in sorted(a.keys() & b.keys())]

    result = {
        "posture_score": {
            "before": before["executive_summary"]["posture_score"],
            "after": after["executive_summary"]["posture_score"],
        },
        "new": new,
        "resolved": resolved,
        "resolved_uncertain_coverage_changed": uncertain,
        "persisting_count": len(persisting),
        "scope_changed": before["metadata"].get("project_ids")
        != after["metadata"].get("project_ids"),
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        ps = result["posture_score"]
        print(f"Posture: {ps['before']} → {ps['after']}")
        if result["scope_changed"]:
            print("! Scope differs between reports — deltas may reflect scope, not fixes.")
        for label, items in (
            ("NEW", new),
            ("RESOLVED", resolved),
            ("RESOLVED? (coverage changed)", uncertain),
        ):
            print(f"\n{label}: {len(items)}")
            for i in items:
                print(
                    f"  [{i['severity']}] {i['check_id']} {i['project_id']} :: {i['resource_id']}"
                )
        print(f"\nPERSISTING: {len(persisting)}")

    sys.exit(3 if new else 0)


if __name__ == "__main__":
    main()
