#!/usr/bin/env python3
"""Lint a gcp-abuse-scanner allowlist and optionally test it against a JSON report.

Usage:
    python validate_allowlist.py ALLOWLIST.yaml [--report REPORT.json] [--fix-format]

Checks:
  WARN   file uses the `allowlist:` wrapper — fine on newer releases, crashes gcp-abuse-scanner <= 0.1.5
  ERROR  rule is not a mapping, has no matching fields (suppresses everything), or has unknown keys
  ERROR  check_id not shaped like CM-001 / GEM-001 / CMN-001
  WARN   missing reason, check_id unknown to the installed scanner, project/check-wide wildcards
  WARN   (with --report) rule suppresses CRITICAL findings, or matches nothing (stale)
--fix-format prints the rules as a top-level list (works on every version).

Matching mirrors ScoringEngine._matches_allowlist: check_id/project_id exact, resource_id substring.
Exit code: 0 = no errors, 1 = errors found.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required (it is installed with gcp-abuse-scanner).")

MATCH_KEYS = {"check_id", "project_id", "resource_id"}
KNOWN_KEYS = MATCH_KEYS | {"reason"}
CHECK_ID_RE = re.compile(r"^(CM|GEM|CMN)-\d{3}$")


def known_check_ids() -> set[str] | None:
    try:
        from gcp_abuse_scanner.checks import CheckRegistry
    except ImportError:
        return None
    return {m["check_id"] for m in CheckRegistry.list_metadata()}


def matches(rule: dict[str, Any], f: dict[str, Any]) -> bool:
    if rule.get("check_id") and rule["check_id"] != f["check_id"]:
        return False
    if rule.get("project_id") and rule["project_id"] != f["resource"]["project_id"]:
        return False
    if rule.get("resource_id") and rule["resource_id"] not in f["resource"]["resource_id"]:
        return False
    return True


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("allowlist", type=Path)
    p.add_argument("--report", type=Path)
    p.add_argument("--fix-format", action="store_true")
    args = p.parse_args()

    if not args.allowlist.exists():
        print(f"ERROR: {args.allowlist} does not exist (the CLI would silently ignore it)")
        return 1

    data = yaml.safe_load(args.allowlist.read_text()) or []
    errors = warnings = 0

    if isinstance(data, dict):
        if isinstance(data.get("allowlist"), list):
            print(
                "WARN  file uses the `allowlist:` wrapper — gcp-abuse-scanner <= 0.1.5 crashes on it; "
                "use a top-level list for those versions (run with --fix-format)."
            )
            if args.fix_format:
                print("\n# --- corrected allowlist (top-level list) ---")
                print(yaml.safe_dump(data["allowlist"], sort_keys=False, allow_unicode=True))
            rules = data["allowlist"]
            warnings += 1
        else:
            print("ERROR: top level must be a list of rules")
            return 1
    elif isinstance(data, list):
        rules = data
    else:
        print("ERROR: top level must be a list of rules")
        return 1

    known = known_check_ids()
    findings = None
    if args.report:
        findings = json.loads(args.report.read_text(encoding="utf-8"))["findings"]

    for i, rule in enumerate(rules, start=1):
        tag = f"rule #{i}"
        if not isinstance(rule, dict):
            print(f"ERROR {tag}: not a mapping: {rule!r}")
            errors += 1
            continue
        tag += f" {{{', '.join(f'{k}={rule[k]}' for k in MATCH_KEYS & rule.keys())}}}"
        unknown = set(rule) - KNOWN_KEYS
        if unknown:
            print(
                f"ERROR {tag}: unknown keys {sorted(unknown)} are ignored by the scanner (rule is broader than it looks)"
            )
            errors += 1
        if not any(rule.get(k) for k in MATCH_KEYS):
            print(f"ERROR {tag}: no check_id/project_id/resource_id — suppresses EVERY finding")
            errors += 1
            continue
        cid = rule.get("check_id")
        if cid and not CHECK_ID_RE.match(str(cid)):
            print(f"ERROR {tag}: check_id '{cid}' is malformed")
            errors += 1
        elif cid and known is not None and cid not in known:
            print(f"WARN  {tag}: check_id '{cid}' is not a registered check")
            warnings += 1
        if not rule.get("reason"):
            print(f"WARN  {tag}: no reason — add who approved, why, and a review date")
            warnings += 1
        if not cid:
            print(f"WARN  {tag}: no check_id — suppresses all checks for this scope")
            warnings += 1
        elif not rule.get("project_id") and not rule.get("resource_id"):
            print(f"WARN  {tag}: suppresses {cid} across the whole scope")
            warnings += 1

        if findings is not None:
            hit = [f for f in findings if matches(rule, f)]
            if not hit:
                print(f"WARN  {tag}: matches no finding in the report (stale or typo?)")
                warnings += 1
                continue
            crit = sum(1 for f in hit if f["severity"] == "CRITICAL")
            print(f"INFO  {tag}: suppresses {len(hit)} finding(s)")
            for f in hit[:5]:
                print(
                    f"        [{f['severity']}] {f['check_id']} {f['resource']['project_id']} :: {f['resource']['resource_id']}"
                )
            if len(hit) > 5:
                print(f"        … +{len(hit) - 5} more")
            if crit:
                print(
                    f"WARN  {tag}: suppresses {crit} CRITICAL finding(s) — needs security sign-off"
                )
                warnings += 1

    print(f"\n{len(rules)} rule(s): {errors} error(s), {warnings} warning(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
