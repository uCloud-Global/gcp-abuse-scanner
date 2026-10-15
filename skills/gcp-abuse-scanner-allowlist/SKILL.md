---
name: gcp-abuse-scanner-allowlist
description: Create, validate and audit gcp-abuse-scanner allowlist (suppression) YAML files — write narrowly-scoped rules for accepted risks, handle the format difference across versions, test a rule against an existing report, and find stale or over-broad rules. Use when the user wants to suppress, ignore, accept, or exempt a finding.
---

# Allowlist (suppressions)

Suppressed findings stay in the report (`suppressed: true`, `suppression_reason`), get no
`priority_rank`, don't count toward posture/severity totals, don't trigger exit code 2, and are
omitted from SARIF `results`.

## File format

Both shapes are accepted and validated before collection (malformed file → exit 1):

```yaml
# allowlist.yaml
allowlist:                       # optional wrapper key; a bare top-level list also works
  - check_id: CM-001
    project_id: networking-prod
    resource_id: "instances/vpn-gateway"
    reason: "VPN gateway needs external IP. Approved by @secops 2026-10-01. Review 2027-01-01."
```

⚠️ **gcp-abuse-scanner ≤ 0.1.5** (current PyPI release) only accepts the **top-level list**; the
`allowlist:` wrapper crashes the scan after collection (`AttributeError: 'str' object has no attribute
'get'`). If `gcp-abuse-scanner version` reports ≤ 0.1.5, write a top-level list
(`validate_allowlist.py --fix-format` converts it).

A missing `--allowlist` path only prints a warning (≤0.1.5: silently ignored). There is no `--config`
flag; `examples/config.example.yaml` is only useful because its `allowlist:` section doubles as an
allowlist file — its `output:`/`scan:` keys are not read.

## Rule semantics

| Field | Match |
|---|---|
| `check_id` | exact |
| `project_id` | exact (org/billing findings may have an empty or non-project value here) |
| `resource_id` | **substring** of the finding's `resource.resource_id` |
| `reason` | stored as `suppression_reason` |

All present fields must match (AND); any rule matching suppresses (OR); omitted fields are wildcards.
Any other key (e.g. `severity`, as in the commented example in `config.example.yaml`) is **ignored** —
which silently widens the rule. A rule with no matching fields suppresses **everything**.

## Workflow

1. Get the exact values from the report, not from memory:
   ```bash
   jq '.findings[] | select(.check_id=="CM-001") | {project: .resource.project_id, resource_id: .resource.resource_id}' REPORT.json
   ```
2. Write the narrowest rule: `check_id` + `project_id` + `resource_id`. Make `resource_id` specific
   enough that it can't match other resources (`instances/bastion` also matches `instances/bastion-old`).
3. `reason` must say *who* accepted the risk, *why*, and a *review date*.
4. Don't suppress CRITICAL findings without explicit security sign-off from the user — ask.
5. Validate and test against a real report:
   ```bash
   python skills/gcp-abuse-scanner-allowlist/scripts/validate_allowlist.py allowlist.yaml --report REPORT.json
   ```
   It errors on rules without matching fields, unknown keys and malformed check IDs; warns on the
   `allowlist:` wrapper (incompatible with ≤0.1.5), missing reasons, CRITICAL suppressions and broad
   rules; with `--report` it shows which findings each rule suppresses and flags rules that match
   nothing (stale).
   `--fix-format` prints the wrapper format as a top-level list, which works on every version.
6. Re-run the scan (use `--cache` to skip re-collection when only the allowlist changed) and confirm
   the suppressed count in the summary.

## Pre-transfer assessment (budget checks)

One sanctioned, time-boxed exception ships with the repo: `examples/allowlist-pre-transfer.yaml`.
Budgets live on the billing account, and before the transfer that account belongs to the client, so
CMN-001, CMN-002, CM-060 and GEM-051 cannot be evaluated — they either report "no budget" or get
skipped, and both distort the result. Suppress those four during the pre-transfer assessment only,
then re-scan **without** the allowlist after the transfer to verify the alarm package is deployed.
Rationale in [`docs/risk-model.md`](../../docs/risk-model.md) §5.

Remember that a suppression changes the SOP risk level: a suppressed finding does not count toward
the level. Never use the allowlist to reach level 1.

## Auditing an existing allowlist

Run the validator with `--report` on a fresh scan. Report to the user: stale rules (match nothing),
rules past their review date, CRITICAL suppressions, project-wide or check-wide wildcards. Propose
removals; don't delete rules without approval — they are security decisions owned by humans and
should go through PR review.
