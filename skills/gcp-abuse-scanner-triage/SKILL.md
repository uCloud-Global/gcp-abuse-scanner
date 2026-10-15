---
name: gcp-abuse-scanner-triage
description: Analyze a gcp-abuse-scanner JSON report — summarize posture and coverage, prioritize findings, group them by root cause, produce a human-approved remediation plan, and compare before/after scans. Use when the user has a report (gcp-scan-*.json) or asks what to fix first, how bad their exposure is, or whether a fix worked.
---

# Triage a scan report

Work from the **JSON** report (`--format json`). If you only have Markdown/HTML, re-run with JSON.

## 1. Summarize first (don't read the whole file)

Reports can be large; start with the compact summary:

```bash
python skills/gcp-abuse-scanner-triage/scripts/summarize_report.py REPORT.json            # overview + top 10
python skills/gcp-abuse-scanner-triage/scripts/summarize_report.py REPORT.json \
  --severity CRITICAL,HIGH --top 20 --remediation                                         # with fix steps
python skills/gcp-abuse-scanner-triage/scripts/summarize_report.py REPORT.json --project my-proj
python skills/gcp-abuse-scanner-triage/scripts/summarize_report.py REPORT.json --check GEM-002 --json
```

Drill into a specific finding with `jq` only when needed:

```bash
jq '.findings[] | select(.check_id=="CM-004") | {finding_id, resource, evidence}' REPORT.json
jq '[.findings[] | select(.suppressed|not)] | group_by(.resource.project_id)
    | map({project: .[0].resource.project_id, n: length}) | sort_by(-.n)' REPORT.json
```

## 2. Read the risk level (SOP 1–4) and the coverage gate

`risk_assessment` in the JSON is the SOP decision. Report it verbatim — do not re-derive it from
severity counts:

| Level | Meaning |
|---|---|
| 4 | Unrestricted Gemini API key (GEM-001/002/006) or public access (CM-043/GEM-021) |
| 3 | Any other CRITICAL (open admin/DB ports, identity gaps, public Cloud Run, …) |
| 2 | HIGH findings, no CRITICAL |
| 1 | MEDIUM/LOW only **and** complete coverage |

```bash
jq '.risk_assessment | {level, label, auto_approval_eligible, blockers: .auto_approval_blockers,
                        gaps: [.coverage_gaps[].domain]}' REPORT.json
```

Then apply the gate before writing any conclusion:

| Field | Rule |
|---|---|
| `coverage_complete` | `false` → the assessment is **undetermined**. Say so, name the gaps. |
| `auto_approval_eligible` | Only `true` (level 1 + complete coverage) is an approval with nothing left to review. |
| `auto_approval_blockers` | Quote them as the reason for not approving. |

A gap is silent by construction: the API or role was missing, so the checks returned no findings and
the scan still exited 0. **Never** turn a gap into "no exposure", and never into a suppression.
Mapping level → action: [`docs/risk-model.md`](../../docs/risk-model.md).

## 3. Validate coverage before conclusions

The summary prints coverage gaps. For each gap say explicitly which checks could not run (map
collectors → checks via [`references/checks.md`](references/checks.md)). Never say "no Gemini
exposure" if `api_keys`/`iam` collectors errored for that project.

## 4. Prioritize

- `priority_rank` (1 = first) is already computed: `exploitability_score × blast_radius_weight`
  (billing_account 1.5, organization 1.3, project 1.0, resource 0.8), tie-broken by severity. Respect it
  unless you have context the scanner lacks — then explain the deviation.
- `posture_score` is normalized by project count and **floors at 0**: on a single-project scan one
  CRITICAL already reads `0.0`, and it stays `0.0` whether the penalty is 11 or 85. Report severity
  counts beside it; for drift between two scans use `executive_summary.penalty_points` (raw sum,
  scope-independent); for the decision use `risk_assessment`.
- Group by **root cause**, not by finding: one fix often closes several checks (clusters table in
  `references/checks.md`). Lead with CRITICALs, then items with `effort: LOW` and high rank (quick wins).
- Org/billing-level findings may have an empty `project_id` or the org/billing ID in it — treat them as
  org-wide, owned by the platform/FinOps team.

## 5. Write the remediation plan

For each root cause give: affected resources (project + resource_id), why it matters (`impact`), the
fix (`remediation.summary` + `steps`), the exact commands (`gcloud_commands`) or IaC
(`iac_reference`), effort, and how to verify (re-scan scope with `--no-cache`).

Rules:
- **Do not run remediation commands.** They modify production resources (remove IAM bindings,
  delete firewall rules, change API key restrictions). Present them; execute only with explicit per-command
  approval, and prefer that the change go through the team's IaC.
- Commands contain placeholders (`TRUSTED_IP_RANGE`, `https://yourdomain.com/*`, `KEY_UID`) —
  call out every placeholder the human must fill in.
- Some fixes can break workloads (restricting an API key used by a mobile app, removing an external IP
  from a VPN gateway). Flag the blast radius and suggest confirming with the resource owner.
- If a finding is an accepted risk, route it to the allowlist skill instead of "fixing" it.
- Don't paste raw `evidence` (API key UIDs, member emails) into tickets or external tools without need.

Suggested output structure: executive summary (**risk level**, posture, counts, coverage caveats) → top root causes
with fixes → quick wins → items needing owner decision → coverage gaps to close.

## 6. Verify fixes / track drift

```bash
gcp-abuse-scanner scan <same scope> --no-cache --format json --output after.json
python skills/gcp-abuse-scanner-triage/scripts/diff_reports.py before.json after.json   # exit 3 if NEW findings
```

`finding_id` is deterministic (check + project + md5 of the resource), so it's stable across scans.
A finding listed under "RESOLVED? (coverage changed)" disappeared because its project lost
coverage — that is **not** a fix.
