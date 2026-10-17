# Risk Model — from scan output to SOP risk level (1–4)

The scanner reports a **posture score (0–100)** and findings by severity. The SOP decides with
**levels 1 to 4**. This document is the only place where one is translated into the other, and the
mapping is implemented in [`scoring/risk.py`](../gcp_abuse_scanner/scoring/risk.py) so that two
analysts — or two runs — reading the same report always arrive at the same level.

Everything below lands in the report as a single object, `risk_assessment`:

```bash
jq '.risk_assessment' gcp-scan-<id>.json
```

```json
{
  "level": 4,
  "label": "CRITICAL",
  "rationale": "2 finding(s) of the level-4 class — unrestricted Gemini API key or public access (GEM-001 ×2).",
  "triggering_check_ids": ["GEM-001"],
  "triggers": [
    {
      "check_id": "GEM-001",
      "finding_id": "GEM-001-1234/5",
      "project_id": "client-project",
      "severity": "CRITICAL",
      "rule": "level_4_check"
    }
  ],
  "coverage_complete": true,
  "coverage_gaps": [],
  "auto_approval_eligible": false,
  "auto_approval_blockers": ["risk level 4 (CRITICAL) — findings require remediation before the assessment can be approved"]
}
```

---

## 1. Level mapping

The level is derived from **every finding, suppressed or not** (suppression never lowers it —
see §5), highest rule wins:

| Level | Label | Rule | Rationale |
|---|---|---|---|
| **4** | CRITICAL | Any finding whose `check_id` is in `LEVEL_4_CHECKS` | Unrestricted access to Gemini from an API key, or access opened to the internet. Exploitable as-is, with no further prerequisite. |
| **3** | HIGH | Any other CRITICAL finding, and no level-4 finding | Includes the identity gaps: a personal account with Owner/Editor (`CM-046`), an open admin/database port (`CM-004`, `CM-008`), `allUsers` bindings, permissive egress. |
| **2** | MEDIUM | Only HIGH findings (no CRITICAL) | Real exposure, but not exploitable without an additional step (a credential, a reachable workload). |
| **1** | LOW | Only MEDIUM/LOW/INFO findings **and** complete coverage | Nothing that blocks the assessment. See the gate in section 2. |

`LEVEL_4_CHECKS` is deliberately a short, explicit list — it must be reviewable line by line, not
inferred:

| Check | Why level 4 |
|---|---|
| `GEM-001` | API key with no API restrictions |
| `GEM-002` | API key with no application restrictions (referrer / IP) — counts only when the key can reach the Gemini API: no API restriction at all, or `generativelanguage.googleapis.com` among its targets. A Maps-only key without referrer restrictions cannot call Gemini, so it reads as level 3. |
| `GEM-006` | API key targeting the Gemini API with no referrer restriction |
| `CM-043` | IAM binding grants access to `allUsers` / `allAuthenticatedUsers` |
| `GEM-021` | Vertex AI role granted to `allUsers` / `allAuthenticatedUsers` |

Level 4 is *not* capped by coverage and *not* reduced by anything else in the report: one
unrestricted key that can reach Gemini means level 4 for the whole assessment, even if every other
check passed.

### The posture score (0–100) is not a decision metric

`executive_summary.posture_score` is computed as:

```
penalty  = Σ severity weight        # CRITICAL=10, HIGH=5, MEDIUM=2, LOW=0.5, INFO=0
baseline = projects × 20 × 0.5      # "~20 checks per project"
score    = max(0, 100 − (penalty / baseline × 100))
```

Two properties make it unusable as a decision metric, so it is never part of the rule above:

**It normalizes by scope.** The same 18 findings (penalty 85) score differently depending only on
how many projects are in scope:

| projects in scope | baseline | score |
|---|---|---|
| 1 | 10 | **0.0** |
| 5 | 50 | 0.0 |
| 20 | 200 | 57.5 |
| 100 | 1000 | 91.5 |

**It floors at 0, which hides everything below.** On a single-project scan the baseline is 10, so
one CRITICAL (10 points) already reports `0.0` — and so does 11 CRITICAL. Measured on
`prj-n-ucbr-lab-ms` (18 findings: 2 CRITICAL, 11 HIGH, 5 MEDIUM): `penalty = 85`,
`raw = 100 − 850 = −750` → `0.0`. The floor cannot tell "something is off" from "this is the worst
report I have ever seen". The `20` constant is also stale — it dates from when the tool had ~25
checks; there are now 50.

What to read instead:

| Question | Metric |
|---|---|
| How bad is this, per the SOP? | `risk_assessment.level` (1–4) + `auto_approval_eligible` |
| What is there to fix? | `executive_summary.by_severity` and `findings[]` by `priority_rank` |
| Did my fix actually improve things? | `executive_summary.penalty_points` — **scope-independent, uncapped** |

`penalty_points` is the raw severity sum, without normalization and without the floor: `85` for the
scan above. It falls by exactly the weight of every finding you fix (−10 per CRITICAL, −5 per
HIGH), regardless of how many projects are in scope, so two scans of the same scope are directly
comparable and a `posture_score` of `0.0` stops meaning "everything".

`posture_score` still exists (unchanged, so historical reports stay comparable) — just never use it
on its own, and never compare two scans taken over different scopes.

### What the level does not measure

- **The posture score** (0–100) is a progress metric weighted by severity, normalized by project
  count. It is not comparable across scans of different sizes and is never used to derive the
  level.
- **Suppressed findings still count.** A suppressed `GEM-001` still reads as level 4: an allowlist
  is a record of accepted risk, not a way to make a report look better (§5). Suppression only
  shapes the report — counts, penalty and ranking — never the level.
- **Level 3 does not require a CRITICAL to be an identity problem.** The SOP wording "no 2SV, no
  Cloud Identity" is not directly observable by a read-only scanner (2SV lives in Workspace/Cloud
  Identity admin, outside the scanned APIs). `CM-046` is the scanner's proxy for it: a personal
  account holding Owner/Editor is a `CRITICAL` finding and therefore level 3. A managed account
  with Owner/Editor and weak 2SV still has to be caught manually — see section 4.

---

## 2. Coverage gate (never auto-approve on unread data)

For a 1/4 result to be worth anything, the scan has to have actually looked. The scanner is
read-only and **fails open**: an API that is not enabled, a `403`, or a collector that raised is
recorded in `coverage` and the scan still exits `0`. Without a gate, "we could not read the API
keys" is indistinguishable from "there were no issues with the API keys".

Rule:

> **If any part of the API keys, IAM, network, compute or quota coverage is missing, the
> assessment is undetermined and can never be approved automatically — regardless of the level.**

The gate is implemented as `coverage_complete` + `auto_approval_eligible`, and it is evaluated
independently of the level (a level-1 scan with a gap is *not* approvable):

| Field | Meaning |
|---|---|
| `coverage_complete` | `false` when at least one gap was found in the sensitive domains below, or when a project could not be scanned at all |
| `auto_approval_eligible` | `level == 1` **and** `coverage_complete`. Only then is there nothing left to review |
| `coverage_gaps[]` | One entry per gap: `domain`, `reason`, `projects`, `missing_apis`, `collectors`, `affected_checks` |
| `auto_approval_blockers[]` | Human-readable list: the level reason plus every gap |

### Sensitive domains

| Domain | Required APIs | Collector | Representative checks |
|---|---|---|---|
| `api_keys` | `apikeys.googleapis.com` | `api_keys` | GEM-001…GEM-006, GEM-010 |
| `iam` | `iam.googleapis.com`, `cloudresourcemanager.googleapis.com` | `iam` | CM-040…CM-046, GEM-020…GEM-023, CMN-004 |
| `network` | `compute.googleapis.com` | `network` | CM-003, CM-004, CM-008, CM-050 |
| `compute` | — (collector and checks only) | `compute` | CM-001, CM-005, CM-006, CM-007, CM-009, CMN-003 |
| `quota` | `serviceusage.googleapis.com` | `quota` | GEM-040, GEM-041 |
| `projects` | — | — | Any project in `coverage.inaccessible_project_ids`: every check is unevaluated there |

`compute.googleapis.com` appears only in the `network` row on purpose: a project with that API
disabled gets **one** gap (the compute collector and the network collector both lose it), not one
gap per domain.

A gap is recorded when any of these holds, per domain:

1. the API appears in `coverage.skipped_apis_by_project` (not enabled, or not readable),
2. the collector appears in `coverage.collector_errors`,
3. a check of the domain is in `coverage.checks_not_applicable_ids` (its required API exists
   nowhere in scope, so it never ran),
4. a check of the domain is in `coverage.checks_errored_ids`.

Gaps outside these domains (GKE, Cloud Run, Recommender, Vertex AI, budgeting) do **not** block
approval — they are visible in `coverage` for the reader, but the SOP's gate is scoped to API
keys, IAM, network, compute and quota.

Budgets deserve a note of their own: when the Cloud Billing Budget API is disabled (or the identity
lacks `roles/billing.viewer`), `coverage.unreadable_budget_accounts` lists the accounts that could
not be read and the budget checks (`CMN-001`, `CMN-002`, `CM-060`, `GEM-051`) **report nothing about
them** — an unreadable account must never turn into a "no budget configured" finding. Budgets stay
out of the approval gate because before the billing transfer they belong to the client's account
(§5); they are reported as a coverage fact instead.

### Fixing a gap instead of reading around it

```bash
# 1. What exactly is missing?
jq '.coverage_gaps' gcp-scan-<id>.json

# 2. Why: the per-project API skips and the collector errors
jq '.coverage.skipped_apis_by_project, .coverage.collector_errors' gcp-scan-<id>.json

# 3. Enable the missing API / grant the role, then re-scan WITHOUT the cache —
#    a cached inventory will happily replay the gap
gcp-abuse-scanner scan --project my-proj --no-cache --format json --output re-scan.json
```

See the setup skill (`skills/gcp-abuse-scanner-setup/SKILL.md`) for the read-only role set and
`docs/iam-setup.md` for the API list. Never turn a gap into a suppression.

---

## 3. SOP 5.2 requirement → implementation

Status of each requirement in the scan scope, as of the current release. "Cobertura" is the
domain column of section 2 — a `No` in the "Automated" column means the item stays a **manual step
in the review**, not that the requirement is waived.

| SOP 5.2 requirement | Automated | Checks / notes |
|---|---|---|
| API keys without restrictions (CooWeb vector) | Yes | GEM-001 (no API restrictions), GEM-002 (no app restrictions), GEM-003 (key targets Gemini), GEM-004 (rotation > 90 days), GEM-005 (orphaned keys), GEM-006 (no referrer) |
| SSH/RDP open to `0.0.0.0/0` | Yes | CM-004 (22, 3389, 5985, 5986) |
| MySQL / PostgreSQL open (3306, 5432) | Yes | CM-008 |
| Personal accounts (`@gmail.com` and similar) as Owner or Editor | Yes | CM-046. **Consumer domains only** — external corporate domains (`@vendor.com`) are not detectable without Cloud Identity directory access; cross-check manually |
| Service account keys older than 90 days | Stricter | CM-041 flags **any** user-managed SA key, regardless of age; CMN-004 covers the default Compute SA. `CM-041` is a superset of the requirement, so an old key is never missed — but the age is not the criterion, the existence of the key is |
| GPUs | Yes | CM-005 (GPU instances present) + compute quotas in GEM-040/`quota_info` |
| GenAI quotas without control | Yes | GEM-040 (Vertex AI) and GEM-041 (Gemini API / Generative Language — the surface API keys reach) |
| Budgets and alerts | Yes, with a caveat | CMN-001, CMN-002, CM-060, GEM-051. **Before the billing transfer** these run against the client's billing account: suppress them deliberately (see section 5) instead of letting them pollute the level |
| 2SV in Workspace | No, by design | Manual validation (form/Workspace admin). CM-046 is the scanner's proxy for identity governance |
| Unusual consumption peaks (level-4 criterion in the SOP) | No, by design | Configuration scanning cannot see consumption. Take it from the billing export or the prioritization template — out of scope here |
| Deploy mitigations via IaC (SOP §1) | No, by design | The scanner is read-only; `remediation.gcloud_commands` are a plan, never executed by an agent. The Terraform module from SOP §7.1 is a separate deliverable that does not exist yet |

---

## 4. Consuming the result (review workflow)

```bash
gcp-abuse-scanner scan --org 123456789012 \
  --impersonate-service-account scanner@scanner-proj.iam.gserviceaccount.com \
  --format json --output /tmp/scan.json ; echo "exit=$?"

# Decide with the level and the gate, not with the posture score:
jq '{level: .risk_assessment.level,
     label: .risk_assessment.label,
     eligible: .risk_assessment.auto_approval_eligible,
     gaps: [.risk_assessment.coverage_gaps[].domain],
     blockers: .risk_assessment.auto_approval_blockers}' /tmp/scan.json
```

Decision table:

| `auto_approval_eligible` | Level | Action |
|---|---|---|
| `true` | 1 | Nothing to fix. Approve, record the scan id. |
| `false` | 1 | **Human review of the coverage gaps.** Fix the permission/API and re-scan, or accept the gap explicitly and in writing. |
| `false` | 2 | Remediate the HIGH findings, then re-scan (`--no-cache`). |
| `false` | 3 | Remediate the CRITICAL findings (open ports, identity gaps, public bindings) before handover. |
| `false` | 4 | Stop. Unrestricted Gemini key or public access. No transfer without fixing this. |

**Combining the scanner with the manual evidence.** 2SV, Cloud Identity, M365 access and
consumption peaks live outside what a read-only scanner sees, so the SOP's manual evidence is
merged with this report by taking the higher of the two:

```
final level = max(scanner level, manual evidence level)
```

`auto_approval_eligible` covers scanner coverage only — the scanner never approves on its own.

Process exit codes are unchanged by the risk model (`0` no active CRITICAL, `2` at least one
CRITICAL, `1`/`2` for usage and scope errors — see `AGENTS.md`). Gate on
`risk_assessment.auto_approval_eligible` in CI instead of re-deriving the rule from severities.

---

## 5. Suppression is not neutral

Suppression never lowers the level: `assess_risk` computes the level from **every** finding,
suppressed or not, so an allowlist cannot turn an open Gemini key or an unremediated `CMN-001`
into a level 1. Suppression only shapes the report — counts, penalty and ranking. Two
consequences worth stating out loud:

- The **pre-transfer allowlist** (`examples/allowlist-pre-transfer.yaml`) suppresses exactly the
  four budget checks, because before the billing transfer the budgets live on the client's billing
  account — there is nothing to observe, and an absent budget is not a finding the client can act
  on. Since those findings are still counted, that scan reads as **level 2** and is never
  auto-approved: it goes through human review (§4). The file documents its own expiry: **remove it
  after the transfer** and re-scan, so the alarm package deployed during the transfer is actually
  verified.
- Any suppression must carry a dated reason and be reviewed (`docs/allowlist.md`). The allowlist is
  a record of accepted risk, never a way to reach level 1.
