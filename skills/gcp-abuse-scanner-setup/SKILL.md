---
name: gcp-abuse-scanner-setup
description: Prepare a GCP environment for gcp-abuse-scanner — install the CLI, verify credentials, configure service-account impersonation, check required APIs and read-only IAM roles, and diagnose why a scan has missing coverage (skipped APIs, 403s, inaccessible projects). Use before a first scan or when a report's coverage section shows gaps.
---

# gcp-abuse-scanner — setup & coverage troubleshooting

## 1. Install

```bash
pipx install gcp-abuse-scanner          # preferred (isolated)
# or: pip install gcp-abuse-scanner     # or, from a clone: pip install -e ".[dev]"
gcp-abuse-scanner version               # expect v0.1.5+
```

Docker alternative: the image runs as non-root user `scanner` with workdir `/reports`
(entrypoint is the CLI). Mount your gcloud config where that user's ADC lookup finds it and mount
a host dir for reports:

```bash
docker run --rm -v ~/.config/gcloud:/home/scanner/.config/gcloud:ro -v "$PWD:/reports" \
  ghcr.io/lmoreno0435/gcp-abuse-scanner:latest \
  scan --project PROJECT_ID --impersonate-service-account SA_EMAIL --format json --output /reports/scan.json
```

(The README's `/root/.config/gcloud` mount does not apply to the non-root user.)

## ⚠️ Credential gotcha (≤ 0.1.5): `GOOGLE_APPLICATION_CREDENTIALS`

The `--service-account-key` flag reads `GOOGLE_APPLICATION_CREDENTIALS` as its env var. If that
variable points to anything other than an SA key JSON — user ADC (`authorized_user`) or a Workload
Identity Federation config (`external_account`, set by `google-github-actions/auth`) — the CLI tries
to load it as an SA key and **every collector fails** with `MalformedError ... missing fields
token_uri, client_email`. The scan can still exit `0` with no findings.

Fix: pass `--impersonate-service-account` (it takes precedence and uses ADC/WIF as the source
credential), or `unset GOOGLE_APPLICATION_CREDENTIALS` to fall back to plain ADC.

Newer releases resolve such a file through ADC automatically, and any credential that cannot be
loaded aborts the scan up front (`Authentication failed`, exit 1) instead of producing an empty report.

## 2. Run the read-only preflight

```bash
bash skills/gcp-abuse-scanner-setup/scripts/preflight.sh \
  --scanner-project SCANNER_PROJECT \
  --impersonate scanner@SCANNER_PROJECT.iam.gserviceaccount.com \
  --project TARGET_PROJECT            # repeatable; or --org ORG_ID
```

It only reads (`gcloud auth list`, `print-access-token`, `services list`, `asset search-all-resources`)
and reports ✅/❌ per prerequisite. It never enables APIs or grants roles.

## 3. Fix what the preflight flags — with human approval

Everything below is a **write operation**. Show the commands to the user and run them only after approval.

**APIs in the scanner project** (where the SA lives / quota is billed):
`cloudasset`, `cloudbilling`, `billingbudgets`, `orgpolicy` (`.googleapis.com`).

**APIs in each scanned project**: `serviceusage` (mandatory — gates every other collector), `iam`,
`compute`, `container`, `run`, `aiplatform`, `apikeys`, `recommender`.

Bulk helper (always dry-run first):

```bash
bash scripts/enable_apis.sh --org ORG_ID --scanner-project SCANNER_PROJECT --dry-run
bash scripts/enable_apis.sh --projects "proj-a,proj-b" --scanner-project SCANNER_PROJECT --dry-run
```

Note: enabling APIs is a change to the customer's environment. A missing API is often intentional
(e.g. no GKE in that project) — then the gap is expected, not a problem.

**Read-only roles for the scanner SA** (org level for org scans, project level otherwise):
`roles/cloudasset.viewer`, `roles/iam.securityReviewer`, `roles/compute.viewer`, `roles/container.viewer`,
`roles/run.viewer`, `roles/serviceusage.serviceUsageViewer`, `roles/serviceusage.apiKeysViewer`,
`roles/aiplatform.viewer`, `roles/billing.viewer`, `roles/recommender.viewer`,
`roles/orgpolicy.policyViewer`, optional `roles/monitoring.viewer`. Full commands + Terraform:
[`docs/iam-setup.md`](../../docs/iam-setup.md).

**Impersonation** (preferred over keys): the human/CI identity needs
`roles/iam.serviceAccountTokenCreator` on the scanner SA. Never create an SA key to "unblock" a scan.

## 4. Diagnosing gaps from a report

Read `coverage` from a JSON report (or run the triage summarizer, which prints it):

| Symptom in `coverage` | Likely cause | Action |
|---|---|---|
| `inaccessible_project_ids` non-empty | SA lacks access, project deleted, or typo in `--project` | Check project ID spelling and role bindings |
| `skipped_apis_by_project[p]` lists an API | API disabled in that project → those checks produced **nothing** for it | Expected if the service isn't used; otherwise enable the API (approval) |
| `collector_errors` with `HTTP 403` | Missing role, or API disabled in the **scanner** project (quota project) | Map collector → API/role with [`docs/apis.md`](../../docs/apis.md) |
| `collector_errors` with `requires billing to be enabled` | Target project has no billing → API unusable | Report as a coverage gap; nothing to fix in the scanner |
| `checks_not_applicable` high | Required APIs not enabled anywhere in scope | Same as skipped APIs |
| Scope resolution failed (exit 1) on `--org` | `cloudasset.googleapis.com` disabled or `roles/cloudasset.viewer` missing at org | Enable API / grant role (approval) |

Re-run with `--verbose` only when the JSON coverage section is not enough; logs are noisy.

Collector → checks map (summary): `iam` → CM-040..045, CMN-004, CMN-006, GEM-020..023 · `compute`/`network`
→ CM-001..009, CM-050, CMN-003 · `gke` → CM-020..026 · `cloud_run` → CM-030/031 · `api_keys` → GEM-001..006 ·
`vertex_ai` → GEM-030 · `quota` → GEM-040 · `billing` → CMN-001/002, CM-060, GEM-051 · `org_policy` →
CM-002, CM-011, GEM-050, CMN-005 · `recommender` → CM-045.
