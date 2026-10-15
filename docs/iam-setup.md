# IAM Setup Guide

Step-by-step instructions to create the service account, enable the required GCP APIs, and assign the required roles.

> **See also:** [docs/apis.md](apis.md) — complete reference of every GCP API the scanner uses, which checks depend on each one, and what happens when an API is disabled.

---

## 0. Enable Required GCP APIs

Before running the scanner, the required GCP APIs must be enabled. Use the helper script:

```bash
# Enable all APIs — org-level (scanner project) + project-level (all projects in org)
bash scripts/enable_apis.sh \
  --org YOUR_ORG_ID \
  --scanner-project YOUR_SCANNER_PROJECT

# Dry-run first to see what would be enabled
bash scripts/enable_apis.sh \
  --org YOUR_ORG_ID \
  --scanner-project YOUR_SCANNER_PROJECT \
  --dry-run
```

Or enable manually:

**Scanner project** (org-level APIs — enable once):
```bash
gcloud services enable \
  cloudasset.googleapis.com \
  cloudbilling.googleapis.com \
  billingbudgets.googleapis.com \
  orgpolicy.googleapis.com \
  --project=YOUR_SCANNER_PROJECT
```

**Each scanned project** (project-level APIs):
```bash
gcloud services enable \
  serviceusage.googleapis.com \
  iam.googleapis.com \
  compute.googleapis.com \
  container.googleapis.com \
  run.googleapis.com \
  aiplatform.googleapis.com \
  apikeys.googleapis.com \
  recommender.googleapis.com \
  --project=PROJECT_ID
```

> **Note:** If a project-level API is not enabled, the scanner skips that resource type for that project silently. No findings are generated for skipped resource types. Use `--verbose` to see which APIs were skipped.

---

## 1. Create the Service Account

```bash
export PROJECT_ID="your-scanner-project"
export SA_NAME="gcp-abuse-scanner"
export SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

gcloud iam service-accounts create ${SA_NAME} \
  --display-name="GCP Abuse Scanner" \
  --description="Read-only SA for gcp-abuse-scanner security scans" \
  --project=${PROJECT_ID}
```

## 2. Assign Roles at Organization Level (for org-wide scans)

```bash
export ORG_ID="your-org-id"

for ROLE in \
  roles/cloudasset.viewer \
  roles/iam.securityReviewer \
  roles/compute.viewer \
  roles/container.viewer \
  roles/run.viewer \
  roles/serviceusage.serviceUsageViewer \
  roles/serviceusage.apiKeysViewer \
  roles/aiplatform.viewer \
  roles/billing.viewer \
  roles/recommender.viewer \
  roles/orgpolicy.policyViewer \
  roles/monitoring.viewer; do
  gcloud organizations add-iam-policy-binding ${ORG_ID} \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="${ROLE}"
done
```

## 3. (Recommended) Use Impersonation

Instead of exporting a key file, grant your user/CI SA the ability to impersonate the scanner SA:

```bash
# Allow your user to impersonate the scanner SA
gcloud iam service-accounts add-iam-policy-binding ${SA_EMAIL} \
  --member="user:your-email@example.com" \
  --role="roles/iam.serviceAccountTokenCreator"

# Then run the scanner with impersonation
gcp-abuse-scanner scan --org ${ORG_ID} \
  --impersonate-service-account ${SA_EMAIL}
```

## 4. (Alternative) Export a Key File

> ⚠️ Only use this if impersonation is not possible. Key files are long-lived credentials.

```bash
gcloud iam service-accounts keys create scanner-key.json \
  --iam-account=${SA_EMAIL}

export GOOGLE_APPLICATION_CREDENTIALS=./scanner-key.json
gcp-abuse-scanner scan --org ${ORG_ID}
```

## 5. Verify Permissions

```bash
# Test that the SA can list projects
gcloud projects list --impersonate-service-account=${SA_EMAIL}

# Test Cloud Asset access
gcloud asset search-all-resources \
  --scope=organizations/${ORG_ID} \
  --asset-types=cloudresourcemanager.googleapis.com/Project \
  --impersonate-service-account=${SA_EMAIL} \
  --limit=5
```

### Prove coverage per role (`--coverage`)

**`roles/viewer` is not a substitute for the roles above.** It grants Compute/GKE/Cloud Run reads but
not the API Keys API, Cloud Asset IAM search, Recommender insights, quotas or Billing — the surfaces
`GEM-001`…`GEM-006`, `CM-043`, `CM-046` and `CM-041` depend on. The scanner fails open, so what you get
is a report with no Gemini findings *and* exit code 0.

Before promising coverage for a handover (e.g. "Viewer + Security Reviewer"), run the preflight in
coverage mode against a project inside the client's org:

```bash
bash skills/gcp-abuse-scanner-setup/scripts/preflight.sh \
  --project CLIENT_PROJECT \
  --impersonate ${SA_EMAIL} \
  --coverage
```

It performs one representative read call per collector and prints, for each failure, the checks that
would come back silently empty. Any ❌ is a hole, not a scan error: grant the missing reader role or
record the accepted gap in writing. The scanner's own version of this check lands in the report as
`risk_assessment.coverage_gaps[]` (see [`risk-model.md`](risk-model.md)).

## Terraform

```hcl
resource "google_service_account" "scanner" {
  account_id   = "gcp-abuse-scanner"
  display_name = "GCP Abuse Scanner"
  project      = var.project_id
}

locals {
  scanner_roles = [
    "roles/cloudasset.viewer",
    "roles/iam.securityReviewer",
    "roles/compute.viewer",
    "roles/container.viewer",
    "roles/run.viewer",
    "roles/serviceusage.serviceUsageViewer",
    "roles/serviceusage.apiKeysViewer",
    "roles/aiplatform.viewer",
    "roles/billing.viewer",
    "roles/recommender.viewer",
    "roles/orgpolicy.policyViewer",
    "roles/monitoring.viewer",
  ]
}

resource "google_organization_iam_member" "scanner" {
  for_each = toset(local.scanner_roles)
  org_id   = var.org_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.scanner.email}"
}
```
