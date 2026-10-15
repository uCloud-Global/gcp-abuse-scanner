# Required GCP APIs

`gcp-abuse-scanner` calls GCP APIs to collect resource inventory. This page lists every API the scanner uses, which collector depends on it, and how to enable it.

> **TL;DR** — Run the helper script to enable everything at once:
> ```bash
> bash scripts/enable_apis.sh --org ORG_ID --scanner-project SCANNER_PROJECT
> ```

---

## Overview

The scanner needs APIs enabled in **two places**:

| Where | What | Why |
|---|---|---|
| **Scanner project** | Org-level APIs | The scanner calls these from its own project to read org-wide resources (IAM policies, billing, org policies) |
| **Each scanned project** | Project-level APIs | The scanner reads per-project resources (VMs, firewalls, GKE clusters, etc.) from each target project |

If an API is not enabled in a scanned project, the corresponding collector **skips that project silently** and no findings are generated for that resource type. You will see a `DEBUG`-level log entry (visible with `--verbose`).

---

## APIs Required in the Scanner Project

These must be enabled in the project where the scanner runs (or where the service account lives).

| GCP API | Enable Command | Used By | What It Collects |
|---|---|---|---|
| `cloudasset.googleapis.com` | `gcloud services enable cloudasset.googleapis.com` | `IAMCollector`, `ScopeResolver` | Org-wide IAM policy search; project enumeration under an org |
| `cloudbilling.googleapis.com` | `gcloud services enable cloudbilling.googleapis.com` | `BillingCollector` | Billing account info, project-to-billing-account mapping |
| `billingbudgets.googleapis.com` | `gcloud services enable billingbudgets.googleapis.com` | `BillingCollector` | Budget alerts per billing account (CMN-001, CMN-002, CM-060, GEM-051) |
| `orgpolicy.googleapis.com` | `gcloud services enable orgpolicy.googleapis.com` | `OrgPolicyCollector` | Org-level and project-level constraint policies (CM-002, CM-011, GEM-050, CMN-005) |

Enable all four at once:

```bash
SCANNER_PROJECT="your-scanner-project"

gcloud services enable \
  cloudasset.googleapis.com \
  cloudbilling.googleapis.com \
  billingbudgets.googleapis.com \
  orgpolicy.googleapis.com \
  --project="${SCANNER_PROJECT}"
```

---

## APIs Required in Each Scanned Project

These must be enabled in every project you want to scan. If an API is disabled in a project, the scanner skips that resource type for that project — it does **not** fail the entire scan.

| GCP API | Enable Command | Used By | Checks Enabled | Notes |
|---|---|---|---|---|
| `serviceusage.googleapis.com` | `gcloud services enable serviceusage.googleapis.com` | `ServiceUsageCollector`, `QuotaCollector` | All checks (gates all other collectors) | **Must be enabled first.** The scanner uses this to discover which other APIs are active in the project. |
| `iam.googleapis.com` | `gcloud services enable iam.googleapis.com` | `IAMCollector` | CM-040 through CM-046, CMN-004, CMN-006, GEM-020 through GEM-023 | Lists service accounts and their keys |
| `compute.googleapis.com` | `gcloud services enable compute.googleapis.com` | `ComputeCollector`, `NetworkCollector` | CM-001, CM-003 through CM-009, CM-050, CMN-003 | VM instances, firewall rules, VPC networks |
| `container.googleapis.com` | `gcloud services enable container.googleapis.com` | `GKECollector` | CM-020 through CM-026 | GKE clusters and node pools |
| `run.googleapis.com` | `gcloud services enable run.googleapis.com` | `CloudRunCollector` | CM-030, CM-031 | Cloud Run services and their IAM bindings |
| `aiplatform.googleapis.com` | `gcloud services enable aiplatform.googleapis.com` | `VertexAICollector` | GEM-030, GEM-040, GEM-011 | Vertex AI endpoints and their network config |
| `generativelanguage.googleapis.com` | `gcloud services enable generativelanguage.googleapis.com` | `QuotaCollector` | GEM-010, GEM-041 | Gemini API quota limits (the surface API keys call) |
| `apikeys.googleapis.com` | `gcloud services enable apikeys.googleapis.com` | `APIKeysCollector` | GEM-001 through GEM-006 | API keys and their restrictions. **Note:** API keys can exist in a project even if this API is not enabled — the scanner always attempts collection and handles 403 gracefully. |
| `recommender.googleapis.com` | `gcloud services enable recommender.googleapis.com` | `RecommenderCollector` | CM-045 | IAM recommender insights for over-privileged service accounts |

Enable all eight at once for a single project:

```bash
PROJECT_ID="your-project-id"

gcloud services enable \
  serviceusage.googleapis.com \
  iam.googleapis.com \
  compute.googleapis.com \
  container.googleapis.com \
  run.googleapis.com \
  aiplatform.googleapis.com \
  apikeys.googleapis.com \
  recommender.googleapis.com \
  --project="${PROJECT_ID}"
```

---

## Enabling APIs Across an Entire Organization

To enable project-level APIs across all projects in an org, use the helper script:

```bash
# Enable in all projects under org 123456789
bash scripts/enable_apis.sh --org 123456789 --scanner-project my-scanner-project

# Enable in a specific list of projects
bash scripts/enable_apis.sh \
  --projects "proj-a,proj-b,proj-c" \
  --scanner-project my-scanner-project

# Dry-run: print what would be enabled without making changes
bash scripts/enable_apis.sh --org 123456789 --scanner-project my-scanner-project --dry-run
```

The script handles pagination, parallel execution (up to 10 projects at a time), and reports which projects succeeded or failed.

---

## APIs Evaluated in the Inventory (Not Called by the Scanner)

These APIs are **not called by the scanner itself** — instead, the scanner checks whether they are enabled or disabled in each project as part of the security assessment.

| GCP API | Checked By | What the Check Does |
|---|---|---|
| `generativelanguage.googleapis.com` | GEM-010 | Flags projects where the Gemini API is enabled without proper controls |
| `aiplatform.googleapis.com` | GEM-011 | Flags projects where Vertex AI is enabled AND has broad IAM bindings |
| `logging.googleapis.com` | CMN-006 | Flags projects with Compute instances but no Cloud Logging enabled |

---

## What Happens When an API Is Disabled

| Scenario | Behavior |
|---|---|
| `serviceusage.googleapis.com` disabled in a project | The scanner cannot determine which APIs are enabled. All collectors skip the project. No findings generated. |
| Any other project-level API disabled | The collector for that API skips the project. Checks that depend on that collector produce no findings for that project. A `DEBUG` log entry is written (visible with `--verbose`). |
| `cloudasset.googleapis.com` disabled in scanner project | `IAMCollector` fails entirely — no IAM findings for any project. An `ERROR` is logged. |
| `billingbudgets.googleapis.com` disabled in scanner project | Budget checks (CMN-001, CMN-002, CM-060, GEM-051) produce no findings. A `WARNING` is logged per billing account. |

---

## Collector → API → Checks Dependency Map

```
serviceusage.googleapis.com
  └── ServiceUsageCollector
        └── (gates all other collectors)
              └── QuotaCollector → GEM-040 (Vertex AI), GEM-041 (Gemini API)

cloudasset.googleapis.com + iam.googleapis.com
  └── IAMCollector
        ├── CM-040  Broad compute creation roles
        ├── CM-041  User-managed SA keys
        ├── CM-042  Broad actAs roles
        ├── CM-043  Public IAM binding (allUsers/allAuthenticatedUsers)
        ├── CM-044  Default Compute SA with Editor role
        ├── CM-046  Personal (consumer email) account with Owner/Editor
        ├── CMN-004 Default Compute SA with active keys
        ├── CMN-006 Audit logs disabled
        ├── GEM-020 Broad Vertex AI IAM
        ├── GEM-021 Public Vertex AI binding
        ├── GEM-022 SA with Vertex access + exported keys
        └── GEM-023 Broad Vertex predict access

compute.googleapis.com
  ├── ComputeCollector
  │     ├── CM-001  VM with external IP
  │     ├── CM-005  GPU instance without restriction
  │     ├── CM-006  Insecure metadata server access
  │     ├── CM-007  Startup script with external download
  │     ├── CM-009  Shielded VM not enabled
  │     └── CMN-003 Project with no owner/team label
  └── NetworkCollector
        ├── CM-003  Unrestricted egress firewall
        ├── CM-004  Admin port (SSH/RDP) open to 0.0.0.0/0
        ├── CM-008  Database port (MySQL/PostgreSQL) open to 0.0.0.0/0
        └── CM-050  VPC with no egress deny-all rule

container.googleapis.com
  └── GKECollector
        ├── CM-020  Node pool unbounded autoscaling
        ├── CM-021  Node auto-provisioning without limits
        ├── CM-023  Public control plane endpoint
        ├── CM-024  No Workload Identity
        ├── CM-025  Legacy ABAC enabled
        └── CM-026  Node pool using default Compute SA

run.googleapis.com
  └── CloudRunCollector
        ├── CM-030  Cloud Run allows public invocation
        └── CM-031  Cloud Run unbounded scaling

aiplatform.googleapis.com
  └── VertexAICollector
        └── GEM-030 Vertex AI endpoint with no private network

apikeys.googleapis.com
  └── APIKeysCollector
        ├── GEM-001 API key with no API restrictions
        ├── GEM-002 API key with no application restrictions
        ├── GEM-003 API key targeting Gemini without app restrictions
        ├── GEM-004 API key not rotated in 90+ days
        ├── GEM-005 Multiple unrestricted API keys in same project
        └── GEM-006 API key targeting Gemini without referrer restriction

recommender.googleapis.com
  └── RecommenderCollector
        └── CM-045  IAM Recommender: over-privileged SA permissions

cloudbilling.googleapis.com + billingbudgets.googleapis.com
  └── BillingCollector
        ├── CMN-001 Billing account with no budget
        ├── CMN-002 Budget with no alert thresholds
        ├── CM-060  No budget alert at project or billing level
        └── GEM-051 No budget covering Vertex AI spend

orgpolicy.googleapis.com
  └── OrgPolicyCollector
        ├── CM-002  Org Policy: external IP not restricted
        ├── CM-011  Org Policy: resource locations not restricted
        ├── GEM-050 No API key creation restriction policy
        └── CMN-005 No security org policies configured
```

---

## Minimum vs. Full Coverage

You can run the scanner with a subset of APIs enabled. Here is what you get at each level:

### Minimum (IAM + Billing only)
Enable: `cloudasset.googleapis.com`, `iam.googleapis.com`, `cloudbilling.googleapis.com`, `billingbudgets.googleapis.com`, `orgpolicy.googleapis.com`, `serviceusage.googleapis.com`

Checks active: CM-040 through CM-046, CM-060, CMN-001 through CMN-006, GEM-020 through GEM-023, GEM-050, GEM-051

### Recommended (adds Compute + GKE + Cloud Run)
Adds: `compute.googleapis.com`, `container.googleapis.com`, `run.googleapis.com`

Additional checks: CM-001 through CM-011, CM-020 through CM-026, CM-030, CM-031, CM-050

### Full Coverage
Adds: `aiplatform.googleapis.com`, `apikeys.googleapis.com`, `recommender.googleapis.com`

Additional checks: GEM-001 through GEM-006, GEM-030, GEM-040, CM-045
