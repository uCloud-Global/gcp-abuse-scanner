# Check reference (v0.1.5 — 47 checks)

Generated from `CheckRegistry`. Source of truth: `gcp-abuse-scanner list-checks`; full rationale and
remediation per check in [`docs/checks/`](../../../docs/checks/). "Collectors" tells you which
coverage gap would hide the check (see the setup skill).

| Check | Severity | Vector | Collectors | Title |
|---|---|---|---|---|
| CM-001 | HIGH | crypto_mining | compute | VM instance has an external IP address |
| CM-002 | HIGH | crypto_mining | org_policy | Org Policy compute.vmExternalIpAccess is not enforced |
| CM-003 | HIGH | crypto_mining | network | Firewall allows unrestricted egress to the internet (0.0.0.0/0) |
| CM-004 | CRITICAL | crypto_mining | network | Firewall rule allows admin port access from the internet (0.0.0.0/0) |
| CM-005 | MEDIUM | crypto_mining | compute | VM instances with GPU accelerators detected without org-level restriction |
| CM-006 | MEDIUM | crypto_mining | compute | VM instance or project has insecure metadata (serial port enabled or OS Login disabled) |
| CM-007 | MEDIUM | crypto_mining | compute | VM startup script downloads or executes content from external URLs |
| CM-009 | MEDIUM | crypto_mining | compute | VM instance does not have Shielded VM enabled |
| CM-011 | MEDIUM | crypto_mining | org_policy | Org Policy gcp.resourceLocations is not configured (no region restriction) |
| CM-020 | HIGH | crypto_mining | gke | GKE node pool has autoscaling enabled without a maxNodeCount limit |
| CM-021 | HIGH | crypto_mining | gke | GKE cluster has Node Auto-Provisioning enabled without resource limits |
| CM-023 | HIGH | crypto_mining | gke | GKE cluster has a public control plane endpoint without authorized networks configured |
| CM-024 | MEDIUM | crypto_mining | gke | GKE cluster does not have Workload Identity enabled |
| CM-025 | MEDIUM | crypto_mining | gke | GKE cluster has Legacy ABAC (Attribute-Based Access Control) enabled |
| CM-026 | HIGH | crypto_mining | gke | GKE node pool uses the default Compute Engine service account |
| CM-030 | HIGH | crypto_mining | cloud_run | Cloud Run service allows public invocation (allUsers invoker) |
| CM-031 | MEDIUM | crypto_mining | cloud_run | Cloud Run service has no maxScale limit configured (unbounded scaling) |
| CM-040 | HIGH | crypto_mining | iam | Service account or principal has broad compute creation roles (compute.admin, container.admin) |
| CM-041 | HIGH | crypto_mining | iam | Service account has user-managed (exported) keys |
| CM-042 | HIGH | crypto_mining | iam | iam.serviceAccountTokenCreator or serviceAccountUser granted broadly |
| CM-043 | CRITICAL | crypto_mining | iam | IAM binding grants access to allUsers or allAuthenticatedUsers |
| CM-044 | HIGH | crypto_mining | iam | Default Compute Engine service account has Editor or Owner role |
| CM-045 | MEDIUM | crypto_mining | recommender | IAM Recommender identifies service account with unused compute permissions |
| CM-050 | HIGH | crypto_mining | network | VPC has no egress deny-all firewall rule (unrestricted outbound traffic) |
| CM-060 | HIGH | crypto_mining | billing | Project or billing account has no budget or budget alert configured |
| CMN-001 | HIGH | common | billing | Billing account has no budget configured |
| CMN-002 | MEDIUM | common | billing | Budget has no threshold alert rules configured |
| CMN-003 | LOW | common | compute | Project has no owner or team label (accountability gap) |
| CMN-004 | HIGH | common | iam | Default Compute Engine service account has user-managed keys |
| CMN-005 | MEDIUM | common | org_policy | Critical org-level security policies are not enforced |
| CMN-006 | MEDIUM | common | iam | Cloud Audit Logs (Data Access) may not be enabled for critical services |
| GEM-001 | CRITICAL | gemini_abuse | api_keys | API key has no API restrictions |
| GEM-002 | CRITICAL | gemini_abuse | api_keys | API key has no application restrictions (HTTP referrer / IP) |
| GEM-003 | HIGH | gemini_abuse | api_keys | API key explicitly grants access to Gemini/Generative Language API |
| GEM-004 | HIGH | gemini_abuse | api_keys | API key has not been rotated recently (older than 90 days) |
| GEM-005 | MEDIUM | gemini_abuse | api_keys | Project has multiple API keys with no API restrictions (potential orphaned keys) |
| GEM-006 | HIGH | gemini_abuse | api_keys | API key targeting Gemini/Generative Language API has no HTTP referrer restriction |
| GEM-010 | MEDIUM | gemini_abuse | service_usage | generativelanguage.googleapis.com is enabled in project (Gemini API surface exposed) |
| GEM-011 | MEDIUM | gemini_abuse | service_usage, iam | aiplatform.googleapis.com is enabled but no IAM controls restrict access |
| GEM-020 | HIGH | gemini_abuse | iam | Vertex AI / Gemini role granted to a broad principal (domain or group) |
| GEM-021 | CRITICAL | gemini_abuse | iam | Vertex AI role granted to allUsers or allAuthenticatedUsers |
| GEM-022 | HIGH | gemini_abuse | iam | Service account with Vertex AI access has user-managed (exportable) keys |
| GEM-023 | HIGH | gemini_abuse | iam | roles/aiplatform.user or broader role granted to non-specific principals |
| GEM-030 | HIGH | gemini_abuse | vertex_ai | Vertex AI endpoint is publicly accessible (no private network configured) |
| GEM-040 | MEDIUM | gemini_abuse | quota | Vertex AI quota is at default high value (no throttling configured) |
| GEM-050 | MEDIUM | gemini_abuse | org_policy | Org Policy does not restrict API key creation (iam.managed.disableServiceAccountKeyCreation absent) |
| GEM-051 | HIGH | gemini_abuse | billing, service_usage | No budget alert configured covering Vertex AI / Gemini spend |

## Related-check clusters (fix once, close several)

| Root cause | Checks it usually closes |
|---|---|
| Unrestricted API keys | GEM-001, GEM-002, GEM-003, GEM-005, GEM-006 (+ GEM-004 if rotated) |
| Public principals (`allUsers` / `allAuthenticatedUsers`) | CM-043, GEM-021, CM-030 |
| Default Compute SA over-privileged / with keys | CM-044, CM-026, CMN-004 |
| User-managed SA keys | CM-041, GEM-022, CMN-004 |
| No budgets / alerts | CMN-001, CMN-002, CM-060, GEM-051 |
| Missing org policies | CM-002, CM-011, GEM-050, CMN-005 |
| Open network edge | CM-004, CM-003, CM-050, CM-001 |
| Unbounded autoscaling | CM-020, CM-021, CM-031 |
