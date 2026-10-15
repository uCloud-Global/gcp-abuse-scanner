# Gemini Abuse & Common Checks

> Checks that detect GCP misconfigurations enabling unauthorized Gemini / Vertex AI usage and cross-cutting governance gaps.

## Summary Table

### Gemini Abuse Checks

| Check ID | Title | Severity | Collectors |
|---|---|---|---|
| GEM-001 | API key has no API restrictions | CRITICAL | `api_keys` |
| GEM-002 | API key has no application restrictions (HTTP referrer / IP) | CRITICAL | `api_keys` |
| GEM-003 | API key explicitly grants access to Gemini/Generative Language API | HIGH | `api_keys` |
| GEM-004 | API key has not been rotated recently (older than 90 days) | HIGH | `api_keys` |
| GEM-005 | Project has multiple API keys with no API restrictions (potential orphaned keys) | MEDIUM | `api_keys` |
| GEM-006 | API key targeting Gemini/Generative Language API has no HTTP referrer restriction | HIGH | `api_keys` |
| GEM-010 | generativelanguage.googleapis.com is enabled in project (Gemini API surface exposed) | MEDIUM | `service_usage` |
| GEM-011 | aiplatform.googleapis.com is enabled but no IAM controls restrict access | MEDIUM | `service_usage`, `iam` |
| GEM-020 | Vertex AI / Gemini role granted to a broad principal (domain or group) | HIGH | `iam` |
| GEM-021 | Vertex AI role granted to allUsers or allAuthenticatedUsers | CRITICAL | `iam` |
| GEM-022 | Service account with Vertex AI access has user-managed (exportable) keys | HIGH | `iam` |
| GEM-023 | roles/aiplatform.user or broader role granted to non-specific principals | HIGH | `iam` |
| GEM-030 | Vertex AI endpoint is publicly accessible (no private network configured) | HIGH | `vertex_ai` |
| GEM-040 | Vertex AI quota is at default high value (no throttling configured) | MEDIUM | `quota` |
| GEM-041 | Gemini API (Generative Language) quota is at default value (no throttling configured) | MEDIUM | `quota` |
| GEM-050 | Org Policy does not restrict API key creation (iam.managed.disableServiceAccountKeyCreation absent) | MEDIUM | `org_policy` |
| GEM-051 | No budget alert configured covering Vertex AI / Gemini spend | HIGH | `billing`, `service_usage` |

### Common Checks

| Check ID | Title | Severity | Collectors |
|---|---|---|---|
| CMN-001 | Billing account has no budget configured | HIGH | `billing` |
| CMN-002 | Budget has no threshold alert rules configured | MEDIUM | `billing` |
| CMN-003 | Project has no owner or team label (accountability gap) | LOW | `compute` |
| CMN-004 | Default Compute Engine service account has user-managed keys | HIGH | `iam` |
| CMN-005 | Critical org-level security policies are not enforced | MEDIUM | `org_policy` |
| CMN-006 | Cloud Audit Logs (Data Access) may not be enabled for critical services | MEDIUM | `iam` |

---

## Gemini Abuse Check Details

### GEM-001 — API key has no API restrictions

**Severity:** CRITICAL
**Vector:** Gemini Abuse
**Collectors required:** `api_keys`
**Required APIs:** `apikeys.googleapis.com`
**CIS Reference:** [CIS GCP 1.14](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)

**What it detects:**
API keys that have no `apiTargets` configured in their restrictions, meaning the key is valid for any GCP API including `generativelanguage.googleapis.com` (Gemini) and `aiplatform.googleapis.com` (Vertex AI).

**Why it matters:**
An unrestricted API key leaked in client-side code, a public repository, or CI logs can be used by anyone to call the Gemini API at the project's expense. There is no API-level boundary preventing the key from being used for any GCP service, maximizing the blast radius of a leak.

**Remediation:**
1. Identify which APIs this key is actually used for.
2. Add API restrictions to limit the key to those APIs only.
3. Add application restrictions (HTTP referrer / IP allowlist).
4. Rotate the key after applying restrictions.
5. Consider migrating to OAuth 2.0 for server-side use cases.

```bash
gcloud services api-keys update KEY_UID \
  --api-target=service=generativelanguage.googleapis.com \
  --allowed-referrers=https://yourdomain.com/*
```

**References:**
- [Restricting an API key](https://cloud.google.com/docs/authentication/api-keys#restricting_an_api_key)
- [Generative AI authentication](https://cloud.google.com/generative-ai-app-builder/docs/authentication)

---

### GEM-002 — API key has no application restrictions (HTTP referrer / IP)

**Severity:** CRITICAL
**Vector:** Gemini Abuse
**Collectors required:** `api_keys`
**Required APIs:** `apikeys.googleapis.com`
**CIS Reference:** [CIS GCP 1.14](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)

**What it detects:**
API keys that have no application restrictions configured — no `browserKeyRestrictions`, `serverKeyRestrictions`, `androidKeyRestrictions`, or `iosKeyRestrictions`. The key can be used from any IP address or HTTP origin.

**Why it matters:**
Without application restrictions, a leaked key can be exploited from any machine anywhere in the world. Even if API restrictions are in place (GEM-001), the absence of application restrictions means there is no network-level control preventing abuse.

**Remediation:**
1. Determine the key's consumer type (browser app, server, mobile).
2. For browser apps: add HTTP referrer restrictions.
3. For server apps: add IP address restrictions.
4. For mobile apps: add Android/iOS app restrictions.
5. Rotate the key after applying restrictions.

```bash
# Browser key:
gcloud services api-keys update KEY_UID \
  --allowed-referrers=https://yourdomain.com/*

# Server key:
gcloud services api-keys update KEY_UID \
  --allowed-ips=203.0.113.0/24
```

**References:**
- [Adding application restrictions](https://cloud.google.com/docs/authentication/api-keys#adding_application_restrictions)

---

### GEM-003 — API key explicitly grants access to Gemini/Generative Language API

**Severity:** HIGH
**Vector:** Gemini Abuse
**Collectors required:** `api_keys`
**Required APIs:** `apikeys.googleapis.com`
**CIS Reference:** —

**What it detects:**
API keys that explicitly target `generativelanguage.googleapis.com` or `aiplatform.googleapis.com` in their `apiTargets` restrictions but have no application restrictions (HTTP referrer / IP allowlist). This is a compound risk: the key is scoped to Gemini but has no caller restriction.

**Why it matters:**
A key explicitly scoped to the Gemini API without application restrictions is a direct Gemini abuse surface. If leaked, it provides immediate, unrestricted access to Gemini model invocations, generating high costs with no network-level barrier.

**Remediation:**
1. Add HTTP referrer or IP restrictions to the key.
2. Rotate the key after applying restrictions.
3. Monitor key usage via Cloud Audit Logs.

```bash
gcloud services api-keys update KEY_UID \
  --allowed-referrers=https://yourdomain.com/*
```

**References:**
- [Restricting an API key](https://cloud.google.com/docs/authentication/api-keys#restricting_an_api_key)

---

### GEM-004 — API key has not been rotated recently (older than 90 days)

**Severity:** HIGH
**Vector:** Gemini Abuse
**Collectors required:** `api_keys`
**CIS Reference:** —

**What it detects:**
API keys whose `createTime` is more than 90 days ago, or whose `createTime` is missing or unparseable (treated conservatively as stale). Long-lived keys increase the window of exposure if the key is leaked.

**Why it matters:**
A stale key that has been leaked may have been in active abuse for an extended period without detection. Regular rotation limits the damage window of any credential leak. Keys older than 90 days should be considered potentially compromised.

**Remediation:**
1. Create a replacement API key with the same restrictions.
2. Update all applications and services to use the new key.
3. Verify the old key is no longer in use via Cloud Audit Logs.
4. Delete the old key.
5. Establish a key rotation schedule (≤ 90 days).

```bash
gcloud services api-keys create \
  --display-name=NEW_KEY \
  --api-target=service=generativelanguage.googleapis.com

# After migration:
gcloud services api-keys delete OLD_KEY_UID
```

**References:**
- [Rotating API keys](https://cloud.google.com/docs/authentication/api-keys#rotating_api_keys)

---

### GEM-005 — Project has multiple API keys with no API restrictions (potential orphaned keys)

**Severity:** MEDIUM
**Vector:** Gemini Abuse
**Collectors required:** `api_keys`
**CIS Reference:** —

**What it detects:**
Projects that have more than 3 API keys with no `apiTargets` configured. A high count of unrestricted keys suggests poor key hygiene and likely orphaned credentials that are no longer actively managed.

**Why it matters:**
Orphaned unrestricted keys are a persistent credential leak risk. Any of them can be used to call Gemini APIs at the project's expense. Accumulated keys are often forgotten, never rotated, and may have been leaked in old codebases or CI logs.

**Remediation:**
1. Review each key's last-used timestamp in Cloud Audit Logs.
2. Delete keys that have not been used in the last 30 days.
3. For remaining keys, add API restrictions to the minimum required APIs.
4. Add application restrictions (HTTP referrer / IP allowlist).
5. Implement a key inventory process to prevent accumulation.

```bash
gcloud services api-keys list --project=PROJECT_ID

gcloud services api-keys delete KEY_ID --project=PROJECT_ID
```

**References:**
- [Restricting an API key](https://cloud.google.com/docs/authentication/api-keys#restricting_an_api_key)

---

### GEM-006 — API key targeting Gemini/Generative Language API has no HTTP referrer restriction

**Severity:** HIGH
**Vector:** Gemini Abuse
**Collectors required:** `api_keys`
**CIS Reference:** —

**What it detects:**
API keys that target `generativelanguage.googleapis.com` or `aiplatform.googleapis.com` but have no `browserKeyRestrictions` configured. This is specifically relevant for keys embedded in browser-side applications.

**Why it matters:**
A Gemini-enabled key without HTTP referrer restrictions can be extracted from browser traffic (e.g., via DevTools or network interception) and reused from any origin to generate costs. This is a common pattern when developers embed API keys directly in frontend JavaScript.

**Remediation:**
1. Determine whether this key is used in a browser or server context.
2. For browser use: add allowed HTTP referrers (e.g., `https://yourdomain.com/*`).
3. For server use: switch to IP restrictions or service account credentials.
4. Rotate the key after applying restrictions.

```bash
gcloud services api-keys update KEY_UID \
  --allowed-referrers=https://yourdomain.com/*
```

**References:**
- [Adding application restrictions](https://cloud.google.com/docs/authentication/api-keys#adding_application_restrictions)

---

### GEM-010 — generativelanguage.googleapis.com is enabled in project (Gemini API surface exposed)

**Severity:** MEDIUM
**Vector:** Gemini Abuse
**Collectors required:** `service_usage`
**CIS Reference:** —

**What it detects:**
Projects where `generativelanguage.googleapis.com` is in the enabled services list, exposing the Gemini API surface. This is an informational check that flags projects where Gemini is enabled, prompting review of associated API key and IAM controls.

**Why it matters:**
Enabled Gemini API combined with weak credentials or IAM controls creates a direct path for unauthorized model invocations. Projects that have enabled this service but do not actively use it represent unnecessary attack surface.

**Remediation:**
1. Verify whether any workload in this project requires the Gemini API.
2. If not required, disable the service.
3. If required, review API key and IAM configurations (GEM-001 through GEM-006).
4. Enable Cloud Audit Logs for the service to monitor usage.

```bash
gcloud services disable generativelanguage.googleapis.com \
  --project=PROJECT_ID
```

**References:**
- [Getting started with Generative AI](https://cloud.google.com/generative-ai-app-builder/docs/before-you-begin)

---

### GEM-011 — aiplatform.googleapis.com is enabled but no IAM controls restrict access

**Severity:** MEDIUM
**Vector:** Gemini Abuse
**Collectors required:** `service_usage`, `iam`
**CIS Reference:** —

**What it detects:**
Projects where `aiplatform.googleapis.com` is enabled and where IAM bindings grant Vertex AI roles (`roles/aiplatform.*`) to broad principals (allUsers, allAuthenticatedUsers, domain:, or group:).

**Why it matters:**
Broad IAM access to Vertex AI allows large populations of users to invoke models, increasing the blast radius of any compromised account. The combination of an enabled service and weak IAM controls is a high-risk configuration.

**Remediation:**
1. Identify which principals actually need Vertex AI access.
2. Remove broad bindings (domain:, group:, allUsers).
3. Grant roles to specific service accounts or users.
4. Consider using IAM Conditions to further restrict access.

```bash
gcloud projects get-iam-policy PROJECT_ID \
  --format=json | jq '.bindings[] | select(.role | contains("aiplatform"))'

gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member=BROAD_MEMBER --role=ROLE
```

**References:**
- [Vertex AI access control](https://cloud.google.com/vertex-ai/docs/general/access-control)

---

### GEM-020 — Vertex AI / Gemini role granted to a broad principal (domain or group)

**Severity:** HIGH
**Vector:** Gemini Abuse
**Collectors required:** `iam`
**CIS Reference:** —

**What it detects:**
IAM bindings where Vertex AI roles (`roles/aiplatform.user`, `roles/aiplatform.admin`, `roles/aiplatform.endpointUser`, `roles/ml.admin`, `roles/ml.developer`) are granted to `domain:` or `group:` principals, giving access to potentially large populations.

**Why it matters:**
Any member of those domains or groups can invoke Gemini models, including compromised accounts, leading to unauthorized cost generation. A single phished account in a broad domain binding becomes a Gemini abuse vector.

**Remediation:**
1. Audit who in the domain/group actually needs Vertex AI access.
2. Create a dedicated group with only those members.
3. Replace the broad binding with the scoped group or individual SAs.
4. Enable Org Policy: `constraints/iam.allowedPolicyMemberDomains`.

```bash
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member=domain:example.com --role=roles/aiplatform.user

gcloud projects add-iam-policy-binding PROJECT_ID \
  --member=serviceAccount:SPECIFIC_SA --role=roles/aiplatform.user
```

**References:**
- [Vertex AI access control](https://cloud.google.com/vertex-ai/docs/general/access-control)

---

### GEM-021 — Vertex AI role granted to allUsers or allAuthenticatedUsers

**Severity:** CRITICAL
**Vector:** Gemini Abuse
**Collectors required:** `iam`
**CIS Reference:** —

**What it detects:**
IAM bindings where Vertex AI roles are granted to `allUsers` or `allAuthenticatedUsers`, meaning any person on the internet (or any Google-authenticated user) can invoke Gemini models on this project.

**Why it matters:**
This is the most severe Gemini abuse misconfiguration. Any internet user can call Gemini APIs at the project's expense with no authentication required (for `allUsers`) or with any Google account (for `allAuthenticatedUsers`). Immediate remediation is required.

**Remediation:**
1. Remove the public binding immediately.
2. Audit Vertex AI usage logs for unauthorized calls.
3. Grant access only to specific, authenticated identities.
4. File a support ticket if unauthorized usage is detected.

```bash
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member=allUsers --role=roles/aiplatform.user

gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member=allAuthenticatedUsers --role=roles/aiplatform.user
```

**References:**
- [Vertex AI access control](https://cloud.google.com/vertex-ai/docs/general/access-control)

---

### GEM-022 — Service account with Vertex AI access has user-managed (exportable) keys

**Severity:** HIGH
**Vector:** Gemini Abuse
**Collectors required:** `iam`
**CIS Reference:** —

**What it detects:**
Service accounts that appear in Vertex AI IAM bindings (roles containing `aiplatform`) and also have one or more `USER_MANAGED` keys. This combination means the SA's Vertex AI access can be exercised from outside GCP using the exported key.

**Why it matters:**
A stolen user-managed SA key with Vertex AI access provides persistent, hard-to-revoke access to Gemini models, enabling high-cost abuse from any location. Unlike short-lived tokens, these keys remain valid until explicitly deleted.

**Remediation:**
1. Identify all consumers of the user-managed keys.
2. Migrate consumers to Workload Identity Federation or SA impersonation.
3. Delete the user-managed keys after migration.
4. Enable the org policy `constraints/iam.disableServiceAccountKeyCreation`.

```bash
gcloud iam service-accounts keys list --iam-account=SA_EMAIL

gcloud iam service-accounts keys delete KEY_ID \
  --iam-account=SA_EMAIL
```

**References:**
- [Best practices for managing SA keys](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys)
- [Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)

---

### GEM-023 — roles/aiplatform.user or broader role granted to non-specific principals

**Severity:** HIGH
**Vector:** Gemini Abuse
**Collectors required:** `iam`
**CIS Reference:** —

**What it detects:**
IAM bindings where `roles/aiplatform.user`, `roles/aiplatform.admin`, or `roles/ml.admin` are granted to broad principals: `allUsers`, `allAuthenticatedUsers`, `domain:*`, or `group:*`.

**Why it matters:**
Any member of the broad principal set can call Gemini prediction endpoints, generating potentially unbounded costs. This check specifically targets the roles that allow model invocation (`aiplatform.user`) and administration (`aiplatform.admin`, `ml.admin`).

**Remediation:**
1. Identify which specific identities need Vertex AI access.
2. Remove the broad binding.
3. Grant the role to specific service accounts or users.
4. Consider using IAM Conditions (e.g., resource name conditions).
5. Enable VPC Service Controls to restrict API access by network.

```bash
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member=BROAD_MEMBER --role=roles/aiplatform.user

gcloud projects add-iam-policy-binding PROJECT_ID \
  --member=serviceAccount:SPECIFIC_SA --role=roles/aiplatform.user
```

**References:**
- [Vertex AI access control](https://cloud.google.com/vertex-ai/docs/general/access-control)
- [IAM Conditions overview](https://cloud.google.com/iam/docs/conditions-overview)

---

### GEM-030 — Vertex AI endpoint is publicly accessible (no private network configured)

**Severity:** HIGH
**Vector:** Gemini Abuse
**Collectors required:** `vertex_ai`
**CIS Reference:** —

**What it detects:**
Vertex AI endpoints that have no `network` field configured, meaning the endpoint is reachable over the public internet rather than through a private VPC network.

**Why it matters:**
A publicly accessible Vertex AI endpoint can be targeted by attackers who obtain valid credentials, enabling model abuse without network-level controls. Private endpoints add a defense-in-depth layer that requires network access in addition to valid credentials.

**Remediation:**
1. Determine the VPC network that should access this endpoint.
2. Configure Private Service Connect for the Vertex AI endpoint.
3. Update DNS to resolve the endpoint to the private IP.
4. Remove any public IP access if not required.
5. Validate that internal consumers can reach the endpoint.

```bash
gcloud ai endpoints update ENDPOINT_NAME \
  --region=REGION \
  --network=projects/PROJECT_NUMBER/global/networks/VPC_NAME
```

**References:**
- [VPC peering for Vertex AI](https://cloud.google.com/vertex-ai/docs/general/vpc-peering)
- [Private endpoints for predictions](https://cloud.google.com/vertex-ai/docs/predictions/using-private-endpoints)

---

### GEM-040 — Vertex AI quota is at default high value (no throttling configured)

**Severity:** MEDIUM
**Vector:** Gemini Abuse
**Collectors required:** `quota`
**CIS Reference:** —

**What it detects:**
Vertex AI quota metrics (`aiplatform.*`) where the `effectiveLimit` equals the `defaultLimit` and the effective limit is ≥ 60, indicating no custom quota reduction has been applied.

**Why it matters:**
Without quota reduction, a compromised credential can consume Vertex AI resources up to the default (high) limit before any budget alert fires. Reducing quotas to match expected usage limits the blast radius of a credential compromise.

**Remediation:**
1. Analyze historical Vertex AI usage for this project.
2. Set a quota limit 20–30% above the expected peak usage.
3. Request a quota reduction via the Cloud Console.
4. Set up budget alerts to detect anomalous spend.

```bash
# Quota changes must be made via Cloud Console or Support:
# https://console.cloud.google.com/iam-admin/quotas
```

**References:**
- [View and manage quotas](https://cloud.google.com/docs/quota/view-manage)
- [Vertex AI quotas](https://cloud.google.com/vertex-ai/docs/quotas)

---

### GEM-041 — Gemini API (Generative Language) quota is at default value (no throttling configured)

**Severity:** MEDIUM
**Vector:** Gemini Abuse
**Collectors required:** `quota`
**CIS Reference:** —

**What it detects:**
Generative Language API quota metrics (`generativelanguage.googleapis.com/*`) where the `effectiveLimit` equals the `defaultLimit` and the effective limit is ≥ 60, indicating no custom quota reduction has been applied. Every metric of the service is collected, because the quota ids differ between free and paid tiers and change over time.

**Granularity:** one finding **per project** (`evidence.metrics_at_default` + `metric_examples`), not one per metric. A live project produced 1016 buckets across 56 metrics; per-metric findings buried the whole report under a single check. The signal — "this project has no throttle on the Gemini surface" — is a property of the project.

**Why it matters:**
This is the service that API keys with Gemini access actually call. GEM-040 covers Vertex AI — a different service, with different credentials and a different quota namespace — so an organization that had only GEM-040 could pass the quota requirement of the SOP while leaving the API-key surface completely unthrottled. Combined with an unrestricted key (GEM-001/GEM-002/GEM-006), the default allowance can be consumed by a single actor, and the spend only becomes visible in billing after the fact.

**Relationship to other checks:**
- GEM-040 — Vertex AI (aiplatform) quotas. Same rule, different service.
- GEM-001/GEM-002/GEM-006 — the key-side controls. Those remove the ability to reach the API; this check limits the damage if a key is still valid.
- GEM-051 — budget alerts covering Gemini spend (detection after the fact).

**Remediation:**
1. List the Gemini API quota limits actually in use (`generateContent`, `embedContent`, `countTokens`).
2. Compare the defaults with the expected peak usage of the project.
3. Apply a quota override 20–30% above the expected peak.
4. Keep high-volume keys restricted so a leaked key cannot reach the API at all.
5. Pair with a budget alert covering generative language spend (GEM-051).

```bash
# Inspect current Gemini API quota limits:
gcloud alpha services quota list \
  --service=generativelanguage.googleapis.com \
  --consumer=projects/PROJECT_ID

# Overrides are requested in the Cloud Console or via Support:
# https://console.cloud.google.com/iam-admin/quotas
```

**References:**
- [View and manage quotas](https://cloud.google.com/docs/quota/view-manage)
- [Gemini API rate limits](https://ai.google.dev/gemini-api/docs/rate-limits)

---

### GEM-050 — Org Policy does not restrict API key creation (iam.managed.disableServiceAccountKeyCreation absent)

**Severity:** MEDIUM
**Vector:** Gemini Abuse
**Collectors required:** `org_policy`
**CIS Reference:** —

**What it detects:**
The org policy constraint `constraints/iam.disableServiceAccountKeyCreation` is either absent from the organization or present but has an empty/unconfigured policy. Without this policy, any project owner can create exportable service account keys.

**Why it matters:**
Without this org policy, developers can create user-managed SA keys that, if leaked, provide persistent Vertex AI / Gemini access. This is the preventive control that stops the creation of the credentials that GEM-022 detects.

**Remediation:**
1. Audit existing user-managed SA keys before enforcing the policy.
2. Migrate workloads to Workload Identity Federation.
3. Apply the constraint at the organization level.
4. Use exceptions (folder/project overrides) only where strictly needed.

```bash
gcloud org-policies set-policy policy.yaml \
  --organization=ORG_ID

# policy.yaml:
# name: organizations/ORG_ID/policies/iam.disableServiceAccountKeyCreation
# spec:
#   rules:
#   - enforce: true
```

**References:**
- [Disable SA key creation](https://cloud.google.com/resource-manager/docs/organization-policy/restricting-service-accounts#disable_service_account_key_creation)

---

### GEM-051 — No budget alert configured covering Vertex AI / Gemini spend

**Severity:** HIGH
**Vector:** Gemini Abuse
**Collectors required:** `billing`, `service_usage`
**CIS Reference:** —

**What it detects:**
Projects that have `generativelanguage.googleapis.com` or `aiplatform.googleapis.com` enabled but no budgets configured that cover those services. This check fires when there are no budgets at all, or when existing budgets do not include Vertex AI / Gemini services.

**Why it matters:**
Gemini API abuse can generate significant costs very quickly. Without a budget alert specifically covering Vertex AI / Gemini spend, unauthorized usage can go undetected until the monthly invoice arrives. This is the billing-layer safety net for all other Gemini abuse checks.

**Remediation:**
1. Go to Cloud Console → Billing → Budgets & alerts.
2. Create a budget scoped to Vertex AI and Generative Language services.
3. Set threshold alerts at 50%, 90%, and 100% of expected spend.
4. Configure Pub/Sub notifications for automated response (e.g., disabling the API).

```bash
# Use Cloud Console or Terraform — gcloud CLI has limited budget support.
# Terraform: google_billing_budget resource with services filter.
```

**References:**
- [Cloud Billing budgets](https://cloud.google.com/billing/docs/how-to/budgets)
- [Terraform: google_billing_budget](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/billing_budget)

---

## Common Check Details

### CMN-001 — Billing account has no budget configured

**Severity:** HIGH
**Vector:** Common
**Collectors required:** `billing`
**CIS Reference:** CIS GCP — Cost Management

**What it detects:**
Billing accounts referenced by scanned projects that have no budgets configured at all. The check compares the set of billing accounts linked to projects against the set of billing accounts that have at least one budget.

**Why it matters:**
Without a budget, crypto mining or Gemini API abuse can generate unbounded costs that go undetected until the invoice arrives. Budgets are the foundational cost control mechanism and the last line of defense when all other security controls fail.

**Remediation:**
1. Go to Cloud Console → Billing → Budgets & alerts.
2. Create a budget for the billing account.
3. Set threshold alerts at 50%, 90%, and 100% of budget.
4. Configure email notifications and/or Pub/Sub for automation.
5. Consider separate budgets per project for granular visibility.

```bash
# Use Cloud Console or Terraform — gcloud CLI has limited budget support.
# Terraform: google_billing_budget resource.
```

**References:**
- [Cloud Billing budgets](https://cloud.google.com/billing/docs/how-to/budgets)
- [Terraform: google_billing_budget](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/billing_budget)

---

### CMN-002 — Budget has no threshold alert rules configured

**Severity:** MEDIUM
**Vector:** Common
**Collectors required:** `billing`
**CIS Reference:** —

**What it detects:**
Budgets that exist but have no `thresholdRules` configured. The budget limit is set but no notifications will be sent when spending approaches or exceeds it.

**Why it matters:**
A budget without alert rules is effectively silent — it tracks spend but never notifies anyone. Cost anomalies from crypto mining or Gemini API abuse will not trigger any alert, defeating the purpose of having a budget.

**Remediation:**
1. Go to Cloud Console → Billing → Budgets & alerts.
2. Edit the budget.
3. Add threshold rules at 50%, 90%, and 100% of budget amount.
4. Configure email recipients and/or Pub/Sub topic for alerts.

```bash
# Use Cloud Console or Terraform to add threshold rules.
# Terraform: google_billing_budget.threshold_rules
```

**References:**
- [Add threshold rules to a budget](https://cloud.google.com/billing/docs/how-to/budgets#add-threshold-rules)

---

### CMN-003 — Project has no owner or team label (accountability gap)

**Severity:** LOW
**Vector:** Common
**Collectors required:** `compute`
**CIS Reference:** CIS GCP Foundations — Resource Tagging

**What it detects:**
Projects that have active compute instances but where none of those instances carry an accountability label with keys matching: `owner`, `team`, `contact`, or `responsible`.

**Why it matters:**
Without ownership labels it is impossible to quickly identify who is responsible for resources when an incident occurs. Unowned resources slow incident response, complicate cost attribution, and are more likely to be left misconfigured or abandoned — increasing the attack surface over time.

**Remediation:**
1. Identify the team or individual responsible for each project.
2. Add labels such as `owner`, `team`, and `contact` to all compute instances.
3. Apply the same labels at the project level for inherited visibility.
4. Use an Org Policy or custom constraint to require specific labels on new resources.
5. Integrate label validation into your CI/CD pipeline.

```bash
# Add labels to a compute instance:
gcloud compute instances add-labels INSTANCE_NAME \
  --labels=owner=team-name,contact=team@example.com \
  --zone=ZONE --project=PROJECT_ID

# Add labels to the project itself:
gcloud projects update PROJECT_ID \
  --update-labels=owner=team-name,team=platform
```

**References:**
- [Creating and managing labels](https://cloud.google.com/resource-manager/docs/creating-managing-labels)
- [Org Policy overview](https://cloud.google.com/resource-manager/docs/organization-policy/overview)

---

### CMN-004 — Default Compute Engine service account has user-managed keys

**Severity:** HIGH
**Vector:** Common
**Collectors required:** `iam`
**CIS Reference:** CIS GCP Foundations — 1.4 (Service Account Keys), MITRE ATT&CK — T1552.001

**What it detects:**
The default Compute Engine service account (email ending in `@developer.gserviceaccount.com`) that has one or more `USER_MANAGED` keys. The default SA typically has the Editor role on the project.

**Why it matters:**
User-managed keys for the default Compute SA are a high-value target: they are long-lived, grant Editor-level access, and are frequently committed to source code or embedded in CI/CD pipelines. A compromised key enables crypto mining, data exfiltration, and lateral movement across the entire project.

**Remediation:**
1. Identify all workloads using the default Compute Engine SA.
2. Migrate each workload to a dedicated SA with minimal permissions.
3. For GKE workloads, enable Workload Identity Federation.
4. Delete the user-managed keys from the default SA.
5. Consider disabling the default SA entirely if no workloads require it.
6. Apply the org policy `constraints/iam.disableServiceAccountKeyCreation` to prevent future key creation.

```bash
# List keys for the default SA:
gcloud iam service-accounts keys list \
  --iam-account=SA_EMAIL --project=PROJECT_ID

# Delete a specific user-managed key:
gcloud iam service-accounts keys delete KEY_ID \
  --iam-account=SA_EMAIL --project=PROJECT_ID
```

**References:**
- [Best practices for managing SA keys](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys)
- [Workload Identity for GKE](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)

---

### CMN-005 — Critical org-level security policies are not enforced

**Severity:** MEDIUM
**Vector:** Common
**Collectors required:** `org_policy`
**CIS Reference:** CIS GCP Foundations Benchmark — Section 2 (Org Policies), Google Cloud Security Foundations Guide

**What it detects:**
Organizations where 2 or more of the following critical org policy constraints are not enforced (absent or have an empty policy):
- `constraints/compute.vmExternalIpAccess`
- `constraints/iam.disableServiceAccountKeyCreation`
- `constraints/compute.skipDefaultNetworkCreation`
- `constraints/iam.allowedPolicyMemberDomains`

**Why it matters:**
Without these org policies, individual projects can create resources with external IPs, generate long-lived SA keys, use default networks, and grant access to external identities — all of which are common entry points for crypto mining and data exfiltration attacks. These four constraints form the minimum security baseline recommended by CIS GCP Foundations.

**Remediation:**
1. Review each missing constraint and understand its impact before enforcing.
2. Apply `constraints/compute.vmExternalIpAccess` to restrict external IPs to approved projects/VMs only.
3. Apply `constraints/iam.disableServiceAccountKeyCreation` to prevent creation of long-lived SA keys.
4. Apply `constraints/compute.skipDefaultNetworkCreation` to prevent auto-created default VPCs in new projects.
5. Apply `constraints/iam.allowedPolicyMemberDomains` to restrict IAM bindings to your organization's domain(s).
6. Use dry-run mode (audit) before enforcing to identify existing violations.

```bash
# Disable SA key creation at org level:
gcloud resource-manager org-policies enable-enforce \
  constraints/iam.disableServiceAccountKeyCreation \
  --organization=ORG_ID

# Skip default network creation:
gcloud resource-manager org-policies enable-enforce \
  constraints/compute.skipDefaultNetworkCreation \
  --organization=ORG_ID
```

**References:**
- [Org Policy constraints](https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints)
- [CIS GCP Foundations Benchmark](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)

---

### CMN-006 — Cloud Audit Logs (Data Access) may not be enabled for critical services

**Severity:** MEDIUM
**Vector:** Common
**Collectors required:** `iam`
**CIS Reference:** CIS GCP Foundations — 2.1 (Audit Logging), MITRE ATT&CK — T1562.008

**What it detects:**
Projects that have active compute instances but where `logging.googleapis.com` is not present in the enabled APIs list. Without the Cloud Logging API enabled, Data Access audit logs (DATA_READ, DATA_WRITE) cannot be collected.

**Why it matters:**
Disabled or absent audit logging eliminates the primary forensic trail for detecting crypto mining, credential abuse, and data exfiltration. Incident response becomes guesswork, and compliance requirements (PCI-DSS, ISO 27001, SOC 2) cannot be met. Audit logs are essential for detecting the abuse patterns that all other checks in this scanner identify.

**Remediation:**
1. Enable the Cloud Logging API for the project.
2. Navigate to Cloud Console → IAM & Admin → Audit Logs.
3. Enable DATA_READ and DATA_WRITE audit logs for critical services: `compute.googleapis.com`, `iam.googleapis.com`, `storage.googleapis.com`.
4. Configure log sinks to export audit logs to Cloud Storage or BigQuery for long-term retention.
5. Set up log-based alerts for suspicious patterns (e.g., SA key creation, firewall rule changes, IAM policy modifications).
6. Apply the org policy to enforce audit logging across all projects.

```bash
# Enable the Cloud Logging API:
gcloud services enable logging.googleapis.com --project=PROJECT_ID

# Create a log sink to Cloud Storage for retention:
gcloud logging sinks create audit-sink \
  storage.googleapis.com/BUCKET_NAME \
  --log-filter='logName:cloudaudit.googleapis.com' \
  --project=PROJECT_ID
```

**References:**
- [Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)
- [Configure Data Access audit logs](https://cloud.google.com/logging/docs/audit/configure-data-access)
- [Terraform: google_project_iam_audit_config](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam_audit_config)
