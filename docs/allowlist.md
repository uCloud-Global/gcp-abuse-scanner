# Allowlist Reference

The allowlist lets you suppress findings that are **known exceptions** or **accepted risks** — false positives that you've reviewed and decided not to fix. Suppressed findings still appear in reports (marked as suppressed) but don't affect the posture score or exit code. They **do** count for the SOP risk level: suppression never lowers it, so an allowlist can't reach level 1 ([`risk-model.md`](risk-model.md) §5).

---

## Format

The allowlist is a YAML file containing a list of suppression rules. Pass it to the scanner with `--allowlist`:

```bash
gcp-abuse-scanner scan --org 123456789012 --allowlist allowlist.yaml
```

Each rule is a mapping with one or more of these fields:

| Field | Type | Description |
|---|---|---|
| `check_id` | `string` | Check ID to suppress (e.g. `CM-001`). Omit to match all checks. |
| `project_id` | `string` | Exact GCP project ID. Omit to match all projects. |
| `resource_id` | `string` | Substring match against the finding's `resource_id`. Omit to match all resources. |
| `reason` | `string` | **Required for auditing.** Human-readable justification. Stored in the report. |

A rule suppresses a finding when **all specified fields match**. Fields that are omitted match everything (wildcard).

---

## Examples

### Suppress a specific check in a specific project

```yaml
allowlist:
  - check_id: CM-001
    project_id: my-legacy-project
    reason: "External IP required for on-prem VPN — reviewed 2024-01-15 by @security-team"
```

### Suppress a specific resource across all projects

```yaml
allowlist:
  - check_id: CM-009
    resource_id: "instances/bastion-host"
    reason: "Bastion host — Shielded VM not compatible with this OS image (CentOS 6)"
```

### Suppress a check across the entire organization

```yaml
allowlist:
  - check_id: GEM-040
    reason: "Vertex AI quotas managed separately via quota increase requests — not a risk"
```

### Suppress all checks in a sandbox project

```yaml
allowlist:
  - project_id: dev-sandbox-123
    reason: "Sandbox project — all risks accepted, no production data"
```

### Multiple rules

```yaml
allowlist:
  # VPN gateway needs external IP
  - check_id: CM-001
    project_id: networking-prod
    resource_id: "instances/vpn-gateway"
    reason: "VPN gateway — external IP required. Reviewed 2024-03-01."

  # Legacy API key used by third-party integration
  - check_id: GEM-001
    project_id: integrations-prod
    reason: "Legacy API key for Vendor X integration — migration planned Q3 2024"

  # Bastion host in all environments
  - check_id: CM-009
    resource_id: "instances/bastion"
    reason: "Bastion hosts use a custom image incompatible with Shielded VM"
```

---

## Matching logic

Rules use **AND logic** across fields and **OR logic** across rules:

```
finding is suppressed if:
  ANY rule matches, where a rule matches if:
    (check_id is absent OR check_id == finding.check_id)
    AND (project_id is absent OR project_id == finding.resource.project_id)
    AND (resource_id is absent OR resource_id IN finding.resource.resource_id)
```

The `resource_id` field uses **substring matching** — you don't need to provide the full resource path. For example, `"instances/bastion"` matches `"projects/my-proj/zones/us-central1-a/instances/bastion-host"`.

---

## Suppressed findings in reports

Suppressed findings are **always included** in reports — they are never silently dropped. In each format:

- **Console**: shown in a separate "Suppressed" section at the bottom
- **JSON**: included with `"suppressed": true` and `"suppression_reason": "..."`
- **Markdown / HTML**: shown in a collapsed suppressed findings table
- **SARIF**: excluded from `results[]` (SARIF convention for suppressed findings)

---

## Pre-transfer assessment (billing checks)

Budgets live on the **billing account**. During the assessment that runs *before* the billing
transfer, the project still belongs to the client's billing account, which the scanner identity
cannot read — so CMN-001, CMN-002, CM-060 and GEM-051 either report "no budget" or get skipped, and
both outcomes distort the result.

Use the ready-made allowlist for that phase:

```bash
gcp-abuse-scanner scan --project CLIENT_PROJECT \
  --impersonate-service-account scanner@scanner-proj.iam.gserviceaccount.com \
  --allowlist examples/allowlist-pre-transfer.yaml \
  --format json --output pre-transfer.json
```

**It expires with the transfer.** Re-run without the allowlist afterwards to verify that the alarm
package actually got deployed. Full rationale in [`docs/risk-model.md`](risk-model.md) §5.

**It does not buy auto-approval.** Suppressed findings still count for the risk level, so a scan
run with this file reads as level 2 whenever a suppressed `CMN-001` (HIGH) is present and is never
auto-approved — take it through human review ([`risk-model.md`](risk-model.md) §4) with a written
note that the budgets were unobservable pre-transfer.

---

## Best practices

1. **Always include a `reason`**. The reason is stored in the report and is essential for audit trails.
2. **Be as specific as possible**. Prefer `check_id + project_id + resource_id` over broad rules that suppress entire projects.
3. **Include a review date** in the reason. Example: `"Reviewed 2024-01-15 — re-evaluate Q2 2024"`.
4. **Version-control your allowlist**. Treat it like code — require PR review for changes.
5. **Avoid suppressing CRITICAL findings** without explicit sign-off from your security team.
6. **Audit quarterly**. Run `gcp-abuse-scanner list-checks` and compare against your allowlist to find stale rules.

---

## Full schema reference

```yaml
# allowlist.yaml
allowlist:
  - check_id: string          # optional — check ID (e.g. "CM-001", "GEM-021")
    project_id: string        # optional — exact project ID
    resource_id: string       # optional — substring of resource_id
    reason: string            # recommended — justification for suppression
```

All fields are optional, but a rule with no fields would suppress **every finding** — avoid this.

---

## Integrating with CI/CD

You can maintain environment-specific allowlists and pass them in your pipeline:

```bash
# In CI, use the production allowlist
gcp-abuse-scanner scan \
  --org "${GCP_ORG_ID}" \
  --impersonate-service-account "${SCANNER_SA}" \
  --allowlist allowlists/production.yaml \
  --format sarif \
  --output results.sarif
```

For GitHub Advanced Security, upload the SARIF output:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```
