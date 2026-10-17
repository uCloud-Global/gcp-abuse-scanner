---
name: gcp-abuse-scanner-scan
description: Run gcp-abuse-scanner against a GCP organization or projects — choose scope, vectors, auth, output format and cache, run it safely (long-running, read-only), and interpret exit codes and coverage. Use whenever asked to scan, audit, or check GCP for crypto-mining or Gemini/Vertex AI abuse risks, or to re-scan after a fix.
---

# Running a scan

## Decision checklist (before running)

1. **Scope** — exactly one of:
   - `--org ORG_ID` (digits only) → all ACTIVE projects via Cloud Asset Inventory. Add `--exclude-project` as needed.
     If you also pass `--project`, it is **ignored**.
   - `--project ID` (repeatable) → only those projects. IDs are not validated; double-check spelling.
   - Unsure what's in scope? `--dry-run` resolves scope and exits (with `--project` it needs no credentials).
2. **Auth** — prefer `--impersonate-service-account SA_EMAIL`. If `GOOGLE_APPLICATION_CREDENTIALS`
   is set to something that isn't an SA key, impersonation is mandatory (see setup skill).
3. **Vectors** — default is all three. Restrict with repeatable `--vector crypto_mining|gemini_abuse|common`.
   Invalid values are rejected immediately (exit 2). On ≤0.1.5 they crash *after* collection — validate first.
4. **Output** — for agents always `--format json --output <path>`. Add other formats with separate
   runs or `--format all` **without** `--output` (auto-named `gcp-scan-<id8>.{json,md,html,sarif}` in CWD).
5. **Allowlist** — `--allowlist FILE` if the user maintains one. Verify the file exists (missing = only a
   warning) and lint it first: `python skills/gcp-abuse-scanner-allowlist/scripts/validate_allowlist.py FILE`.
6. **Cache** — `--cache` reuses inventory for the same scope for `--cache-ttl` seconds (default 3600).
   Use it when iterating on allowlist/report formats; **never** when verifying a remediation.

If not obvious from the request, ask the user for scope and the SA to impersonate — don't guess an org ID.

## Run

```bash
OUT="${TMPDIR:-/tmp}/gcp-scan-$(date +%Y%m%d-%H%M%S).json"
gcp-abuse-scanner scan --project PROJECT_A --project PROJECT_B \
  --impersonate-service-account SA_EMAIL \
  --format json --output "$OUT"
echo "exit=$?"
```

- Org-wide scans can take a long time (12 collectors, retries with backoff up to ~30s per call).
  Run in the background / with a long timeout; don't kill and restart.
- Don't use `--verbose` by default — it floods context. Use the JSON `coverage` section instead.

## Interpret the result

| Exit | Report written? | Meaning / next step |
|---|---|---|
| 0 | yes (unless empty scope / dry-run) | Done, no active CRITICAL. **Still check coverage.** |
| 2 | yes | Done, ≥1 active CRITICAL finding → go to triage skill. |
| 2 | **no** | Usage error: unknown flag/command, bad `--format`/`--vector`/`--transport`, non-numeric `--org`, empty `--project`, negative `--request-timeout`/`--cache-ttl`, unreadable `--allowlist`. Read stderr, fix the command. |
| 1 | no | No scope, scope resolution failed (Cloud Asset / permissions), credentials failed to load, malformed allowlist. Read stderr. |

Then summarize:

```bash
python skills/gcp-abuse-scanner-triage/scripts/summarize_report.py "$OUT"
```

Before reporting "clean", confirm: `coverage.projects_scanned` matches expectation,
`inaccessible_project_ids` is empty, `collector_errors` is empty, and `skipped_apis_by_project`
only lists services the user doesn't use.

The report also carries the SOP decision object — read it instead of guessing from severities:

```bash
jq '.risk_assessment | {level, label, auto_approval_eligible, blockers: .auto_approval_blockers}' "$OUT"
```

`auto_approval_eligible: false` means either the level is ≥2 or a sensitive domain (API keys, IAM,
network, compute, quota) could not be read. A scan that exits `0` with an incomplete
`risk_assessment` is **not** a clean scan — it is an undetermined one. See
[`docs/risk-model.md`](../../docs/risk-model.md).

## Common recipes

```bash
# Inventory of checks (no GCP access)
gcp-abuse-scanner list-checks --vector gemini_abuse

# Gemini/Vertex exposure only, whole org minus sandboxes
gcp-abuse-scanner scan --org 123456789012 --exclude-project sandbox-1 \
  --vector gemini_abuse --impersonate-service-account "$SA" --format json --output gem.json

# Assessment BEFORE the billing transfer (budgets are unreadable until then)
gcp-abuse-scanner scan --project client-proj --impersonate-service-account "$SA" \
  --allowlist examples/allowlist-pre-transfer.yaml --format json --output pre.json

# Verify a fix: same scope, no cache, then diff against the previous report
gcp-abuse-scanner scan --project my-proj --impersonate-service-account "$SA" \
  --no-cache --format json --output after.json
python skills/gcp-abuse-scanner-triage/scripts/diff_reports.py before.json after.json

# Human-friendly deliverable for stakeholders
gcp-abuse-scanner scan --project my-proj --impersonate-service-account "$SA" \
  --format html --output report.html
```

## Offline run (no GCP, no credentials)

To demo the CLI, test allowlists, or develop reporters, run the real pipeline against a fixture
inventory (collectors are mocked; checks, scoring and reporters are real):

```bash
python skills/gcp-abuse-scanner-scan/scripts/offline_scan.py \
  tests/fixtures/inventory_crypto_mining.json -- --format json --output /tmp/offline.json
```

Requires the package importable (`pip install -e .`). Fixtures: `tests/fixtures/inventory_*.json`;
any `ResourceInventory`-shaped JSON works, including a cached inventory decompressed from
`~/.cache/gcp-abuse-scanner/*.inventory.json.gz` (use its `inventory` key).
