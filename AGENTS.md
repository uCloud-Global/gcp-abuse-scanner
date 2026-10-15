# AGENTS.md

Guidance for AI coding/ops agents working with **gcp-abuse-scanner** — a read-only Python CLI that
scans GCP organizations/projects for misconfigurations exploitable for **crypto mining** and
**Gemini / Vertex AI API abuse**, and emits a prioritized remediation report.

Task-specific playbooks live in [`skills/`](skills/README.md). Load the matching skill before acting:

| You need to… | Skill |
|---|---|
| Prepare a GCP environment (APIs, IAM, impersonation) or debug coverage gaps | [`skills/gcp-abuse-scanner-setup`](skills/gcp-abuse-scanner-setup/SKILL.md) |
| Run a scan (choose scope, flags, output, interpret exit code) | [`skills/gcp-abuse-scanner-scan`](skills/gcp-abuse-scanner-scan/SKILL.md) |
| Analyze a report and build a remediation plan | [`skills/gcp-abuse-scanner-triage`](skills/gcp-abuse-scanner-triage/SKILL.md) |
| Suppress accepted risks / audit the allowlist | [`skills/gcp-abuse-scanner-allowlist`](skills/gcp-abuse-scanner-allowlist/SKILL.md) |
| Run the scanner in CI/CD, Docker, or GitHub code scanning | [`skills/gcp-abuse-scanner-ci`](skills/gcp-abuse-scanner-ci/SKILL.md) |

---

## Ground rules (read these first)

1. **The scanner is read-only; you must stay read-only too.** Reports contain `remediation.gcloud_commands`
   that *modify* resources (delete firewall rules, remove IAM bindings, disable keys). **Never execute
   them** without explicit, per-command human approval. Present them as a plan.
2. **Never create service account keys** to get a scan running. Use `--impersonate-service-account`
   (preferred) or ADC. Never print, commit, or upload key files.
3. **Reports are sensitive** (SA emails, API key UIDs, firewall rules, IAM members). Don't commit them
   (`gcp-scan-*` is gitignored), don't paste them into external services, and quote only what you need.
4. **Don't enable APIs or grant IAM roles on your own.** `scripts/enable_apis.sh` and role grants are
   write operations — run with `--dry-run` first and get approval.
5. **Always parse the JSON file, never stdout.** stdout mixes Rich progress lines with output.
   Use `--format json --output <path>` and read the file.
6. **"No findings" is not "secure" until you check `coverage`.** Collector failures (403, disabled
   APIs, bad credentials) are recorded in the report and the scan can still exit `0`.
7. **Decide with `risk_assessment`, not with the posture score.** The report carries the SOP risk
   level (1–4) plus `auto_approval_eligible`. When `auto_approval_eligible` is `false` — because the
   level is ≥2 *or* because API keys / IAM / network coverage is incomplete — the case goes to human
   review; never approve it, and never suppress a finding to move the level. See
   [`docs/risk-model.md`](docs/risk-model.md).

---

## CLI quick reference (verified on `main`; notes marked ≤0.1.5 apply to the current PyPI release)

```
gcp-abuse-scanner scan        # run a scan
gcp-abuse-scanner list-checks [--vector crypto_mining|gemini_abuse|common]
gcp-abuse-scanner version
```

`scan` options:

| Flag | Notes |
|---|---|
| `--org/-o ORG_ID` | Digits only — validated up front (non-numeric → usage error, exit 2, before any I/O). Enumerates ACTIVE projects via Cloud Asset Inventory. **If set, `--project` is ignored.** |
| `--project/-p ID` | Repeatable. Not validated — a typo just shows up as an inaccessible/empty project. |
| `--exclude-project ID` | Repeatable. Applied after org enumeration. |
| `--impersonate-service-account EMAIL` | Preferred auth. Caller needs `roles/iam.serviceAccountTokenCreator` on the SA. |
| `--service-account-key PATH` | Also read from `GOOGLE_APPLICATION_CREDENTIALS`. Discouraged. If the env var points to user ADC or a WIF config, it is used via ADC; a non-key file passed explicitly fails fast (exit 1). **≤0.1.5: such files make every collector fail** — use `--impersonate-service-account`. |
| `--format/-f` | `console` (default) · `json` · `markdown` · `html` · `sarif` · `all` |
| `--output PATH` | File path for non-console formats. Missing parent directories are created. Ignored with `--format console` (warning). **Do not combine with `--format all`** (every format overwrites the same path — the CLI warns). |
| `--vector V` | Repeatable: `crypto_mining`, `gemini_abuse`, `common`. Invalid values are rejected up front (usage error, exit 2). **≤0.1.5: an invalid value crashes after collection.** |
| `--allowlist PATH` | YAML list of rules, top-level or under an `allowlist:` key; validated before collection (exit 1 if malformed, or if the path is a directory). A missing file only prints a warning; an unreadable existing file is rejected by the CLI layer (exit 2). **≤0.1.5: only the top-level list works** — see allowlist skill. |
| `--dry-run` | Resolves scope and lists all checks; no collection. With `--project` it needs no credentials. |
| `--cache/--no-cache`, `--cache-ttl SECONDS` | Gzip inventory cache in `~/.cache/gcp-abuse-scanner/` (default off, TTL 3600). Use `--no-cache` when verifying a fix. |
| `--verbose/-v` | Debug logs (noisy). Prefer reading `coverage` in the JSON report. |
| `--transport` | `requests` (default) or `httplib2` (legacy). An unknown value is a usage error (exit 2) — a typo would otherwise fail every discovery client and *still* exit 0 with an empty report. Env: `GCP_ABUSE_SCANNER_TRANSPORT`. |
| `--request-timeout SECONDS` | Timeout per GCP API request (default 30, `0` = no timeout). `httplib2` cannot take a per-request timeout, which is why `requests` is the default. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, no active CRITICAL findings (also: empty scope, dry-run). |
| `1` | No scope given, scope resolution failed, credentials could not be loaded, malformed allowlist, or an unhandled error. |
| `2` | Scan completed **and** ≥1 active (non-suppressed) CRITICAL finding — report was written. **Also** used for usage errors: unknown flag/command, bad `--format`/`--vector`/`--transport`, non-numeric `--org`, empty `--project`, negative `--request-timeout`/`--cache-ttl`, unreadable `--allowlist`. Disambiguate by checking that the report file exists. |

### Canonical agent invocation

```bash
gcp-abuse-scanner scan --project my-proj \
  --impersonate-service-account scanner@scanner-proj.iam.gserviceaccount.com \
  --format json --output /tmp/scan.json ; echo "exit=$?"
python skills/gcp-abuse-scanner-triage/scripts/summarize_report.py /tmp/scan.json
jq '.risk_assessment | {level, label, auto_approval_eligible, blockers: .auto_approval_blockers}' /tmp/scan.json
```

Org scans can take many minutes (12 collectors × N projects); run them in the background with a generous timeout.

---

## Report model (JSON)

Top-level keys: `metadata`, `executive_summary`, `coverage`, `findings[]`, `risk_assessment`.

- `executive_summary`: `posture_score` (0–100, **scope-normalized and floored at 0** — one CRITICAL is already `0.0` on a single-project scan, so never read it alone), `penalty_points` (raw severity sum, scope-independent — the metric for comparing two scans), `total_findings` (active only), `by_severity`, `by_vector[]`, `top_findings[]` (top 10).
- `risk_assessment`: **the SOP decision**. `level` (1–4), `label`, `rationale`, `triggering_check_ids[]`, `triggers[]`, `coverage_complete`, `coverage_gaps[]` (`domain`, `reason`, `projects`, `missing_apis`, `collectors`, `affected_checks`), `auto_approval_eligible`, `auto_approval_blockers[]`.
- `coverage`: `projects_scanned`, `inaccessible_project_ids`, `checks_*` counters, `checks_not_applicable_ids[]`, `checks_errored_ids[]`, `skipped_apis_by_project`, `unreadable_budget_accounts[]`, `collector_errors[]`. **Always check coverage before claiming a project is clean** — a disabled API or 403 produces *no findings*, not a pass.
- `findings[]`: `finding_id`, `check_id`, `vector`, `severity`, `priority_rank` (1 = fix first; `null` if suppressed), `exploitability_score`, `blast_radius`, `resource{project_id,resource_type,resource_id}`, `evidence`, `description`, `impact`, `remediation{summary,steps,gcloud_commands,iac_reference,docs,effort}`, `suppressed`, `suppression_reason`. Suppressed findings are included (with `suppressed: true`).
- Known quirk: `metadata.tool_version` is always `"0.1.0"`; use `gcp-abuse-scanner version` instead.

Checks: 50 total (27 `CM-*`, 17 `GEM-*`, 6 `CMN-*`). Source of truth: `gcp-abuse-scanner list-checks`;
details in [`docs/checks/`](docs/checks/).

---

## Working on the codebase

```bash
pip install -e ".[dev]"          # Python ≥ 3.11
pytest                           # offline tests, < 2s, no GCP calls
ruff check gcp_abuse_scanner tests && black --check gcp_abuse_scanner tests && mypy gcp_abuse_scanner
```

Pipeline: `cli.py` → `auth/` (AuthManager, ScopeResolver) → `collectors/engine.py` (ServiceUsage first,
then 11 collectors concurrently, 12 in total) → `checks/` (auto-registered via `@CheckRegistry.register`) →
`scoring/engine.py` (allowlist, priority rank, posture score) → `scoring/risk.py` (SOP level 1–4 +
coverage gate) → `reporters/`. See [`docs/architecture.md`](docs/architecture.md) and
[`docs/risk-model.md`](docs/risk-model.md).

Invariants:
- Checks **never** call GCP APIs — they only read `ResourceInventory`. Collectors never evaluate posture.
- Collectors fail open: record into `inventory.collector_errors` / `skipped_apis` and continue.
- No GCP write calls anywhere. Tests use fixtures in `tests/fixtures/` and mocks only.
- New check = file under `checks/<vector>/`, unique never-reused `check_id`, FAIL + PASS tests,
  entry in `docs/checks/<vector>.md`, remediation with summary + step + gcloud/IaC. See
  [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Version lives only in `pyproject.toml`; update `CHANGELOG.md` for user-visible changes.
- Line length 100 (ruff + black).

Offline end-to-end run against a fixture (no credentials) — useful to test reporters/allowlist changes:
see `skills/gcp-abuse-scanner-scan/scripts/offline_scan.py`.
