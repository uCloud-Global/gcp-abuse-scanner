# Changelog

All notable changes to `gcp-abuse-scanner` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Removed the Codecov badge from the README: it has never shown data (`unknown` for both the
  organization and the previous personal slug — the workflow has no `CODECOV_TOKEN`, and the
  upload action does not fail CI, so it silently reported nothing). Coverage stays visible in
  the CI log and in `docs/coverage.md`; re-enable Codecov only with a token and a coverage gate.



### Added
- `AGENTS.md` and `skills/` — guidance and helper scripts for AI agents using the CLI.
- **`risk_assessment` in every report** — the SOP risk score (1–4) plus a coverage gate, so the same
  report always maps to the same level: 4 = unrestricted Gemini API key (`GEM-001`/`GEM-002`/`GEM-006`)
  or public access (`CM-043`/`GEM-021`); 3 = any other CRITICAL; 2 = HIGH without CRITICAL; 1 = only
  MEDIUM/LOW. `coverage_complete` / `auto_approval_eligible` are `false` whenever API keys, IAM or
  network input could not be read, so an incomplete scan is never approved automatically. Rendered in
  console/markdown/HTML and summarized by the triage script. Rule + decision table:
  [`docs/risk-model.md`](docs/risk-model.md).
- **`CM-046`** CRITICAL — personal (consumer email) account holds Owner or Editor. Consumer domains
  only; external corporate domains need Cloud Identity and stay a manual review step.
- **`GEM-041`** MEDIUM — Gemini API (Generative Language) quota is at its default value. `GEM-040`
  covered Vertex AI only, so the surface that API keys actually call had no quota check.
- **`CM-008`** CRITICAL — firewall allows MySQL/PostgreSQL (3306/5432) from `0.0.0.0/0` (previously
  present in the code but untested and undocumented).
- `examples/allowlist-pre-transfer.yaml` — sanctioned suppression of the four budget checks
  (`CMN-001`, `CMN-002`, `CM-060`, `GEM-051`) for the assessment that runs before the billing transfer,
  with its own expiry instruction.
- `preflight.sh --coverage` — one read-only probe per collector that prints which checks would be
  silently empty with the current roles (answers "does Viewer + Security Reviewer cover this?").
- `checks_not_applicable_ids` and `checks_errored_ids` in `coverage`, and a `CONTRIBUTING.md` release
  section documenting the org-owned publishing setup.
- **`--transport requests|httplib2` and `--request-timeout SECONDS`** (env: `GCP_ABUSE_SCANNER_TRANSPORT`).
  Discovery-based collectors now talk HTTP through `requests` with an explicit per-request timeout
  (default 30 s) instead of `httplib2`, which takes its timeout when the client is built and can
  therefore hang a scan indefinitely on a stalled socket; `--transport httplib2` keeps the legacy
  path. An invalid transport name is rejected before collection (exit 2) instead of failing every
  collector silently.
- Tests for the transport layer (`tests/unit/test_transport.py`) and for the CLI flags.
- **`executive_summary.penalty_points`** — the raw severity sum (CRITICAL 10, HIGH 5, MEDIUM 2,
  LOW 0.5) with no scope normalization and no floor. Added because `posture_score` is normalized by
  project count and floors at 0: a live single-project scan with 18 findings computed a raw
  `−750` and reported `0.0`, the same value a single CRITICAL would produce. `penalty_points` is
  what to compare across scans. Documented in `docs/risk-model.md` (§ "The posture score is not a
  decision metric"), README, AGENTS.md, `docs/architecture.md` and the triage skill.

### Changed
- **Repository moved to the `uCloud-Global` organization**: `pyproject.toml` URLs, README badges and
  Docker examples, `Dockerfile` labels, `SECURITY.md`, `CONTRIBUTING.md`, SARIF `informationUri` /
  `helpUri` and the setup/CI skills now point to `github.com/uCloud-Global/gcp-abuse-scanner` and
  `ghcr.io/ucloud-global/gcp-abuse-scanner`. Release artifacts are published only from the org
  repository (see `CONTRIBUTING.md` → Releasing).
- `AGENTS.md`/`README.md` check counts corrected to the real registry (50 checks: 27 `CM-*`,
  17 `GEM-*`, 6 `CMN-*`); `~65+` and `47` were both wrong.
- **Pre-commit mirrors CI** (`.pre-commit-config.yaml`): `ruff-format` was removed — ruff's formatter and
  black disagree in both directions (verified with ruff 0.17 / black 26.10.1), so a config with both never
  converges — and the `ruff`/`black` pins were bumped to the versions CI resolves from `pyproject.toml`.
  `detect-private-key` no longer fails on the fake PEM fixture in `tests/unit/test_auth.py`.
- Every discovery collector built its own `googleapiclient.discovery.build(...)` call and logged a
  build failure locally; they now share `BaseCollector.build_client()`, which uses the transport above
  and records the failure in `collector_errors` so the coverage gate can block approval.
- Allowlist docs now cover the pre-transfer budget case (and warn that a suppression changes the risk
  level, so it must never be used to reach level 1).

### Fixed
- **Budget findings asserted on unreadable data** (found by a live scan): when the Cloud Billing
  Budget API is disabled — the common case, since it lives in the *scanner* project — `BillingCollector`
  only logged a warning, so `CMN-001`, `CM-060` and `GEM-051` reported "no budget configured" for
  accounts nobody could read, with no coverage gap recorded. The collector now records
  `inventory.budgets_unreadable` (surfaced as `coverage.unreadable_budget_accounts`) plus a collector
  error, and the four budget checks report nothing about those accounts.
- **`GEM-041` produced 1016 findings on a single project** (56 Generative Language metrics × their
  free/paid buckets, one finding each), burying the report and the priority ranking. `GEM-040` and
  `GEM-041` now emit **one finding per project** with `metrics_at_default` + `metric_examples`.
  Same live scan: 1036 findings → 21.
- **CLI robustness pass** — invalid input now fails as a *usage error* (exit 2, no work done) instead of
  surfacing later as a cryptic failure or, worse, as a scan that "succeeds" while every collector records
  a coverage gap: non-numeric `--org`, empty `--project`, negative `--request-timeout`, negative
  `--cache-ttl`. `--output` now creates missing parent directories and reports an unwritable path cleanly
  (exit 1) instead of raising `FileNotFoundError`; `--allowlist` pointing at a directory is rejected with
  a clear message (exit 1); `--format all` with `--output` and `--format console` with `--output` warn
  instead of silently ignoring/overwriting. 24 new CLI edge-case tests
  (`tests/unit/test_cli.py::TestScanRobustness`) take `cli.py` from 94% to 99% coverage
  (the only uncovered line is the `__main__` guard), including the two paths that feed the
  coverage gate: a check that is NOT_APPLICABLE and a check that raises.
- **Collectors skipped data without recording it**: `APIKeysCollector` swallowed `403`/`404` (API not
  enabled) and `NetworkCollector` silently skipped projects without the Compute API, so those checks
  returned no findings and the scan exited `0`. Both now record the gap via
  `record_skipped_api()` / `record_collector_error()` (applied to compute, GKE, Cloud Run, Vertex AI
  and Recommender too), which is what the coverage gate reads.
- `QuotaCollector` ignored the Gemini API (Generative Language) quotas entirely; it now collects them
  with a wildcard target since the metric ids differ between free and paid tiers.
- **Service-account collection failures were invisible**: a per-project failure in
  `IAMCollector._collect_service_accounts()` only logged a warning, so `CM-041`/`CMN-004` reported
  nothing for that project with no coverage gap recorded. It now records `iam.googleapis.com` as skipped.
- **`--transport httplib2` without credentials**: `AuthorizedHttp(None)` built successfully and then raised
  `AttributeError: 'NoneType' object has no attribute 'before_request'` on *every* request. The anonymous
  case now returns an unwrapped client, matching the `requests` branch.
- **Documented allowlist format crashed the scan**: an allowlist using the `allowlist:` key (as in `docs/allowlist.md` and `examples/config.example.yaml`) raised `AttributeError` in the scoring engine after the full collection phase. Both a top-level list and the `allowlist:` mapping are now accepted via `load_allowlist()`, and malformed files are rejected before collection (exit 1). A missing allowlist file now prints a warning instead of being silently ignored.
- **Non-key files in `GOOGLE_APPLICATION_CREDENTIALS` broke every collector**: the variable is bound to `--service-account-key`, so user ADC (`authorized_user`) or Workload Identity Federation (`external_account`) configs were parsed as SA keys and every collector failed, producing an empty report with exit 0. Such files are now resolved through ADC; a non-key file passed explicitly raises a clear `AuthError`. Credentials are now resolved before collection, so auth failures abort with exit 1.
- **Invalid `--vector` crashed after collection**: `--vector` (on `scan` and `list-checks`) is now an enum validated by Typer before any work (usage error, exit 2).

## [0.1.4] - 2026-07-17

### Added
- `docs/apis.md`: complete reference of all 12 GCP APIs the scanner uses, per-collector breakdown, collector→API→checks dependency map, and minimum/recommended/full coverage tiers.
- `scripts/enable_apis.sh`: interactive bash script (bash 3.2+ / macOS compatible) to enable all required APIs across an org or explicit project list. Supports `--dry-run`, `--parallel`, `--skip-org-apis`, `--skip-project-apis`.

### Changed
- `docs/iam-setup.md`: added Step 0 with manual and script-based API setup instructions before IAM role assignment.
- `README.md`: added Prerequisites section with quick-setup commands and link to `docs/apis.md`.

## [0.1.3] - 2026-07-17

### Fixed
- **CM-002 crash on real org scans**: `_org_policy_is_restricted()` called `.upper()` on `denyAll`/`allowAll` fields that the Org Policy REST v2 API returns as native Python booleans, not strings. Fixed to handle both `bool` and `str` representations.

## [0.1.2] - 2026-07-17

### Fixed
- **API Keys checks (GEM-001 to GEM-004) were silently skipped** in most real projects. Root cause: `required_apis = ["apikeys.googleapis.com"]` caused `is_applicable()` to return `False` when that API was not listed in the ServiceUsage response — even though API keys exist independently of whether the API Keys API is explicitly enabled. Removed `required_apis` from GEM-001, GEM-002, and GEM-003 (GEM-004 was already unaffected).
- **`APIKeysCollector` was also skipping projects** via the same `is_api_enabled()` guard. The collector now always attempts collection. HTTP 403/404 responses (API not enabled or no permission) are logged at DEBUG level instead of WARNING, keeping logs clean while still collecting keys when accessible.
- Added 5 new tests covering: collection without `apikeys.googleapis.com` in enabled_apis, collection with it present, 403 is silent, 500 is a warning, and `GEM-001.is_applicable()` returns `True` without the API in enabled_apis.

## [0.1.1] - 2026-07-17

### Fixed
- Suppressed noisy `googleapiclient` internal log messages (`Encountered 403 Forbidden with reason "PERMISSION_DENIED"`) that appeared before each collector's own contextual warning. These are now silenced at `CRITICAL` level (downgraded to `ERROR` in `--verbose` mode).
- Collector error messages now show a concise one-line summary instead of dumping the full JSON response body. Example: `GKE collection failed for my-proj: HTTP 403: This API method requires billing to be enabled` instead of a multi-line `<HttpError 403 when requesting ... details: [{'@type': ...}]>`.
- Added `_fmt_exc()` helper in `collectors/base.py` with 17 unit tests covering `HttpError` formatting, generic exceptions, truncation, and collector integration.

## [0.1.0] - 2026-07-17

### Added

#### Core framework
- Project scaffold: `pyproject.toml`, `hatchling` build, `ruff`/`black`/`mypy` toolchain
- Core models: `Finding`, `ResourceInventory`, `ScanReport`, `ScanMetadata`, `ExecutiveSummary`
- Auth layer: `AuthManager` (key file + impersonation), `ScopeResolver` (org → project list)
- CLI: `scan`, `list-checks`, `version` commands via `typer`; `--format`, `--vector`, `--allowlist`, `--dry-run`, `--cache/--no-cache`, `--cache-ttl` options
- Base check/collector plugin framework with auto-registration via `CheckRegistry`
- Scoring engine: priority ranking, CVSS-inspired exploitability score, allowlist suppression

#### Collectors (11 total)
- `ComputeCollector`, `IAMCollector`, `NetworkCollector`, `ServiceUsageCollector`, `APIKeysCollector`, `BillingCollector`
- `GKECollector`, `CloudRunCollector`, `VertexAICollector`, `OrgPolicyCollector`, `RecommenderCollector`, `QuotaCollector`
- `CollectorEngine`: concurrent collection with `tenacity` retry/backoff
- `InventoryCache`: gzip-compressed JSON cache with SHA256 key and configurable TTL

#### Crypto Mining checks (25)
- **CM-001** HIGH — VM instances with external IP addresses
- **CM-002** MEDIUM — VM instances without OS Login enabled
- **CM-003** MEDIUM — VM instances with serial port access enabled
- **CM-004** CRITICAL — Firewall allows SSH/RDP from 0.0.0.0/0
- **CM-005** HIGH — Firewall allows all ingress traffic (0.0.0.0/0 any port)
- **CM-006** MEDIUM — Default network exists in project
- **CM-007** HIGH — VM instance running as default Compute service account
- **CM-009** MEDIUM — Shielded VM not enabled
- **CM-011** HIGH — VM instance with full cloud-platform OAuth scope
- **CM-020** HIGH — GKE node pools with unbounded autoscaling
- **CM-021** MEDIUM — GKE cluster without Workload Identity
- **CM-023** HIGH — GKE cluster with public endpoint and no authorized networks
- **CM-024** MEDIUM — GKE cluster without network policy
- **CM-025** MEDIUM — GKE node pool without auto-upgrade
- **CM-026** MEDIUM — GKE cluster with legacy ABAC enabled
- **CM-030** HIGH — Cloud Run service with public invoker (allUsers)
- **CM-031** MEDIUM — Cloud Run service with no CPU/memory limits
- **CM-040** HIGH — Service account with Compute Admin role granted broadly
- **CM-041** HIGH — Service account with user-managed (exported) keys
- **CM-042** HIGH — Overly permissive custom role (compute.instances.create + iam.serviceAccounts.actAs)
- **CM-043** CRITICAL — IAM binding grants allUsers/allAuthenticatedUsers
- **CM-044** HIGH — Default Compute SA has Editor/Owner role
- **CM-045** HIGH — Service account key older than 90 days
- **CM-050** HIGH — Workload Identity not used (SA key attached to GKE workload)
- **CM-060** MEDIUM — IAM recommender: unused permissions on SA

#### Gemini API Abuse checks (16)
- **GEM-001** CRITICAL — API key has no API restrictions
- **GEM-002** CRITICAL — API key has no application restrictions
- **GEM-003** HIGH — API key targets Gemini API without app restrictions
- **GEM-004** HIGH — API key not rotated in 90+ days
- **GEM-005** MEDIUM — API key with no expiry date
- **GEM-006** HIGH — Multiple Gemini-enabled API keys in project
- **GEM-010** HIGH — Gemini API enabled but no VPC Service Controls perimeter
- **GEM-011** MEDIUM — Gemini API enabled but no org policy restricting API key creation
- **GEM-020** HIGH — Vertex AI role granted to broad principal (domain/group)
- **GEM-021** CRITICAL — Vertex AI role granted to allUsers/allAuthenticatedUsers
- **GEM-022** HIGH — Vertex AI User role granted at project level (not resource level)
- **GEM-023** MEDIUM — External identity (gmail.com) has Vertex AI role
- **GEM-030** HIGH — Vertex AI endpoint accessible without private endpoint
- **GEM-040** MEDIUM — Vertex AI quotas at default (high) values
- **GEM-050** HIGH — No budget alert covering Vertex AI/Gemini spend
- **GEM-051** HIGH — No budget covering Vertex AI/Gemini spend at all

#### Common checks (6)
- **CMN-001** HIGH — Billing account has no budget configured
- **CMN-002** MEDIUM — Budget exists but has no threshold alert rules
- **CMN-003** HIGH — Cloud Audit Logs (Data Access) not enabled for critical services
- **CMN-004** MEDIUM — Audit log sink not configured (no log export)
- **CMN-005** MEDIUM — Key org policy constraints absent (domain restriction, resource location)
- **CMN-006** MEDIUM — Cloud Audit Logs (Data Access) disabled for all services

#### Reporters (5)
- `ConsoleReporter` — rich terminal output with severity-colored tables
- `JSONReporter` — machine-readable structured JSON
- `MarkdownReporter` — GitHub-flavored Markdown with summary tables
- `HTMLReporter` — self-contained HTML with Jinja2 template, severity badges, remediation accordion
- `SARIFReporter` — SARIF 2.1.0 for GitHub Advanced Security, VS Code, and SAST tooling

#### Documentation
- `docs/checks/crypto_mining.md` — 25 checks with full detail blocks
- `docs/checks/gemini_abuse.md` — 16 GEM + 6 CMN checks documented
- `docs/iam-setup.md` — step-by-step IAM setup with `gcloud` commands
- `CONTRIBUTING.md` — check/collector/reporter authoring guide
- `examples/config.example.yaml` — allowlist and configuration reference

#### CI/CD
- GitHub Actions: `ci.yml` (lint + type check + test matrix 3.11/3.12 + Codecov)
- GitHub Actions: `release.yml` (PyPI trusted publishing + Docker push to ghcr.io)

#### Tests
- 179 unit tests, all offline (no GCP API calls)
- Fixtures: `inventory_crypto_mining.json`, `inventory_gemini_abuse.json`
