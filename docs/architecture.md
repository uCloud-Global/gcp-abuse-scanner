# Architecture

`gcp-abuse-scanner` follows a **pipeline architecture** with four distinct stages:

```
Collectors → Checks → ScoringEngine → Reporters
```

Each stage is independently extensible via a plugin/registry pattern — adding a new check, collector, or reporter never requires touching the core.

---

## High-level diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                          CLI (typer)                            │
│  scan --org / --project / --format / --vector / --allowlist     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │   AuthManager   │  ADC / impersonation / key file
                    │   ScopeResolver │  org → [project_id, ...]
                    └────────┬────────┘
                             │ project_ids[]
                    ┌────────▼────────┐
                    │ CollectorEngine │  concurrent, retry/backoff
                    │  (12 collectors)│
                    └────────┬────────┘
                             │ ResourceInventory
                    ┌────────▼────────┐
                    │  CheckRegistry  │  auto-registered plugins
                    │  (50 checks)    │
                    └────────┬────────┘
                             │ [Finding, ...]
                    ┌────────▼────────┐
                    │  ScoringEngine  │  allowlist · priority rank · posture score
                    │  + risk.py      │  SOP risk level 1–4 · coverage gate
                    └────────┬────────┘
                             │ ScanReport
                    ┌────────▼────────┐
                    │   Reporters     │  Console · JSON · Markdown · HTML · SARIF
                    └─────────────────┘
```

---

## Components

### 1. Auth layer (`gcp_abuse_scanner/auth/`)

| Class | Responsibility |
|---|---|
| `AuthManager` | Resolves GCP credentials: impersonation → key file → ADC (in that order). Caches credentials after first resolution. |
| `ScopeResolver` | Converts `--org` / `--project` flags into a flat, deduplicated list of project IDs. Uses Cloud Asset Inventory for org-wide enumeration. |

**Key design decision**: impersonation is always preferred over key files. The `--impersonate-service-account` flag uses short-lived tokens; key files are flagged with a warning.

---

### 2. Collectors (`gcp_abuse_scanner/collectors/`)

Collectors are responsible for **reading raw GCP resource data** and populating a `ResourceInventory` object. They never evaluate security posture — that is the job of checks.

| Collector | Data collected |
|---|---|
| `ComputeCollector` | VM instances, firewall rules |
| `IAMCollector` | IAM bindings, service accounts, SA keys |
| `NetworkCollector` | VPC networks, subnets |
| `ServiceUsageCollector` | Enabled APIs per project |
| `APIKeysCollector` | API keys and their restrictions |
| `BillingCollector` | Billing accounts, budgets, alert policies |
| `GKECollector` | GKE clusters and node pools |
| `CloudRunCollector` | Cloud Run services |
| `VertexAICollector` | Vertex AI endpoints |
| `OrgPolicyCollector` | Organization Policy constraints |
| `RecommenderCollector` | IAM Recommender insights |
| `QuotaCollector` | Service quota values |

**HTTP transport** (`gcp_abuse_scanner/utils/transport.py`): discovery-based collectors build their
clients through `BaseCollector.build_client()`, which uses `requests`
(`google.auth.transport.requests.AuthorizedSession`) with an explicit **per-request timeout** (default
30 s, `--request-timeout`). `httplib2` takes its timeout when the client is built, so a stalled socket
turned a scan into an unbounded wait; `--transport httplib2` restores the legacy behaviour.
A client that cannot be built, an API that is not enabled and a collector that raises are all recorded
(`record_collector_error()` / `record_skipped_api()`) instead of being swallowed — that is what the
coverage gate reads. Collectors fail open, but never silently.

**`CollectorEngine`** runs all collectors concurrently using `ThreadPoolExecutor`. Each collector uses `tenacity` for retry/backoff on transient GCP API errors. Inaccessible projects are recorded in `inventory.inaccessible_projects` rather than failing the entire scan.

**`InventoryCache`** optionally persists the `ResourceInventory` to disk as gzip-compressed JSON (SHA256-keyed, configurable TTL). Enabled with `--cache`.

#### Base class

```python
class BaseCollector(ABC):
    @abstractmethod
    def collect(self, project_id: str, credentials: Credentials) -> None:
        """Populate self.inventory fields. Never raises — logs errors instead."""
```

---

### 3. Checks (`gcp_abuse_scanner/checks/`)

Checks are **stateless, read-only evaluators** that inspect a `ResourceInventory` and return zero or more `Finding` objects.

#### Auto-registration

Every check class that inherits from `BaseCheck` and is imported anywhere in the package is automatically registered in `CheckRegistry` via a metaclass. No manual registration needed.

```python
class BaseCheck(ABC, metaclass=CheckMeta):
    check_id: str          # e.g. "CM-001"
    vector: Vector         # CRYPTO_MINING | GEMINI_ABUSE | COMMON
    title: str
    severity: Severity     # CRITICAL | HIGH | MEDIUM | LOW
    required_apis: list[str]

    @abstractmethod
    def evaluate(self, inventory: ResourceInventory) -> list[Finding]: ...

    def is_applicable(self, inventory: ResourceInventory) -> bool:
        """Return False if required APIs are not enabled — check is skipped."""
```

#### Check vectors

| Vector | Module | Checks |
|---|---|---|
| `crypto_mining` | `checks/crypto_mining/` | CM-001 → CM-060 (25 checks) |
| `gemini_abuse` | `checks/gemini_abuse/` | GEM-001 → GEM-051 (16 checks) |
| `common` | `checks/common/` | CMN-001 → CMN-006 (6 checks) |

#### Finding model

```python
@dataclass
class Finding:
    check_id: str
    vector: Vector
    severity: Severity
    status: FindingStatus      # FAIL | PASS | NOT_APPLICABLE
    resource: GCPResource      # project_id, resource_id, region
    evidence: dict             # raw data that triggered the finding
    remediation: Remediation   # steps, gcloud_commands, effort
    exploitability_score: float  # 0–10, used for priority ranking
    blast_radius: str          # "resource" | "project" | "organization" | "billing_account"
```

---

### 4. Scoring engine (`gcp_abuse_scanner/scoring/`)

`ScoringEngine` takes a flat list of `Finding` objects and:

1. **Applies allowlist suppression** — marks findings as `suppressed=True` if they match any rule in the YAML allowlist. Rules match on `check_id`, `project_id`, and/or `resource_id` (substring).
2. **Assigns priority ranks** — sorts active (non-suppressed) findings by a composite score:
   ```
   score = exploitability_score × blast_radius_weight
   ```
   Blast radius weights: `billing_account=1.5`, `organization=1.3`, `project=1.0`, `resource=0.8`.
3. **Builds the executive summary** — computes `posture_score` (0–100), counts by severity and vector, and extracts the top 10 findings.

**Posture score formula**:
```
penalty      = Σ severity_weight(finding)   # CRITICAL=10, HIGH=5, MEDIUM=2, LOW=0.5
baseline     = max_projects × 20 × 0.5    # ~20 checks/project at LOW weight
posture_score = max(0, 100 − (penalty / baseline × 100))
penalty_points = penalty                  # also reported: no normalization, no floor
```

**Read `penalty_points`, not `posture_score`, when comparing scans.** The normalization makes the
score scope-dependent (the same findings: `0.0` for 1 project, `57.5` for 20) and the `max(0, …)`
floor hides everything once the penalty exceeds the baseline — one CRITICAL already zeroes a
single-project scan. `penalty_points` is the raw sum: it falls by exactly the weight of each fixed
finding, in any scope. Full arithmetic in [`risk-model.md`](risk-model.md).

#### Risk level and the coverage gate (`scoring/risk.py`)

The posture score is a progress metric, not a decision. `assess_risk(findings, coverage)` translates
the scan into the **SOP risk level (1–4)** and decides whether the assessment may be approved without
human review:

| Level | Rule |
|---|---|
| 4 | Any finding in `LEVEL_4_CHECKS` (GEM-001/002/006, CM-043, GEM-021), suppressed or not |
| 3 | Any other CRITICAL |
| 2 | HIGH findings, no CRITICAL |
| 1 | Only MEDIUM/LOW/INFO |

Independently of the level, the **coverage gate** inspects `coverage` and produces
`coverage_gaps[]` when an API keys, IAM, network, compute or quota input could not be read (API not
enabled or not readable, collector error, sensitive check NOT_APPLICABLE or errored, inaccessible
project). Any gap
sets `coverage_complete: false` and `auto_approval_eligible: false`: a scan that could not look
cannot approve. Collectors feed this by recording skips via
`BaseCollector.record_skipped_api()` / `record_collector_error()` — never by staying silent.

The result is stored in `ScanReport.risk_assessment` and documented in
[`risk-model.md`](risk-model.md).

---

### 5. Reporters (`gcp_abuse_scanner/reporters/`)

Reporters consume a `ScanReport` and produce output. All reporters implement the same interface:

```python
class BaseReporter(ABC):
    def __init__(self, output_path: Path | None = None): ...

    @abstractmethod
    def render(self, report: ScanReport) -> str:
        """Return rendered output as string. Also writes to output_path if set."""
```

| Reporter | Format | Use case |
|---|---|---|
| `ConsoleReporter` | Rich terminal tables | Interactive use |
| `JSONReporter` | Structured JSON | API integration, automation |
| `MarkdownReporter` | GitHub-flavored Markdown | PR comments, wikis |
| `HTMLReporter` | Self-contained HTML | Sharing with stakeholders |
| `SARIFReporter` | SARIF 2.1.0 | GitHub Advanced Security, VS Code, SAST tools |

`HTMLReporter` uses a Jinja2 template (`reporters/templates/report.html.j2`) with all CSS/JS inlined — the output file has no external dependencies.

---

## Data flow (detailed)

```
CLI parses args
  → AuthManager.get_credentials()
  → ScopeResolver.resolve_projects(org, projects, excludes)
      → [project_id, ...]
  → CollectorEngine.collect(project_ids, org_id)
      → for each collector in parallel:
            collector.collect(project_id, credentials)
            → populates ResourceInventory fields
      → returns ResourceInventory
  → CheckRegistry.all_checks()
      → for each check:
            if check.is_applicable(inventory):
                findings = check.safe_evaluate(inventory)
  → ScoringEngine.process(findings)
      → _apply_allowlist(findings)
      → _assign_priority_ranks(findings)
  → ScoringEngine.build_executive_summary(findings, max_projects)
  → ScanReport(metadata, executive_summary, coverage, findings)
  → Reporter.render(report)
      → stdout / file
  → exit(0) if no CRITICAL, exit(2) if CRITICAL findings
```

---

## Adding a new check

1. Create a file in the appropriate vector directory (e.g. `checks/crypto_mining/cm_new.py`).
2. Inherit from `BaseCheck` — it auto-registers on import.
3. Implement `evaluate(inventory) -> list[Finding]`.
4. Add unit tests in `tests/unit/` using offline fixtures.
5. Document in `docs/checks/<vector>.md`.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full template.

---

## Adding a new collector

1. Create `collectors/my_collector.py` inheriting from `BaseCollector`.
2. Register it in `collectors/engine.py` → `CollectorEngine._collectors` list.
3. Add the new fields to `models/inventory.py` → `ResourceInventory`.
4. Add unit tests with mocked GCP API responses.

---

## Key design principles

- **Read-only**: no GCP write operations anywhere in the codebase.
- **Fail-open on collection**: a collector error records the error in `inventory.collector_errors` and continues — a partial scan is better than no scan.
- **Offline tests**: all unit tests use static JSON fixtures. No GCP API calls in CI.
- **Single source of truth for version**: `pyproject.toml` → read at runtime via `importlib.metadata`.
- **PEP 561 compliant**: `py.typed` marker included for downstream type checking.
