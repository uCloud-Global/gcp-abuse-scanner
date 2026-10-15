# Contributing to gcp-abuse-scanner

Thank you for contributing! This guide explains how to add checks, collectors, and reporters.

## Development Setup

```bash
git clone https://github.com/uCloud-Global/gcp-abuse-scanner
cd gcp-abuse-scanner
pip install -e ".[dev]"
pre-commit install
```

## Adding a New Security Check

Every check must follow the `BaseCheck` contract. Here's the minimal template:

```python
# gcp_abuse_scanner/checks/<vector>/<check_file>.py

from gcp_abuse_scanner.checks.base import BaseCheck, CheckRegistry
from gcp_abuse_scanner.models.finding import Finding, Severity, Vector, ...
from gcp_abuse_scanner.models.inventory import ResourceInventory

@CheckRegistry.register
class MY001MyCheck(BaseCheck):
    check_id = "MY-001"           # Unique ID — never reuse
    title = "Short description"
    vector = Vector.CRYPTO_MINING  # or GEMINI_ABUSE, COMMON
    severity_base = Severity.HIGH
    required_apis = ["compute.googleapis.com"]   # skip if API not enabled
    required_collectors = ["compute"]
    references = ["CIS GCP 4.x"]
    tags = ["compute", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings = []
        for resource in inventory.compute_instances:
            if <condition>:
                findings.append(Finding(
                    finding_id=f"{self.check_id}-{resource.project_id}-{hash(resource.name)}",
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    ...
                ))
        return findings
```

### Rules for checks

1. **No API calls** — use only `inventory` data. Collectors fetch data; checks evaluate it.
2. **Every new check requires**:
   - A unit test with at least one FAIL fixture and one PASS case.
   - An entry in `docs/checks/<vector>.md`.
3. **`finding_id` must be unique** per resource instance. Use `hashlib.md5` on the resource identifier.
4. **`safe_evaluate()`** is called by the engine — it catches exceptions. Don't swallow errors silently.
5. **Remediation must include** at least: `summary`, one `step`, and one `gcloud_command` or `iac_reference`.

## Adding a New Collector

```python
# gcp_abuse_scanner/collectors/my_collector.py

from gcp_abuse_scanner.collectors.base import BaseCollector
from gcp_abuse_scanner.models.inventory import ResourceInventory

class MyCollector(BaseCollector):
    name = "my_collector"
    required_apis = ["myservice.googleapis.com"]

    def collect(self, inventory: ResourceInventory, project_ids: list[str], organization_id=None):
        creds = self._auth.get_credentials()
        for project_id in project_ids:
            if not self.is_api_enabled(inventory, project_id):
                inventory.skipped_apis.setdefault(project_id, []).append("myservice.googleapis.com")
                continue
            # ... fetch and append to inventory
```

Then register it in `collectors/engine.py`.

## Running Tests

```bash
# All tests
pytest

# Specific check
pytest tests/unit/test_crypto_mining_checks.py -v

# With coverage
pytest --cov=gcp_abuse_scanner --cov-report=html
```

**Coverage plan**: current state (94.2 %), the gap analysis and the staged plan to close it are in
[`docs/coverage.md`](docs/coverage.md). Follow its tranche order when adding tests, and keep its
checkboxes up to date as a tranche lands.

## Code Style

```bash
ruff check .          # linting
black .               # formatting
mypy gcp_abuse_scanner  # type checking
```

## Pull Request Checklist

- [ ] New check has `check_id`, `title`, `vector`, `severity_base`, `required_apis`, `required_collectors`
- [ ] Unit test with FAIL fixture + PASS case
- [ ] Entry in `docs/checks/<vector>.md`
- [ ] `ruff`, `black`, `mypy` pass
- [ ] `pytest` passes with no regressions

## Releasing

Releases are cut from `uCloud-Global/gcp-abuse-scanner` only — never from a personal fork or
namespace. Everything the pipeline publishes is bound to that repository:

| Artifact | Target | Configured where |
|---|---|---|
| PyPI package `gcp-abuse-scanner` | PyPI project owner: **uCloud-Global** | PyPI → project → Publishing → **Trusted publisher**: owner `uCloud-Global`, repository `gcp-abuse-scanner`, workflow `release.yml`, environment `release` |
| Docker image | `ghcr.io/ucloud-global/gcp-abuse-scanner` | `.github/workflows/release.yml` (derived from `${{ github.repository }}`) |
| Coverage badge | `codecov.io/gh/uCloud-Global/gcp-abuse-scanner` | Codecov must be re-enabled on the organization repository |

```bash
# 1. Bump the version in pyproject.toml and add a CHANGELOG entry
# 2. Tag and push the tag — the Release workflow does the rest
git tag -a v0.1.6 -m "v0.1.6"
git push origin v0.1.6
```

Notes:
- Publishing uses OIDC trusted publishing (`id-token: write`); no long-lived PyPI token exists
  in the repository secrets. If the trusted publisher is still registered against a different
  owner, the PyPI job fails with `invalid-publisher` — fix the PyPI configuration, not the workflow.
- The Docker image path is lowercased by GitHub; write `ghcr.io/ucloud-global/...` in docs.
- Add new checks/changes to `CHANGELOG.md` before tagging: users are expected to pin an exact
  released version, so the changelog is the audit trail.
