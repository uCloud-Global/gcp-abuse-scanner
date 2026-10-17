# Code quality & maintainability — improvement proposals

Snapshot: **2026-10-16 · 457 tests passing · 94.2 % coverage · Python 3.11/3.12 · v0.1.6**.

This document complements [`coverage.md`](coverage.md) (the test-coverage plan, Tranches A–C) with
proposals that are **not** coverage work: correctness fixes, duplication, structural consistency
and operational hardening. Each item names the file, the problem and the effort, and is classified
P0 (do now, low risk), P1 (structural), P2 (operational).

> The pipeline architecture — `Collectors → Checks → ScoringEngine → Reporters` — is sound, and the
> fail-open-with-a-coverage-gate design is the right call: a 403 or a disabled API is recorded as a
> coverage gap, never silently reported as "no findings". Most of the remaining work is DRY and
> consistency, not redesign.

---

## P0 — Correctness, low risk

### 1. `metadata.tool_version` is hardcoded to `"0.1.0"`

`models/report.py:15` defaults `tool_version = "0.1.0"` and `cli.py:342` never overrides it. The
`version` command reads `__version__` correctly, but the JSON/SARIF report always emits the wrong
tool version. For SARIF this is a **provenance** problem: consumers use `tool.driver.version` to
identify the analyzer that produced the result.

Fix: wire the package version into `ScanMetadata` in `cli.py`.

```python
from gcp_abuse_scanner import __version__
metadata = ScanMetadata(..., tool_version=__version__)
```

**Effort:** ~10 min · **Risk:** none.

### 2. `_make_id` duplicated across 12 check modules

The same helper (MD5 hash truncated to 8 hex chars) is copy-pasted with **three different
signatures** in `cm_compute.py`, `cm_iam.py`, `cm_gke.py`, `cm_cloudrun.py`, `cm_compute_extended.py`,
`cm_iam_extended.py`, `gem_api_keys.py`, `gem_iam.py`, `gem_extended.py`, `cmn_budgets.py`,
`cmn_extended.py`. The same applies to constants like `_PUBLIC_MEMBERS`, `_BROAD_PREFIXES`,
`_is_broad_member`, `_ADMIN_PORTS` and `_DB_PORTS`.

Extract a single shared helper (e.g. in `checks/base.py` or a `checks/_utils.py`) and delete the
copies. Practical collision risk of the 8-hex (32-bit) truncation is low because the hash is scoped
per `(check_id, project_id)`, but bumping to 12 hex chars costs nothing and removes the concern.

**Effort:** ~1 h (mechanical) · **Risk:** low.

### 3. Allowlist matches `resource_id` as a substring

`scoring/engine.py:110`:

```python
if rule.get("resource_id") and rule["resource_id"] not in finding.resource.resource_id:
```

`not in` is a substring test, not equality or glob. A rule with `resource_id: "vm-prod"` suppresses
any resource whose ID *contains* `vm-prod` (`vm-prod-bastion`, `vm-prod-backup`, …). For an
allowlist that decides which risks are accepted, this can **over-suppress** real findings.

Fix: exact equality by default, with an explicit glob prefix if wildcards are wanted. Review
existing allowlists when the semantics change.

**Effort:** ~30 min + test · **Risk:** medium (changes public allowlist semantics).

---

## P1 — Structural consistency

### 4. Check "god files"

`gem_extended.py` holds **1,364 lines and 16 checks**; `cm_iam_extended.py` (819),
`cm_compute_extended.py` (770) and `cmn_extended.py` (463) follow the same pattern. The `_extended`
suffix is a smell: checks were appended to a second file instead of grouped by resource (API keys,
Vertex AI, org policies, quotas). The tests mirror the problem (`test_crypto_mining_extended.py`
is 1,673 lines).

Split by theme; move, don't rewrite.

**Effort:** ~2–3 h per file · **Risk:** low (move only).

### 5. Collectors have no registry, unlike checks

`docs/architecture.md` states "adding a new collector never requires touching the core", but
`collectors/engine.py:56-107` hardcodes the 12 collectors with lazy imports. Checks use
`CheckRegistry`; collectors do not — adding a collector today means editing `engine.py`. The same
applies to `checks/__init__.py:11-13`, which hardcodes the three vector subpackages, so a fourth
vector requires editing that file too.

Introduce a collector registry (or a declarative list) consistent with the check pattern, keeping
the Phase-1 (`ServiceUsageCollector`) vs Phase-2 ordering contract.

**Effort:** ~2 h · **Risk:** medium (touches execution order).

### 6. Single source of truth for the version

The version lives in three places: `pyproject.toml` (0.1.6), `__init__.py` (fallback `"0.1.0"`)
and `models/report.py` (`"0.1.0"`). A `_version.py` or always reading `importlib.metadata` removes
the drift (related to P0-1).

**Effort:** ~20 min · **Risk:** none.

---

## P2 — Operational hardening

### 7. Missing coverage gate (already recommended in this repo)

`docs/coverage.md` proposes `--cov-fail-under=96` in `[tool.pytest.ini_options]`. CI uploads
coverage to Codecov but never fails when it drops. Do this together with Tranche A.

**Effort:** ~5 min · **Risk:** none.

### 8. `max_workers` is not configurable

`collectors/engine.py:19` fixes `_MAX_WORKERS = 10`; the constructor accepts `max_workers` but the
CLI never exposes it. For orgs with thousands of projects this is a tuning knob worth exposing
(`--max-workers` or an env var).

**Effort:** ~30 min · **Risk:** low.

### 9. Exit code `2` is overloaded

Exit code `2` means both "usage error" and "scan completed with CRITICAL findings"
(`AGENTS.md` CLI reference). CI cannot distinguish them without checking that the report file
exists. Consider a dedicated code (e.g. `3`) for active CRITICAL findings. This is a public CLI
contract, so document the change.

**Effort:** ~30 min + docs · **Risk:** medium (breaking for scripts that parse exit codes).

### 10. No dependency pinning / lockfile

`pyproject.toml` uses loose lower bounds (`>=`); CI installs `.[dev]` unpinned. For a security
tool, reproducible builds matter. Add a lockfile (uv/poetry) or at least pin CI dependency
versions. `pre-commit` already documents the pain of keeping `ruff`/`black` versions in sync across
two places (`ruff 0.17` and `black 26.10.1` do not converge).

**Effort:** ~1 h · **Risk:** low.

---

## Already-tracked technical debt (see `coverage.md`)

- **Dead code**: `ScopeResolver.validate_project()` and `AuthManager.build_service()` — delete,
  don't test (Tranche B).
- **`safe_evaluate()` is never truly exercised** — CLI tests mock the whole check object; the 16
  statements of the wrapper that keeps a crashing check from killing a scan are untested.
- **`TestComputeCollector` never existed** — `collectors/compute.py` is at 33 %.

---

## Effort summary

| Priority | Item | Effort | Risk | Value |
|---|---|---|---|---|
| P0 | `tool_version` + single version source (1 + 6) | ~30 min | none | correct provenance |
| P0 | `_make_id` DRY + shared constants (2) | ~1 h | low | maintainability |
| P0 | Allowlist exact/glob matching (3) | ~30 min | medium | stops over-suppression |
| P1 | Split check god files (4) | ~8 h | low | navigability |
| P1 | Collector registry (5) | ~2 h | medium | design consistency |
| P2 | Coverage gate (7) + Tranche A | ~1.5 h | none | prevents regression |
| P2 | `max-workers` (8) | ~30 min | low | operability |
| P2 | Exit code split (9) | ~30 min | medium | CI clarity |
| P2 | Lockfile / pinning (10) | ~1 h | low | reproducibility |

Recommended order: **P0 (1, 2, 3) → P2-7 + coverage Tranche A → P1-5 → P1-4 → remaining P2**.
