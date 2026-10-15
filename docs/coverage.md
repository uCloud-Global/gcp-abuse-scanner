# Test coverage — state, gap analysis and plan

Snapshot: **2026-10-15 · 94.2 %** (3138 statements, 182 uncovered) · 450 tests · Python 3.11 / 3.12.

This document is the plan for closing the remaining gap, in order of value per hour. It is a
checklist, not an aspiration: every item names the file, the exact number of uncovered statements
and the effort. Update the table below whenever a tranche lands.

```bash
pytest --cov=gcp_abuse_scanner --cov-report=term-missing
```

---

## Where the coverage is

| Module | Covered | Uncovered | Note |
|---|---|---|---|
| `scoring/risk.py` | 73/73 = **100 %** | 0 | risk level + coverage gate |
| `utils/transport.py` | 67/67 = **100 %** | 0 | requests/httplib2 transport |
| `scoring/engine.py` | 101/101 = **100 %** | 0 | ranking, allowlist, penalty_points |
| `cli.py` | 210/211 = **99 %** | 1 | only the `__main__` guard |
| `models/report.py` | 86/87 = **99 %** | 1 | |
| `collectors/compute.py` | 11/33 = **33 %** | **22** | no `TestComputeCollector` ever existed |
| `checks/base.py` | 42/58 = **72 %** | **16** | `is_applicable` + `safe_evaluate` never run |
| `collectors/iam.py` | 29/45 = **64 %** | **16** | Cloud Asset loop, key shapes, failure path |
| `checks/crypto_mining/cm_compute_extended.py` | 183/197 = 93 % | 14 | branch fixtures |
| `checks/gemini_abuse/gem_extended.py` | 296/307 = 96 % | 11 | branch fixtures |
| `collectors/engine.py` | 54/63 = 86 % | 9 | cache hit, priority collector failure |
| `collectors/org_policy.py` | 40/48 = 83 % | 8 | |
| `auth/scope.py` | 39/46 = 85 % | 7 | `validate_project()` — **dead code** |
| `collectors/quota.py` | 36/43 = 84 % | 7 | |
| `cmn_budgets.py`, `vertex_ai.py`, `recommender.py` | — | 6 each | |
| `reporters/markdown`, `reporters/html` | — | 5 each | rare sections |
| everything else | — | 1–4 each | 17 files |

---

## Why it is not 100 %

| Category | Statements | Detail |
|---|---|---|
| Collectors with no unit tests / error branches | ~70 | `compute` is the extreme case (22 of 33): no test class ever existed. The rest are 403/timeout/pagination branches that only a shaped API response reaches |
| The check contract never executes | 16 | `checks/base.py`: `is_applicable()` with APIs defined and **all of `safe_evaluate()`** — the wrapper that keeps a crashing check from killing a scan. CLI tests mock the whole check object, so the real one is never called |
| Check branches needing a concrete payload shape | ~40 | org policy `rules` of a given form, `budgetFilter` without services, bucket without `defaultLimit`, … |
| Structurally unreachable / dead code | ~14 | `__main__` guard, `__version__` ImportError fallback, `ScopeResolver.validate_project()` (never called), `AuthManager.build_service()` (superseded by `utils/transport.py`) |
| Rare reporter sections | 12 | markdown/html/console paths that only render with specific data |

**100 % needs configuration for a handful of lines**, not tests: coverage.py's `exclude_lines` for
`pragma: no cover` and `if __name__ == "__main__":`.

---

## The plan

### Tranche A — ~1,5 h → ~96 % · do first

The highest-risk uncovered code, all cheap to test without exotic mocks.

- [ ] `checks/base.py` — `is_applicable()` with `required_apis` populated; `safe_evaluate()` on a
      check that raises (asserts it returns `[]` and logs). 16 statements, protects every scan.
- [ ] `reporters/` — markdown (5), html (5), console (2) branch rendering. 12.
- [ ] `collectors/engine.py` (9) — cache-hit path and priority-collector failure path.
- [ ] `collectors/base.py` (4) — `record_skipped_api` / `record_collector_error` / `build_client`
      branches.
- [ ] `collectors/cache.py` (3), `models/finding.py` (2), `models/report.py` (1).
- [ ] Seven single-line leftovers: `cmn_extended`, `cm_cloudrun`, `network`, `api_keys`, `gke`,
      `__init__`.

### Tranche B — ~3–4 h → ~98,5 %

- [ ] `TestComputeCollector` (22) — `aggregatedList` + `list_next`, skip when the Compute API is
      disabled, error path recording a coverage gap.
- [ ] `collectors/iam.py` (16) — Cloud Asset search loop, failure path, SA key shapes,
      `_extract_project` variants.
- [ ] `org_policy` (8), `quota` (7), `vertex_ai` (6), `recommender` (6), `cloud_run` (4),
      `billing` (2), `service_usage` (2) — error and pagination branches with the real API shape
      (403 / HTTP 404 / timeout), following the pattern already used in
      `test_collectors.py::TestFailuresAreRecordedAsCoverageGaps`.
- [ ] **Delete instead of test** the dead code: `ScopeResolver.validate_project()` (7) and
      `AuthManager.build_service()` (2). A test that only proves an unused method runs adds no
      safety and pins dead code in place.

### Tranche C — ~4–6 h → 100 %

Only if a compliance requirement demands 100 %.

- [ ] `cm_compute_extended` (14), `gem_extended` (11), `cmn_budgets` (6), `cm_iam_extended` (4),
      `cm_compute` (4), `cm_iam` (3), `gem_iam` (3) — read each branch, derive the exact payload
      shape that triggers it, build the fixture. Some branches may prove unreachable: delete the
      branch or annotate it.
- [ ] `[tool.coverage.report] exclude_lines` for structurally unreachable lines
      (`pragma: no cover`, the `__main__` guard, the `__version__` fallback).
- [ ] `models/finding.py` (2) and `reporters/console.py` (2) edge branches.

---

## Keep it from decaying (do this with tranche A)

- [ ] Add `--cov-fail-under=96` to `[tool.pytest.ini_options] addopts` in `pyproject.toml`, set to
      the level reached by tranche A, and raise it as A and B land. Five minutes, and it is worth
      more than the last 20 lines: CI fails on regression instead of drifting.
- [x] **Codecov badge removed from the README** (2026-10-14) — both badges (`uCloud-Global` and the old
      `lmoreno0435`) render `unknown`: the repo never uploaded coverage (the workflow has no
      `CODECOV_TOKEN`, and the action does not fail CI on upload errors, so it fails silently).
      Re-enable only if PR-level coverage deltas are wanted: register the org repo on codecov.io,
      add the `CODECOV_TOKEN` secret, then the badge and a `--cov-fail-under` gate in Codecov.

---

## Rules for new tests

1. **Test the branch with the real API response**, not just the happy path: a 403, a 404, a timeout
   and a paginated page are what collectors actually meet in the field.
2. **Never cover dead code — delete or wire it.** A test on an uncalled method is noise.
3. Repo convention stands: every new check needs a FAIL fixture and a PASS case.
4. Never raise coverage by weakening assertions or by asserting `True` on generated lines.

## Effort summary

| Tranche | Effort | Coverage | Value |
|---|---|---|---|
| A | ~1,5 h | ~96 % | high — the scan-safety wrapper and reporting |
| B | ~3–4 h | ~98,5 % | medium — collector error paths |
| C | ~4–6 h | 100 % | low — last-mile fixtures |
| Gate | 5 min | — | prevents regression, do it with A |

Recommended: A + B + gate (≈5 h → 98,5 %). C only under a contractual requirement.
