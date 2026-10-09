---
name: gcp-abuse-scanner-ci
description: Automate gcp-abuse-scanner in CI/CD — scheduled GitHub Actions scans with Workload Identity Federation and impersonation, SARIF upload to GitHub code scanning, correct exit-code handling, artifact retention, drift alerts, and Docker usage. Use when asked to schedule, automate, gate a pipeline on, or integrate the scanner with GitHub/GitLab/Cloud Build.
---

# Scanner in CI/CD

## Principles

- **Keyless auth**: Workload Identity Federation → impersonate the scanner SA. Never store SA keys as
  CI secrets.
- **Always pass `--impersonate-service-account`** in CI. `google-github-actions/auth` exports
  `GOOGLE_APPLICATION_CREDENTIALS` pointing to an `external_account` file; on ≤0.1.5 the CLI loads it
  as an SA key and every collector fails (the job may still exit 0 with an empty report).
- **Exit code 2 means "CRITICAL found" and the report exists** — upload artifacts/SARIF *before* failing
  the job. Exit 2 without a report is a usage error. Exit 1 is a scan failure.
- **Gate on coverage**: fail (or warn) if `coverage.collector_errors` or `inaccessible_project_ids` is
  non-empty, otherwise a broken permission silently turns the job green.
- Pin the scanner version (`pip install gcp-abuse-scanner==X.Y.Z` or an image tag) for reproducible results.
- Reports are sensitive: keep artifacts private with short retention.

## GitHub Actions (scheduled org scan → code scanning)

```yaml
name: gcp-abuse-scan
on:
  schedule: [{ cron: "0 6 * * 1" }]
  workflow_dispatch:

permissions:
  contents: read
  id-token: write          # WIF
  security-events: write   # SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4          # only needed for the allowlist + helper scripts
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ vars.GCP_WIF_PROVIDER }}
          service_account: ${{ vars.GCP_CI_SA }}           # needs TokenCreator on the scanner SA
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install "gcp-abuse-scanner==0.1.5"

      - name: Scan
        id: scan
        run: |
          set +e
          common=(--org "${{ vars.GCP_ORG_ID }}" --impersonate-service-account "${{ vars.SCANNER_SA }}" \
                  --allowlist allowlists/production.yaml --cache)
          gcp-abuse-scanner scan "${common[@]}" --format json --output scan.json
          echo "code=$?" >> "$GITHUB_OUTPUT"
          # Second render reuses the cached inventory (no re-collection) for code scanning
          gcp-abuse-scanner scan "${common[@]}" --format sarif --output results.sarif || true

      - name: Summary
        if: always()
        run: |
          { echo '```'; python skills/gcp-abuse-scanner-triage/scripts/summarize_report.py scan.json; echo '```'; } >> "$GITHUB_STEP_SUMMARY"

      - uses: github/codeql-action/upload-sarif@v3
        if: always() && hashFiles('results.sarif') != ''
        with: { sarif_file: results.sarif, category: gcp-abuse-scanner }

      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: gcp-scan, path: "scan.json\nresults.sarif", retention-days: 14 }

      - name: Gate
        run: |
          code="${{ steps.scan.outputs.code }}"
          test -f scan.json || { echo "::error::scan failed (exit $code), no report"; exit 1; }
          jq -e '.coverage.collector_errors == [] and .coverage.inaccessible_project_ids == []' scan.json \
            || echo "::warning::scan has coverage gaps — see summary"
          [ "$code" = 2 ] && { echo "::error::CRITICAL findings"; exit 2; }
          exit 0
```

Notes:
- `--cache` on both runs makes the SARIF render reuse the first run's inventory (fresh runner, so no
  stale cache). Don't use `--format all` with `--output` (all formats overwrite one path).
- SARIF omits suppressed findings by design. Results appear under *Security → Code scanning*; logical
  locations are `gcp://<project>/<resource_type>/<resource_id>` (no source file lines).
- Validate the allowlist in the same workflow:
  `python skills/gcp-abuse-scanner-allowlist/scripts/validate_allowlist.py allowlists/production.yaml`.

## Drift alerting

Keep the previous `scan.json` (artifact or bucket) and run
`python skills/gcp-abuse-scanner-triage/scripts/diff_reports.py previous.json scan.json` — exit `3`
when new findings appear; post the NEW section to the team channel.

## Docker / other runners

Use the image (`ghcr.io/lmoreno0435/gcp-abuse-scanner:<version>`, entrypoint = CLI, non-root user,
workdir `/reports`) with a writable host dir mounted at `/reports`; credential mounting is covered in
the setup skill. With WIF inside a container, the `external_account` config's token source file must
also be mounted — running the pip-installed CLI directly on the runner is simpler.

In Cloud Build / GitLab, run as an identity that can impersonate the scanner SA and use the same exit-code
and coverage gating.
