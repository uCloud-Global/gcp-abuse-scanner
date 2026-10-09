# Agent skills for gcp-abuse-scanner

Each folder is a self-contained skill in the [Agent Skills](https://agentskills.io) format
(`SKILL.md` with `name` / `description` frontmatter, plus optional `scripts/` and `references/`).
They teach AI agents to use the `gcp-abuse-scanner` CLI safely and effectively. Start with
[`../AGENTS.md`](../AGENTS.md) for the ground rules.

| Skill | Use it when |
|---|---|
| [`gcp-abuse-scanner-setup`](gcp-abuse-scanner-setup/SKILL.md) | Installing the CLI, enabling GCP APIs, granting read-only IAM, configuring impersonation, diagnosing missing coverage |
| [`gcp-abuse-scanner-scan`](gcp-abuse-scanner-scan/SKILL.md) | Running a scan: picking scope, vectors, format, cache; reading exit codes |
| [`gcp-abuse-scanner-triage`](gcp-abuse-scanner-triage/SKILL.md) | Summarizing a JSON report, prioritizing fixes, writing a remediation plan, comparing scans |
| [`gcp-abuse-scanner-allowlist`](gcp-abuse-scanner-allowlist/SKILL.md) | Suppressing accepted risks, validating and auditing allowlist YAML |
| [`gcp-abuse-scanner-ci`](gcp-abuse-scanner-ci/SKILL.md) | Scheduled/CI scans, SARIF upload to GitHub code scanning, Docker usage |

Helper scripts use only the Python standard library (plus PyYAML, already a dependency of the scanner):

| Script | Purpose |
|---|---|
| `gcp-abuse-scanner-setup/scripts/preflight.sh` | Read-only check of gcloud auth, impersonation, and enabled APIs |
| `gcp-abuse-scanner-scan/scripts/offline_scan.py` | Run the real pipeline against a fixture inventory (no GCP calls) |
| `gcp-abuse-scanner-triage/scripts/summarize_report.py` | Compact, token-efficient summary of a JSON report |
| `gcp-abuse-scanner-triage/scripts/diff_reports.py` | New / resolved / persisting findings between two reports |
| `gcp-abuse-scanner-allowlist/scripts/validate_allowlist.py` | Lint an allowlist (and optionally test it against a report) |

## Installing for a specific agent

- **Claude Code**: `mkdir -p .claude && ln -s ../skills .claude/skills` (project) or copy folders into `~/.claude/skills/`.
- **Other agents** (Codex, Cursor, Gemini CLI, …): they read `AGENTS.md`, which links each skill by path; point the agent's skills directory at `skills/` if it supports one.
