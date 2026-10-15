# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `gcp-abuse-scanner`, please **do not** open a public GitHub issue.

Instead, report it via:
- **Email**: hola@ucloudstore.com
- **GitHub Security Advisories**: [Report a vulnerability](https://github.com/uCloud-Global/gcp-abuse-scanner/security/advisories/new)

We will acknowledge your report within 48 hours and aim to release a fix within 14 days for critical issues.

## Security Design Principles

- **Read-only**: The tool never writes, modifies, or deletes any GCP resource.
- **No credential logging**: Credentials and tokens are never written to logs or output files.
- **Impersonation preferred**: We recommend SA impersonation over key files.
- **Minimal permissions**: The required IAM roles are strictly read-only (see README).
- **No telemetry**: The tool does not send any data to external services.
