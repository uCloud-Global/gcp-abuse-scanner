#!/usr/bin/env python3
"""Run the real gcp-abuse-scanner pipeline against an inventory JSON file — no GCP calls.

Auth, scope resolution and collectors are mocked; checks, scoring, allowlist and reporters
are the real implementations. Exits with the CLI's own exit code.

Usage:
    python offline_scan.py INVENTORY.json [-- SCAN_ARGS...]

Examples:
    python offline_scan.py tests/fixtures/inventory_gemini_abuse.json
    python offline_scan.py tests/fixtures/inventory_crypto_mining.json -- \
        --format json --output /tmp/offline.json --allowlist allowlist.yaml

INVENTORY.json may be a ResourceInventory dump, or a decompressed cache file
(an object with an "inventory" key).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch


def main(argv: list[str]) -> int:
    if not argv or argv[0] in {"-h", "--help"}:
        print(__doc__)
        return 0 if argv else 64

    inventory_path, rest = Path(argv[0]), argv[1:]
    if rest and rest[0] == "--":
        rest = rest[1:]

    try:
        from typer.testing import CliRunner

        from gcp_abuse_scanner.cli import app
        from gcp_abuse_scanner.models.inventory import ResourceInventory
    except ImportError:
        print("gcp_abuse_scanner is not importable — run `pip install -e .` first.", file=sys.stderr)
        return 1

    data = json.loads(inventory_path.read_text())
    inventory = ResourceInventory.model_validate(data.get("inventory", data))
    project_ids = inventory.project_ids or ["offline-project"]

    auth = MagicMock()
    auth.identity = "offline"
    scope = MagicMock()
    scope.resolve_projects.return_value = project_ids
    engine = MagicMock()
    engine.collect.return_value = inventory

    args = ["scan", "--project", project_ids[0], *rest]
    with (
        patch("gcp_abuse_scanner.auth.AuthManager", return_value=auth),
        patch("gcp_abuse_scanner.auth.ScopeResolver", return_value=scope),
        patch("gcp_abuse_scanner.collectors.engine.CollectorEngine", return_value=engine),
    ):
        result = CliRunner().invoke(app, args)

    sys.stdout.write(result.output)
    if result.exception and not isinstance(result.exception, SystemExit):
        print(f"\nUnhandled error: {result.exception!r}", file=sys.stderr)
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
