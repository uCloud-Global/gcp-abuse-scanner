"""
Gemini Abuse checks — API Keys.

GEM-001: API key with no API restrictions
GEM-002: API key with no application restrictions
GEM-003: API key with explicit access to generativelanguage.googleapis.com
GEM-004: API key without rotation (long-lived)
"""

from __future__ import annotations

import hashlib

from gcp_abuse_scanner.checks.base import BaseCheck, CheckRegistry
from gcp_abuse_scanner.models.finding import (
    Finding,
    FindingStatus,
    GCPResource,
    Remediation,
    RemediationEffort,
    Severity,
    Vector,
)
from gcp_abuse_scanner.models.inventory import APIKey, ResourceInventory

_GEMINI_APIS = {
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
}


def _make_id(check_id: str, project_id: str, key_name: str) -> str:
    h = hashlib.md5(key_name.encode(), usedforsecurity=False).hexdigest()[:8]
    return f"{check_id}-{project_id}-{h}"


def _has_api_restrictions(key: APIKey) -> bool:
    """Return True if the key restricts which APIs it can call."""
    api_targets = key.restrictions.get("apiTargets", [])
    return bool(api_targets)


def _has_app_restrictions(key: APIKey) -> bool:
    """Return True if the key has HTTP referrer, IP, or app restrictions."""
    r = key.restrictions
    return bool(
        r.get("browserKeyRestrictions")
        or r.get("serverKeyRestrictions")
        or r.get("androidKeyRestrictions")
        or r.get("iosKeyRestrictions")
    )


def _targets_gemini(key: APIKey) -> bool:
    targets = {t.get("service", "") for t in key.restrictions.get("apiTargets", [])}
    return bool(targets & _GEMINI_APIS)


@CheckRegistry.register
class GEM001NoAPIRestrictions(BaseCheck):
    """API key has no API restrictions — valid for any GCP API."""

    check_id = "GEM-001"
    title = "API key has no API restrictions"
    vector = Vector.GEMINI_ABUSE
    severity_base = Severity.CRITICAL
    required_collectors = ["api_keys"]
    # NOTE: required_apis intentionally omitted — API keys exist independently of whether
    # apikeys.googleapis.com is listed as enabled. The collector always attempts collection.
    references = ["CIS GCP 1.14"]
    tags = ["api_keys", "gemini_abuse", "credentials"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for key in inventory.api_keys:
            if _has_api_restrictions(key):
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, key.project_id, key.name),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=9.5,
                    blast_radius="billing_account",
                    resource=GCPResource(
                        resource_type="apikeys.googleapis.com/Key",
                        resource_id=key.name,
                        project_id=key.project_id,
                        region="global",
                    ),
                    evidence={
                        "key_name": key.name,
                        "display_name": key.display_name,
                        "restrictions": key.restrictions,
                        "uid": key.uid,
                    },
                    description=(
                        f"API key '{key.display_name or key.name}' has no API restrictions. "
                        "It can be used to call ANY GCP API, including "
                        "generativelanguage.googleapis.com (Gemini). If this key is leaked "
                        "(e.g. in client-side code, repos, logs), an attacker can consume "
                        "Gemini at the project's expense."
                    ),
                    impact=(
                        "Unrestricted API key leaked → unlimited Gemini API calls → "
                        "runaway costs on the billing account."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Restrict the key to only the APIs it needs, or migrate to "
                            "OAuth 2.0 / service account authentication."
                        ),
                        steps=[
                            "Identify which APIs this key is actually used for.",
                            "Add API restrictions to limit the key to those APIs only.",
                            "Add application restrictions (HTTP referrer / IP allowlist).",
                            "Rotate the key after applying restrictions.",
                            "Consider migrating to OAuth 2.0 for server-side use cases.",
                        ],
                        gcloud_commands=[
                            f"gcloud services api-keys update {key.uid} --api-target=service=generativelanguage.googleapis.com --allowed-referrers=https://yourdomain.com/*",
                        ],
                        iac_reference="google_apikeys_key.restrictions",
                        docs=[
                            "https://cloud.google.com/docs/authentication/api-keys#restricting_an_api_key",
                            "https://cloud.google.com/generative-ai-app-builder/docs/authentication",
                        ],
                        effort=RemediationEffort.LOW,
                    ),
                    references=self.references,
                )
            )
        return findings


@CheckRegistry.register
class GEM002NoAppRestrictions(BaseCheck):
    """API key has no application (HTTP referrer / IP) restrictions."""

    check_id = "GEM-002"
    title = "API key has no application restrictions (HTTP referrer / IP)"
    vector = Vector.GEMINI_ABUSE
    severity_base = Severity.CRITICAL
    required_collectors = ["api_keys"]
    references = ["CIS GCP 1.14"]
    tags = ["api_keys", "gemini_abuse", "credentials"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for key in inventory.api_keys:
            if _has_app_restrictions(key):
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, key.project_id, key.name),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=9.0,
                    blast_radius="billing_account",
                    resource=GCPResource(
                        resource_type="apikeys.googleapis.com/Key",
                        resource_id=key.name,
                        project_id=key.project_id,
                        region="global",
                    ),
                    evidence={
                        "key_name": key.name,
                        "display_name": key.display_name,
                        "restrictions": key.restrictions,
                    },
                    description=(
                        f"API key '{key.display_name or key.name}' has no application "
                        "restrictions. It can be used from any IP address or HTTP origin. "
                        "A leaked key can be exploited from anywhere to call Gemini APIs."
                    ),
                    impact=(
                        "Key usable from any origin → if leaked, attacker can call Gemini "
                        "from any machine → unbounded cost exposure."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Add HTTP referrer restrictions for browser keys, or IP "
                            "allowlists for server-side keys."
                        ),
                        steps=[
                            "Determine the key's consumer type (browser app, server, mobile).",
                            "For browser apps: add HTTP referrer restrictions.",
                            "For server apps: add IP address restrictions.",
                            "For mobile apps: add Android/iOS app restrictions.",
                            "Rotate the key after applying restrictions.",
                        ],
                        gcloud_commands=[
                            f"# Browser key:\ngcloud services api-keys update {key.uid} --allowed-referrers=https://yourdomain.com/*",
                            f"# Server key:\ngcloud services api-keys update {key.uid} --allowed-ips=203.0.113.0/24",
                        ],
                        iac_reference="google_apikeys_key.restrictions.browser_key_restrictions",
                        docs=[
                            "https://cloud.google.com/docs/authentication/api-keys#adding_application_restrictions"
                        ],
                        effort=RemediationEffort.LOW,
                    ),
                    references=self.references,
                )
            )
        return findings


@CheckRegistry.register
class GEM003KeyTargetsGemini(BaseCheck):
    """API key explicitly targets the Gemini / Generative Language API."""

    check_id = "GEM-003"
    title = "API key explicitly grants access to Gemini/Generative Language API"
    vector = Vector.GEMINI_ABUSE
    severity_base = Severity.HIGH
    required_collectors = ["api_keys"]
    tags = ["api_keys", "gemini_abuse"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for key in inventory.api_keys:
            if not _targets_gemini(key):
                continue
            # Only flag if ALSO missing app restrictions (compound risk)
            if _has_app_restrictions(key):
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, key.project_id, key.name),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=8.5,
                    blast_radius="billing_account",
                    resource=GCPResource(
                        resource_type="apikeys.googleapis.com/Key",
                        resource_id=key.name,
                        project_id=key.project_id,
                        region="global",
                    ),
                    evidence={
                        "key_name": key.name,
                        "display_name": key.display_name,
                        "api_targets": key.restrictions.get("apiTargets", []),
                        "has_app_restrictions": False,
                    },
                    description=(
                        f"API key '{key.display_name or key.name}' explicitly targets "
                        "the Gemini/Generative Language API but has no application "
                        "restrictions. This is a direct Gemini abuse surface."
                    ),
                    impact=(
                        "Direct, unrestricted access to Gemini API → high-cost abuse "
                        "if key is leaked."
                    ),
                    remediation=Remediation(
                        summary="Add application restrictions to this Gemini-enabled key.",
                        steps=[
                            "Add HTTP referrer or IP restrictions to the key.",
                            "Rotate the key after applying restrictions.",
                            "Monitor key usage via Cloud Audit Logs.",
                        ],
                        gcloud_commands=[
                            f"gcloud services api-keys update {key.uid} --allowed-referrers=https://yourdomain.com/*",
                        ],
                        iac_reference="google_apikeys_key.restrictions",
                        docs=[
                            "https://cloud.google.com/docs/authentication/api-keys#restricting_an_api_key"
                        ],
                        effort=RemediationEffort.LOW,
                    ),
                    references=self.references,
                )
            )
        return findings
