"""
Gemini Abuse checks — Extended surface.

GEM-004: API key has not been rotated recently (older than 90 days)
GEM-005: Project has multiple API keys with no API restrictions (orphaned keys)
GEM-006: API key targeting Gemini/Generative Language API has no HTTP referrer restriction
GEM-010: generativelanguage.googleapis.com is enabled in project
GEM-011: aiplatform.googleapis.com is enabled but no IAM controls restrict access
GEM-022: Service account with Vertex AI access has user-managed (exportable) keys
GEM-023: roles/aiplatform.user or broader role granted to non-specific principals
GEM-030: Vertex AI endpoint is publicly accessible (no private network configured)
GEM-040: Vertex AI quota is at default high value (no throttling configured)
GEM-041: Gemini API (Generative Language) quota is at default value (no throttling configured)
GEM-050: Org Policy does not restrict API key / SA key creation
GEM-051: No budget alert configured covering Vertex AI / Gemini spend
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import UTC, datetime, timedelta

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
from gcp_abuse_scanner.models.inventory import ResourceInventory

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GEMINI_SERVICES = {"generativelanguage", "aiplatform"}
_KEY_MAX_AGE_DAYS = 90
_ORPHAN_KEY_THRESHOLD = 3  # more than this many unrestricted keys → flag

_BROAD_VERTEX_ROLES = {
    "roles/aiplatform.user",
    "roles/aiplatform.admin",
    "roles/ml.admin",
}
_PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
_BROAD_PREFIXES = ("domain:", "group:")

_SA_KEY_CREATION_CONSTRAINT = "constraints/iam.disableServiceAccountKeyCreation"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_id(check_id: str, project_id: str, key: str) -> str:
    h = hashlib.md5(key.encode(), usedforsecurity=False).hexdigest()[:8]
    return f"{check_id}-{project_id}-{h}"


def _parse_create_time(create_time: str | None) -> datetime | None:
    """Parse an ISO 8601 timestamp string into an aware datetime, or return None."""
    if not create_time:
        return None
    # GCP timestamps may end with 'Z' or have +00:00
    ts = create_time.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def _targets_gemini_or_aiplatform(restrictions: dict) -> bool:
    """Return True if any apiTarget service contains 'generativelanguage' or 'aiplatform'."""
    for target in restrictions.get("apiTargets", []):
        svc = target.get("service", "")
        if any(g in svc for g in _GEMINI_SERVICES):
            return True
    return False


def _is_broad_member(member: str) -> bool:
    return member in _PUBLIC_MEMBERS or any(member.startswith(p) for p in _BROAD_PREFIXES)


# ---------------------------------------------------------------------------
# GEM-004 — API key rotation
# ---------------------------------------------------------------------------


@CheckRegistry.register
class GEM004APIKeyNoRotation(BaseCheck):
    """API key has not been rotated in more than 90 days."""

    check_id = "GEM-004"
    title = "API key has not been rotated recently (older than 90 days)"
    vector = Vector.GEMINI_ABUSE
    severity_base = Severity.HIGH
    required_collectors = ["api_keys"]
    tags = ["api_keys", "gemini_abuse", "credentials", "rotation"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        now = datetime.now(UTC)
        cutoff = now - timedelta(days=_KEY_MAX_AGE_DAYS)

        for key in inventory.api_keys:
            created_at = _parse_create_time(key.create_time)

            if created_at is None:
                # Conservative: treat unparseable / missing create_time as a fail
                age_days = None
                reason = "create_time is missing or unparseable — assuming stale key"
            elif created_at < cutoff:
                age_days = (now - created_at).days
                reason = f"Key is {age_days} days old (threshold: {_KEY_MAX_AGE_DAYS} days)"
            else:
                continue  # Key is fresh — PASS

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, key.project_id, key.name),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=6.5,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="apikeys.googleapis.com/Key",
                        resource_id=key.name,
                        project_id=key.project_id,
                        region="global",
                    ),
                    evidence={
                        "key_name": key.name,
                        "display_name": key.display_name,
                        "create_time": key.create_time,
                        "age_days": age_days,
                        "reason": reason,
                    },
                    description=(
                        f"API key '{key.display_name or key.name}' has not been rotated "
                        f"within the last {_KEY_MAX_AGE_DAYS} days. {reason}. "
                        "Long-lived keys increase the window of exposure if the key is leaked."
                    ),
                    impact=(
                        "A stale key that has been leaked may have been in active abuse "
                        "for an extended period without detection."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Rotate this API key. Create a new key, update all consumers, "
                            "then delete the old key."
                        ),
                        steps=[
                            "Create a replacement API key with the same restrictions.",
                            "Update all applications and services to use the new key.",
                            "Verify the old key is no longer in use via Cloud Audit Logs.",
                            "Delete the old key.",
                            "Establish a key rotation schedule (≤ 90 days).",
                        ],
                        gcloud_commands=[
                            "gcloud services api-keys create --display-name=NEW_KEY --api-target=service=generativelanguage.googleapis.com",
                            f"gcloud services api-keys delete {key.uid}  # after migration",
                        ],
                        iac_reference="google_apikeys_key",
                        docs=[
                            "https://cloud.google.com/docs/authentication/api-keys#rotating_api_keys"
                        ],
                        effort=RemediationEffort.LOW,
                    ),
                    references=self.references,
                )
            )
        return findings


# ---------------------------------------------------------------------------
# GEM-005 — Orphaned API keys (many unrestricted keys per project)
# ---------------------------------------------------------------------------


@CheckRegistry.register
class GEM005OrphanAPIKeys(BaseCheck):
    """Project has more than 3 API keys with no API restrictions — potential orphaned keys."""

    check_id = "GEM-005"
    title = "Project has multiple API keys with no API restrictions (potential orphaned keys)"
    vector = Vector.GEMINI_ABUSE
    severity_base = Severity.MEDIUM
    required_collectors = ["api_keys"]
    tags = ["api_keys", "gemini_abuse", "credentials", "hygiene"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []

        # Group unrestricted keys by project
        unrestricted_by_project: dict[str, list] = defaultdict(list)
        for key in inventory.api_keys:
            api_targets = key.restrictions.get("apiTargets", [])
            if not api_targets:
                unrestricted_by_project[key.project_id].append(key)

        for project_id, keys in unrestricted_by_project.items():
            if len(keys) <= _ORPHAN_KEY_THRESHOLD:
                continue

            key_names = [k.name for k in keys]
            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, project_id, project_id),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=4.5,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="cloudresourcemanager.googleapis.com/Project",
                        resource_id=project_id,
                        project_id=project_id,
                        region="global",
                    ),
                    evidence={
                        "unrestricted_key_count": len(keys),
                        "threshold": _ORPHAN_KEY_THRESHOLD,
                        "key_names": key_names,
                    },
                    description=(
                        f"Project '{project_id}' has {len(keys)} API keys with no API "
                        f"restrictions (threshold: {_ORPHAN_KEY_THRESHOLD}). These keys can "
                        "call any GCP API, including Gemini, and may be forgotten / orphaned."
                    ),
                    impact=(
                        "Orphaned unrestricted keys are a persistent credential leak risk. "
                        "Any of them can be used to call Gemini APIs at the project's expense."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Audit all unrestricted API keys. Delete unused ones and apply "
                            "API restrictions to those that must be retained."
                        ),
                        steps=[
                            "Review each key's last-used timestamp in Cloud Audit Logs.",
                            "Delete keys that have not been used in the last 30 days.",
                            "For remaining keys, add API restrictions to the minimum required APIs.",
                            "Add application restrictions (HTTP referrer / IP allowlist).",
                            "Implement a key inventory process to prevent accumulation.",
                        ],
                        gcloud_commands=[
                            f"gcloud services api-keys list --project={project_id}",
                            "gcloud services api-keys delete KEY_ID --project=" + project_id,
                        ],
                        iac_reference="google_apikeys_key.restrictions.api_targets",
                        docs=[
                            "https://cloud.google.com/docs/authentication/api-keys#restricting_an_api_key"
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings


# ---------------------------------------------------------------------------
# GEM-006 — Gemini API key without HTTP referrer restriction
# ---------------------------------------------------------------------------


@CheckRegistry.register
class GEM006APIKeyNoReferrerRestriction(BaseCheck):
    """API key targeting Gemini/Generative Language API has no HTTP referrer restriction."""

    check_id = "GEM-006"
    title = "API key targeting Gemini/Generative Language API has no HTTP referrer restriction"
    vector = Vector.GEMINI_ABUSE
    severity_base = Severity.HIGH
    required_collectors = ["api_keys"]
    tags = ["api_keys", "gemini_abuse", "credentials"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []

        for key in inventory.api_keys:
            if not _targets_gemini_or_aiplatform(key.restrictions):
                continue

            # Flag only if browserKeyRestrictions is absent or empty
            browser_restrictions = key.restrictions.get("browserKeyRestrictions", {})
            if browser_restrictions:
                continue

            api_targets = key.restrictions.get("apiTargets", [])
            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, key.project_id, key.name),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=7.0,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="apikeys.googleapis.com/Key",
                        resource_id=key.name,
                        project_id=key.project_id,
                        region="global",
                    ),
                    evidence={
                        "key_name": key.name,
                        "display_name": key.display_name,
                        "api_targets": api_targets,
                        "browser_key_restrictions": browser_restrictions,
                    },
                    description=(
                        f"API key '{key.display_name or key.name}' targets the Gemini / "
                        "Generative Language API but has no HTTP referrer restriction. "
                        "If this key is embedded in client-side code, any origin can use it."
                    ),
                    impact=(
                        "A Gemini-enabled key without referrer restrictions can be extracted "
                        "from browser traffic and reused from any origin to generate costs."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Add HTTP referrer restrictions to this key, or migrate to "
                            "OAuth 2.0 / service account authentication for server-side use."
                        ),
                        steps=[
                            "Determine whether this key is used in a browser or server context.",
                            "For browser use: add allowed HTTP referrers (e.g. https://yourdomain.com/*).",
                            "For server use: switch to IP restrictions or service account credentials.",
                            "Rotate the key after applying restrictions.",
                        ],
                        gcloud_commands=[
                            f"gcloud services api-keys update {key.uid} --allowed-referrers=https://yourdomain.com/*",
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


# ---------------------------------------------------------------------------
# GEM-010 — generativelanguage.googleapis.com enabled
# ---------------------------------------------------------------------------


@CheckRegistry.register
class GEM010GenerativeLanguageAPIEnabled(BaseCheck):
    """generativelanguage.googleapis.com is enabled — Gemini API surface exposed."""

    check_id = "GEM-010"
    title = "generativelanguage.googleapis.com is enabled in project (Gemini API surface exposed)"
    vector = Vector.GEMINI_ABUSE
    severity_base = Severity.MEDIUM
    required_collectors = ["service_usage"]
    tags = ["service_usage", "gemini_abuse", "api_surface"]

    _TARGET_SERVICE = "generativelanguage.googleapis.com"

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []

        # Build a set of projects that have the service enabled
        enabled_projects = {
            api.project_id
            for api in inventory.enabled_apis
            if api.service_name == self._TARGET_SERVICE
        }

        for project_id in inventory.project_ids:
            if project_id not in enabled_projects:
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, project_id, project_id),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=4.0,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="serviceusage.googleapis.com/Service",
                        resource_id=self._TARGET_SERVICE,
                        project_id=project_id,
                        region="global",
                    ),
                    evidence={
                        "project_id": project_id,
                        "service": self._TARGET_SERVICE,
                    },
                    description=(
                        f"Project '{project_id}' has '{self._TARGET_SERVICE}' enabled. "
                        "This exposes the Gemini API surface. If API keys or IAM bindings "
                        "are misconfigured, this project can be abused to generate Gemini costs."
                    ),
                    impact=(
                        "Enabled Gemini API combined with weak credentials or IAM controls "
                        "creates a direct path for unauthorized model invocations."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Disable the Generative Language API if it is not required by "
                            "this project. If required, ensure strict IAM and API key controls."
                        ),
                        steps=[
                            "Verify whether any workload in this project requires the Gemini API.",
                            "If not required, disable the service.",
                            "If required, review API key and IAM configurations (GEM-001 through GEM-006).",
                            "Enable Cloud Audit Logs for the service to monitor usage.",
                        ],
                        gcloud_commands=[
                            f"gcloud services disable {self._TARGET_SERVICE} --project={project_id}",
                        ],
                        iac_reference="google_project_service",
                        docs=[
                            "https://cloud.google.com/generative-ai-app-builder/docs/before-you-begin"
                        ],
                        effort=RemediationEffort.LOW,
                    ),
                    references=self.references,
                )
            )
        return findings


# ---------------------------------------------------------------------------
# GEM-011 — aiplatform.googleapis.com enabled but broad IAM controls
# ---------------------------------------------------------------------------


@CheckRegistry.register
class GEM011VertexAIEnabledNoBroadIAMControls(BaseCheck):
    """aiplatform.googleapis.com is enabled but IAM bindings allow broad access."""

    check_id = "GEM-011"
    title = "aiplatform.googleapis.com is enabled but no IAM controls restrict access"
    vector = Vector.GEMINI_ABUSE
    severity_base = Severity.MEDIUM
    required_collectors = ["service_usage", "iam"]
    tags = ["service_usage", "iam", "gemini_abuse", "vertex_ai"]

    _TARGET_SERVICE = "aiplatform.googleapis.com"

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []

        # Projects with Vertex AI enabled
        vertex_projects = {
            api.project_id
            for api in inventory.enabled_apis
            if api.service_name == self._TARGET_SERVICE
        }

        for project_id in vertex_projects:
            # Find IAM bindings in this project that involve aiplatform roles
            # and have broad members
            problematic_bindings = []
            for binding in inventory.iam_bindings:
                if binding.project_id != project_id:
                    continue
                if "aiplatform" not in binding.role:
                    continue
                broad = [m for m in binding.members if _is_broad_member(m)]
                if broad:
                    problematic_bindings.append(
                        {
                            "role": binding.role,
                            "broad_members": broad,
                            "resource": binding.resource,
                        }
                    )

            if not problematic_bindings:
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, project_id, project_id),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=6.0,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="serviceusage.googleapis.com/Service",
                        resource_id=self._TARGET_SERVICE,
                        project_id=project_id,
                        region="global",
                    ),
                    evidence={
                        "project_id": project_id,
                        "service": self._TARGET_SERVICE,
                        "problematic_bindings": problematic_bindings,
                    },
                    description=(
                        f"Project '{project_id}' has '{self._TARGET_SERVICE}' enabled and "
                        "contains IAM bindings that grant Vertex AI roles to broad principals "
                        f"(allUsers, allAuthenticatedUsers, domain:, or group:). "
                        f"Affected bindings: {len(problematic_bindings)}."
                    ),
                    impact=(
                        "Broad IAM access to Vertex AI allows large populations of users "
                        "to invoke models, increasing the blast radius of any compromised account."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Restrict Vertex AI IAM roles to specific service accounts or "
                            "individual users. Remove broad domain/group/public bindings."
                        ),
                        steps=[
                            "Identify which principals actually need Vertex AI access.",
                            "Remove broad bindings (domain:, group:, allUsers).",
                            "Grant roles to specific service accounts or users.",
                            "Consider using IAM Conditions to further restrict access.",
                        ],
                        gcloud_commands=[
                            f"gcloud projects get-iam-policy {project_id} --format=json | jq '.bindings[] | select(.role | contains(\"aiplatform\"))'",
                            f"gcloud projects remove-iam-policy-binding {project_id} --member=BROAD_MEMBER --role=ROLE",
                        ],
                        iac_reference="google_project_iam_binding",
                        docs=["https://cloud.google.com/vertex-ai/docs/general/access-control"],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings


# ---------------------------------------------------------------------------
# GEM-022 — SA with Vertex AI access AND user-managed (exportable) keys
# ---------------------------------------------------------------------------


@CheckRegistry.register
class GEM022SAWithVertexAccessAndExportedKeys(BaseCheck):
    """Service account with Vertex AI access has user-managed (exportable) keys."""

    check_id = "GEM-022"
    title = "Service account with Vertex AI access has user-managed (exportable) keys"
    vector = Vector.GEMINI_ABUSE
    severity_base = Severity.HIGH
    required_collectors = ["iam"]
    tags = ["iam", "gemini_abuse", "vertex_ai", "service_accounts", "credentials"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []

        # Step 1: collect SAs that appear in Vertex AI IAM bindings
        vertex_sa_emails: dict[str, list[str]] = defaultdict(list)  # email -> [roles]
        for binding in inventory.iam_bindings:
            if "aiplatform" not in binding.role:
                continue
            for member in binding.members:
                if member.startswith("serviceAccount:"):
                    sa_email = member[len("serviceAccount:") :]
                    vertex_sa_emails[sa_email].append(binding.role)

        if not vertex_sa_emails:
            return findings

        # Step 2: find those SAs that have USER_MANAGED keys
        for sa in inventory.service_accounts:
            if sa.email not in vertex_sa_emails:
                continue
            user_managed_keys = [k for k in sa.keys if k.get("keyType") == "USER_MANAGED"]
            if not user_managed_keys:
                continue

            key_names = [k.get("name", "") for k in user_managed_keys]
            roles = vertex_sa_emails[sa.email]

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, sa.project_id, sa.email),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=8.5,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="iam.googleapis.com/ServiceAccount",
                        resource_id=sa.email,
                        project_id=sa.project_id,
                        region="global",
                    ),
                    evidence={
                        "sa_email": sa.email,
                        "vertex_ai_roles": roles,
                        "user_managed_key_names": key_names,
                        "user_managed_key_count": len(user_managed_keys),
                    },
                    description=(
                        f"Service account '{sa.email}' has Vertex AI roles "
                        f"({roles}) and {len(user_managed_keys)} user-managed (exportable) "
                        "key(s). Exported SA keys can be stolen and used to call Vertex AI / "
                        "Gemini APIs from outside GCP."
                    ),
                    impact=(
                        "A stolen user-managed SA key with Vertex AI access provides "
                        "persistent, hard-to-revoke access to Gemini models, enabling "
                        "high-cost abuse from any location."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Delete user-managed SA keys. Use Workload Identity Federation "
                            "or SA impersonation instead of exported keys."
                        ),
                        steps=[
                            "Identify all consumers of the user-managed keys.",
                            "Migrate consumers to Workload Identity Federation or SA impersonation.",
                            "Delete the user-managed keys after migration.",
                            "Enable the org policy constraints/iam.disableServiceAccountKeyCreation.",
                        ],
                        gcloud_commands=[
                            f"gcloud iam service-accounts keys list --iam-account={sa.email}",
                            f"gcloud iam service-accounts keys delete KEY_ID --iam-account={sa.email}",
                        ],
                        iac_reference="google_service_account_key",
                        docs=[
                            "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys",
                            "https://cloud.google.com/iam/docs/workload-identity-federation",
                        ],
                        effort=RemediationEffort.HIGH,
                    ),
                    references=self.references,
                )
            )
        return findings


# ---------------------------------------------------------------------------
# GEM-023 — Broad Vertex predict access
# ---------------------------------------------------------------------------


@CheckRegistry.register
class GEM023BroadVertexPredictAccess(BaseCheck):
    """roles/aiplatform.user or broader role granted to non-specific principals."""

    check_id = "GEM-023"
    title = "roles/aiplatform.user or broader role granted to non-specific principals"
    vector = Vector.GEMINI_ABUSE
    severity_base = Severity.HIGH
    required_collectors = ["iam"]
    tags = ["iam", "gemini_abuse", "vertex_ai", "public_access"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []

        for binding in inventory.iam_bindings:
            if binding.role not in _BROAD_VERTEX_ROLES:
                continue

            broad_members = [m for m in binding.members if _is_broad_member(m)]
            if not broad_members:
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(
                        self.check_id,
                        binding.project_id,
                        f"{binding.resource}-{binding.role}",
                    ),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=8.0,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type=binding.resource_type,
                        resource_id=binding.resource,
                        project_id=binding.project_id,
                    ),
                    evidence={
                        "role": binding.role,
                        "broad_members": broad_members,
                        "all_members": binding.members,
                    },
                    description=(
                        f"Role '{binding.role}' is granted to broad principals: "
                        f"{broad_members}. This role allows invoking Vertex AI / Gemini "
                        "prediction endpoints and can be abused by any member of those "
                        "domains or groups."
                    ),
                    impact=(
                        "Any member of the broad principal set can call Gemini prediction "
                        "endpoints, generating potentially unbounded costs."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Restrict Vertex AI roles to specific service accounts. "
                            "Use IAM Conditions to further limit access scope."
                        ),
                        steps=[
                            "Identify which specific identities need Vertex AI access.",
                            "Remove the broad binding.",
                            "Grant the role to specific service accounts or users.",
                            "Consider using IAM Conditions (e.g. resource name conditions).",
                            "Enable VPC Service Controls to restrict API access by network.",
                        ],
                        gcloud_commands=[
                            f"gcloud projects remove-iam-policy-binding {binding.project_id} --member=BROAD_MEMBER --role={binding.role}",
                            f"gcloud projects add-iam-policy-binding {binding.project_id} --member=serviceAccount:SPECIFIC_SA --role={binding.role}",
                        ],
                        iac_reference="google_project_iam_binding.members",
                        docs=[
                            "https://cloud.google.com/vertex-ai/docs/general/access-control",
                            "https://cloud.google.com/iam/docs/conditions-overview",
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings


# ---------------------------------------------------------------------------
# GEM-030 — Vertex AI endpoint without private network
# ---------------------------------------------------------------------------


@CheckRegistry.register
class GEM030VertexEndpointNoPrivateNetwork(BaseCheck):
    """Vertex AI endpoint is publicly accessible (no private network configured)."""

    check_id = "GEM-030"
    title = "Vertex AI endpoint is publicly accessible (no private network configured)"
    vector = Vector.GEMINI_ABUSE
    severity_base = Severity.HIGH
    required_collectors = ["vertex_ai"]
    tags = ["vertex_ai", "gemini_abuse", "network", "public_access"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []

        for endpoint in inventory.vertex_ai_endpoints:
            if endpoint.network:
                continue  # Private network configured — PASS

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, endpoint.project_id, endpoint.name),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=7.0,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="aiplatform.googleapis.com/Endpoint",
                        resource_id=endpoint.name,
                        project_id=endpoint.project_id,
                        region=endpoint.region,
                    ),
                    evidence={
                        "endpoint_name": endpoint.name,
                        "display_name": endpoint.display_name,
                        "region": endpoint.region,
                        "network": endpoint.network or "(none — public)",
                    },
                    description=(
                        f"Vertex AI endpoint '{endpoint.display_name or endpoint.name}' "
                        f"in region '{endpoint.region}' has no private network configured. "
                        "The endpoint is reachable over the public internet, increasing "
                        "the attack surface for unauthorized model invocations."
                    ),
                    impact=(
                        "A publicly accessible Vertex AI endpoint can be targeted by "
                        "attackers who obtain valid credentials, enabling model abuse "
                        "without network-level controls."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Configure Private Service Connect or VPC peering for the "
                            "endpoint to restrict access to internal networks only."
                        ),
                        steps=[
                            "Determine the VPC network that should access this endpoint.",
                            "Configure Private Service Connect for the Vertex AI endpoint.",
                            "Update DNS to resolve the endpoint to the private IP.",
                            "Remove any public IP access if not required.",
                            "Validate that internal consumers can reach the endpoint.",
                        ],
                        gcloud_commands=[
                            f"gcloud ai endpoints update {endpoint.name} --region={endpoint.region} --network=projects/PROJECT_NUMBER/global/networks/VPC_NAME",
                        ],
                        iac_reference="google_vertex_ai_endpoint.network",
                        docs=[
                            "https://cloud.google.com/vertex-ai/docs/general/vpc-peering",
                            "https://cloud.google.com/vertex-ai/docs/predictions/using-private-endpoints",
                        ],
                        effort=RemediationEffort.HIGH,
                    ),
                    references=self.references,
                )
            )
        return findings


# ---------------------------------------------------------------------------
# GEM-040 — Vertex AI quota at default (no throttling)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# GEM-040 / GEM-041 — quota throttling
# ---------------------------------------------------------------------------


def _uncapped_quota_buckets(
    quota_info: list[dict], service_filter: str, min_limit: int
) -> list[dict]:
    """
    Return quota buckets that still sit at their default value.

    ``service_filter`` is a substring of the service name, so a caller can target
    Vertex AI (``aiplatform``) or the Gemini API (``generativelanguage``)
    independently. A bucket is returned when its effective limit equals the
    default limit and that default is >= ``min_limit`` (a small default is
    already tight enough to be an acceptable throttle).
    """
    uncapped: list[dict] = []

    for quota_entry in quota_info:
        service = quota_entry.get("service", "")
        if service_filter not in service:
            continue

        project_id = quota_entry.get("project_id", "")
        metric = quota_entry.get("metric", "")
        limit_name = quota_entry.get("limit_name", "")

        for bucket in quota_entry.get("quota_buckets", []):
            effective = bucket.get("effectiveLimit")
            default = bucket.get("defaultLimit")

            if effective is None or default is None:
                continue

            try:
                effective_int = int(effective)
                default_int = int(default)
            except (ValueError, TypeError):
                continue

            if effective_int == default_int and effective_int >= min_limit:
                uncapped.append(
                    {
                        "project_id": project_id,
                        "service": service,
                        "metric": metric,
                        "limit_name": limit_name,
                        "effective_limit": effective_int,
                        "default_limit": default_int,
                    }
                )

    return uncapped


def _group_uncapped_by_project(buckets: list[dict]) -> dict[str, list[dict]]:
    """Group uncapped quota buckets by project, so one finding covers the whole surface.

    A live scan of a single project produced 1016 buckets across 56 Generative
    Language metrics: one finding per metric buries the report (and the priority
    ranking) under a single check. The signal is "this project has no throttle",
    which is a property of the project, not of each metric.
    """
    grouped: dict[str, list[dict]] = defaultdict(list)
    for bucket in buckets:
        grouped[bucket["project_id"]].append(bucket)
    return grouped


@CheckRegistry.register
class GEM040VertexAIQuotaAtDefault(BaseCheck):
    """Vertex AI quota is at default high value — no custom throttling configured."""

    check_id = "GEM-040"
    title = "Vertex AI quota is at default high value (no throttling configured)"
    vector = Vector.GEMINI_ABUSE
    severity_base = Severity.MEDIUM
    required_collectors = ["quota"]
    tags = ["quota", "gemini_abuse", "vertex_ai", "cost_control"]

    _MIN_EFFECTIVE_LIMIT = 60  # flag if effectiveLimit >= this value
    _SERVICE = "aiplatform"

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        grouped = _group_uncapped_by_project(
            _uncapped_quota_buckets(inventory.quota_info, self._SERVICE, self._MIN_EFFECTIVE_LIMIT)
        )

        for project_id, buckets in sorted(grouped.items()):
            metrics = sorted({b["metric"] for b in buckets})
            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, project_id, self._SERVICE),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=4.0,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="serviceusage.googleapis.com/QuotaLimit",
                        resource_id=f"projects/{project_id}/services/{buckets[0]['service']}",
                        project_id=project_id,
                        region="global",
                    ),
                    evidence={
                        "project_id": project_id,
                        "service": buckets[0]["service"],
                        "metrics_at_default": len(metrics),
                        "limit_entries_at_default": len(buckets),
                        "metric_examples": metrics[:10],
                        "min_effective_limit": self._MIN_EFFECTIVE_LIMIT,
                    },
                    description=(
                        f"{len(metrics)} Vertex AI quota metric(s) in project "
                        f"'{project_id}' are still at their default value "
                        f"(>= {self._MIN_EFFECTIVE_LIMIT}), i.e. no custom throttling has "
                        f"been applied. Examples: {', '.join(metrics[:5])}."
                    ),
                    impact=(
                        "Without quota reduction, a compromised credential can consume "
                        "Vertex AI resources up to the default (high) limit before "
                        "any budget alert fires."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Reduce the Vertex AI quotas that matter for this project to "
                            "values consistent with expected usage."
                        ),
                        steps=[
                            "Analyze historical Vertex AI usage for this project.",
                            "Pick the metrics that bound abuse (prediction/generateContent RPM) rather than all of them.",
                            "Set each quota 20–30% above the expected peak usage.",
                            "Request the reductions via the Cloud Console.",
                            "Set up budget alerts to detect anomalous spend.",
                        ],
                        gcloud_commands=[
                            "# List current limits, then request reductions in the Console:",
                            f"gcloud alpha services quota list --service=aiplatform.googleapis.com --consumer=projects/{project_id}",
                            "# https://console.cloud.google.com/iam-admin/quotas",
                        ],
                        iac_reference="google_service_usage_consumer_quota_override",
                        docs=[
                            "https://cloud.google.com/docs/quota/view-manage",
                            "https://cloud.google.com/vertex-ai/docs/quotas",
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings


@CheckRegistry.register
class GEM041GeminiAPIQuotaAtDefault(BaseCheck):
    """
    Gemini API (Generative Language / AI Studio) quota is at its default value.

    This is the surface that API keys target: a key that can call
    generativelanguage.googleapis.com is bounded only by these quotas. GEM-040
    covers Vertex AI, which is a different service with different credentials
    and a different quota namespace.

    One finding per project (not per metric): the live quota namespace has 50+
    metrics with free/paid tier variants, so per-metric findings are unusable.
    """

    check_id = "GEM-041"
    title = "Gemini API (Generative Language) quota is at default value (no throttling configured)"
    vector = Vector.GEMINI_ABUSE
    severity_base = Severity.MEDIUM
    required_collectors = ["quota"]
    references = ["SOP 5.2 — cuotas de GenAI sin control"]
    tags = ["quota", "gemini_abuse", "generative_language", "api_keys", "cost_control"]

    _MIN_EFFECTIVE_LIMIT = 60  # flag if effectiveLimit >= this value
    _SERVICE = "generativelanguage"

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        grouped = _group_uncapped_by_project(
            _uncapped_quota_buckets(inventory.quota_info, self._SERVICE, self._MIN_EFFECTIVE_LIMIT)
        )

        for project_id, buckets in sorted(grouped.items()):
            metrics = sorted({b["metric"] for b in buckets})
            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, project_id, self._SERVICE),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=4.5,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="serviceusage.googleapis.com/QuotaLimit",
                        resource_id=f"projects/{project_id}/services/{buckets[0]['service']}",
                        project_id=project_id,
                        region="global",
                    ),
                    evidence={
                        "project_id": project_id,
                        "service": buckets[0]["service"],
                        "metrics_at_default": len(metrics),
                        "limit_entries_at_default": len(buckets),
                        "metric_examples": metrics[:10],
                        "min_effective_limit": self._MIN_EFFECTIVE_LIMIT,
                    },
                    description=(
                        f"{len(metrics)} Gemini API quota metric(s) in project "
                        f"'{project_id}' are still at their default value "
                        f"(>= {self._MIN_EFFECTIVE_LIMIT}), so any credential that can call "
                        "the Gemini API — including an API key — can consume the full "
                        f"default allowance. Examples: {', '.join(metrics[:5])}."
                    ),
                    impact=(
                        "An unrestricted or leaked API key has no cost throttle on the "
                        "Gemini API surface: the whole default quota can be consumed by a "
                        "single actor, and the spend only becomes visible through billing "
                        "after the fact."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Set project-level quota overrides on the Gemini API limits that "
                            "matter, and alert before the default allowance is consumed."
                        ),
                        steps=[
                            "List the Gemini API limits actually in use (generateContent, embedContent, countTokens).",
                            "Compare the defaults with the expected peak usage of the project.",
                            "Apply an override 20–30% above the expected peak on those limits.",
                            "Keep high-volume keys restricted (GEM-001/GEM-002/GEM-006) so a leaked key cannot reach the API at all.",
                            "Pair with a budget alert covering generative language spend (GEM-051).",
                        ],
                        gcloud_commands=[
                            "# Inspect current Gemini API quota limits:",
                            f"gcloud alpha services quota list --service=generativelanguage.googleapis.com --consumer=projects/{project_id}",
                            "# Overrides are requested in the Cloud Console or via Support:",
                            "# https://console.cloud.google.com/iam-admin/quotas",
                        ],
                        iac_reference="google_service_usage_consumer_quota_override",
                        docs=[
                            "https://cloud.google.com/docs/quota/view-manage",
                            "https://ai.google.dev/gemini-api/docs/rate-limits",
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings


# ---------------------------------------------------------------------------
# GEM-050 — No Org Policy restricting SA key creation
# ---------------------------------------------------------------------------


@CheckRegistry.register
class GEM050NoAPIKeyCreationRestriction(BaseCheck):
    """Org Policy does not restrict service account key creation."""

    check_id = "GEM-050"
    title = (
        "Org Policy does not restrict API key creation "
        "(iam.managed.disableServiceAccountKeyCreation absent)"
    )
    vector = Vector.GEMINI_ABUSE
    severity_base = Severity.MEDIUM
    required_collectors = ["org_policy"]
    tags = ["org_policy", "gemini_abuse", "credentials", "service_accounts"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []

        # Look for the constraint in org policies
        matching_policies = [
            p for p in inventory.org_policies if p.constraint == _SA_KEY_CREATION_CONSTRAINT
        ]

        # If the constraint is absent entirely, or all matching policies are empty → FAIL
        if not matching_policies or all(not p.policy for p in matching_policies):
            # Use the first matching resource if available, else fall back to org
            resource = (
                matching_policies[0].resource
                if matching_policies
                else (inventory.organization_id or "organization")
            )
            constraint_present = bool(matching_policies)

            findings.append(
                Finding(
                    finding_id=_make_id(
                        self.check_id,
                        inventory.organization_id or "org",
                        _SA_KEY_CREATION_CONSTRAINT,
                    ),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=5.0,
                    blast_radius="organization",
                    resource=GCPResource(
                        resource_type="orgpolicy.googleapis.com/Policy",
                        resource_id=_SA_KEY_CREATION_CONSTRAINT,
                        project_id=inventory.organization_id or "organization",
                        region="global",
                    ),
                    evidence={
                        "constraint": _SA_KEY_CREATION_CONSTRAINT,
                        "resource": resource,
                        "constraint_present": constraint_present,
                        "policy": matching_policies[0].policy if matching_policies else {},
                    },
                    description=(
                        f"The org policy constraint '{_SA_KEY_CREATION_CONSTRAINT}' is "
                        + (
                            "present but has an empty/unconfigured policy."
                            if constraint_present
                            else "absent from the organization."
                        )
                        + " Without this policy, any project owner can create exportable "
                        "service account keys that could be used to call Gemini APIs."
                    ),
                    impact=(
                        "Without this org policy, developers can create user-managed SA keys "
                        "that, if leaked, provide persistent Vertex AI / Gemini access."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Apply the org policy constraint to disable service account key "
                            "creation across the organization."
                        ),
                        steps=[
                            "Audit existing user-managed SA keys before enforcing the policy.",
                            "Migrate workloads to Workload Identity Federation.",
                            "Apply the constraint at the organization level.",
                            "Use exceptions (folder/project overrides) only where strictly needed.",
                        ],
                        gcloud_commands=[
                            "gcloud org-policies set-policy policy.yaml --organization=ORG_ID",
                            "# policy.yaml:\n# name: organizations/ORG_ID/policies/iam.disableServiceAccountKeyCreation\n# spec:\n#   rules:\n#   - enforce: true",
                        ],
                        iac_reference="google_org_policy_policy",
                        docs=[
                            "https://cloud.google.com/resource-manager/docs/organization-policy/restricting-service-accounts#disable_service_account_key_creation"
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings


# ---------------------------------------------------------------------------
# GEM-051 — No budget alert covering Vertex AI / Gemini
# ---------------------------------------------------------------------------


@CheckRegistry.register
class GEM051NoBudgetForVertexAI(BaseCheck):
    """No budget alert configured covering Vertex AI / Gemini spend."""

    check_id = "GEM-051"
    title = "No budget alert configured covering Vertex AI / Gemini spend"
    vector = Vector.GEMINI_ABUSE
    severity_base = Severity.HIGH
    required_collectors = ["billing", "service_usage"]
    tags = ["billing", "gemini_abuse", "cost_control", "budget"]

    _GEMINI_BUDGET_SERVICES = {"aiplatform", "generativelanguage"}

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []

        # If the budget API was unreadable and nothing was collected, there is nothing to
        # assert: BillingCollector recorded a coverage gap for those accounts, and both
        # "no budget" and "no budget covering Gemini" would be guesses.
        if inventory.budgets_unreadable and not inventory.budgets:
            return findings

        # Case 1: no budgets at all
        if not inventory.budgets:
            findings.append(
                Finding(
                    finding_id=_make_id(
                        self.check_id,
                        inventory.organization_id or "org",
                        "no-budgets",
                    ),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=4.5,
                    blast_radius="billing_account",
                    resource=GCPResource(
                        resource_type="billing.googleapis.com/Budget",
                        resource_id="(none)",
                        project_id=inventory.organization_id or "organization",
                        region="global",
                    ),
                    evidence={
                        "budgets_found": 0,
                        "gemini_covered": False,
                        "reason": "No budgets configured at all",
                    },
                    description=(
                        "No billing budgets are configured. Without budget alerts, "
                        "unauthorized Vertex AI / Gemini usage can go undetected until "
                        "the billing cycle closes."
                    ),
                    impact=(
                        "Unconstrained spend: a compromised credential or misconfigured "
                        "resource can generate arbitrarily large Gemini costs with no alert."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Create billing budgets with alert thresholds for Vertex AI "
                            "and Generative Language API spend."
                        ),
                        steps=[
                            "Open Cloud Billing → Budgets & alerts.",
                            "Create a budget scoped to the billing account or specific projects.",
                            "Add service filters for 'Vertex AI' and 'Generative Language API'.",
                            "Set alert thresholds at 50%, 90%, and 100% of the budget.",
                            "Configure Pub/Sub notifications for automated responses.",
                        ],
                        gcloud_commands=[
                            "# Use Cloud Console or Billing API to create budgets:",
                            "# https://console.cloud.google.com/billing/budgets",
                        ],
                        iac_reference="google_billing_budget",
                        docs=[
                            "https://cloud.google.com/billing/docs/how-to/budgets",
                            "https://cloud.google.com/billing/docs/how-to/notify",
                        ],
                        effort=RemediationEffort.LOW,
                    ),
                    references=self.references,
                )
            )
            return findings

        # Case 2: budgets exist but none cover Vertex AI / Gemini
        def _covers_gemini(budget) -> bool:
            services = budget.budget_filter.get("services", [])
            if not services:
                # Empty services list means "all services" — counts as covered
                return True
            return any(any(g in svc for g in self._GEMINI_BUDGET_SERVICES) for svc in services)

        covered_budgets = [b for b in inventory.budgets if _covers_gemini(b)]
        if covered_budgets:
            return findings  # At least one budget covers Gemini — PASS

        # No budget covers Gemini services
        existing_budget_names = [b.display_name or b.name for b in inventory.budgets]
        findings.append(
            Finding(
                finding_id=_make_id(
                    self.check_id,
                    inventory.organization_id or "org",
                    "no-gemini-budget",
                ),
                check_id=self.check_id,
                vector=self.vector,
                title=self.title,
                severity=self.severity_base,
                status=FindingStatus.FAIL,
                exploitability_score=4.5,
                blast_radius="billing_account",
                resource=GCPResource(
                    resource_type="billing.googleapis.com/Budget",
                    resource_id="(none covering Vertex AI)",
                    project_id=inventory.organization_id or "organization",
                    region="global",
                ),
                evidence={
                    "budgets_found": len(inventory.budgets),
                    "existing_budgets": existing_budget_names,
                    "gemini_covered": False,
                    "reason": "Existing budgets do not cover aiplatform or generativelanguage services",
                },
                description=(
                    f"{len(inventory.budgets)} budget(s) exist but none cover "
                    "Vertex AI ('aiplatform') or Generative Language API "
                    "('generativelanguage') services. Unauthorized Gemini usage "
                    "will not trigger any budget alert."
                ),
                impact=(
                    "Gemini abuse can generate significant costs without triggering "
                    "any existing budget alert, delaying detection."
                ),
                remediation=Remediation(
                    summary=(
                        "Create a dedicated budget for Vertex AI and Generative Language "
                        "API with alert thresholds at 50%, 90%, and 100%."
                    ),
                    steps=[
                        "Open Cloud Billing → Budgets & alerts.",
                        "Create a new budget or update an existing one.",
                        "Add service filters for 'Vertex AI' and 'Generative Language API'.",
                        "Set alert thresholds at 50%, 90%, and 100% of the budget.",
                        "Configure Pub/Sub notifications for automated quota reduction.",
                    ],
                    gcloud_commands=[
                        "# Use Cloud Console or Billing API to create budgets:",
                        "# https://console.cloud.google.com/billing/budgets",
                    ],
                    iac_reference="google_billing_budget",
                    docs=[
                        "https://cloud.google.com/billing/docs/how-to/budgets",
                        "https://cloud.google.com/billing/docs/how-to/notify",
                    ],
                    effort=RemediationEffort.LOW,
                ),
                references=self.references,
            )
        )
        return findings
