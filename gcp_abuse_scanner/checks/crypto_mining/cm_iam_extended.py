"""
Crypto Mining checks — IAM / Network (extended).

CM-040: Broad compute-creation roles granted to wide principals
CM-042: iam.serviceAccountTokenCreator or serviceAccountUser granted broadly
CM-045: IAM Recommender identifies SA with unused compute permissions
CM-046: Personal (consumer email) accounts granted Owner or Editor
CM-050: VPC has no egress deny-all firewall rule (unrestricted outbound traffic)
CM-060: Project or billing account has no budget or budget alert configured
"""

from __future__ import annotations

import hashlib
from collections import defaultdict

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

_BROAD_COMPUTE_ROLES = {
    "roles/compute.admin",
    "roles/compute.instanceAdmin",
    "roles/compute.instanceAdmin.v1",
    "roles/container.admin",
    "roles/container.clusterAdmin",
}

_ACT_AS_ROLES = {
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
}

_COMPUTE_ROLE_KEYWORDS = ("compute.", "container.", "run.")

_RECOMMENDER_REMOVE_SUBTYPES = {"REMOVE_ROLE", "REPLACE_ROLE"}

# Highest-privilege project roles that should never belong to personal accounts.
_PRIVILEGED_ROLES = {"roles/owner", "roles/editor"}

# Well-known consumer email domains. A user: member on one of these domains is a
# personal account — outside the organization's identity lifecycle (no MFA
# enforcement, no offboarding, no key rotation policy).
_PERSONAL_EMAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "msn.com",
    "icloud.com",
    "aol.com",
    "protonmail.com",
    "proton.me",
    "gmx.com",
    "mail.com",
    "yandex.com",
    "zoho.com",
}


def _make_id(check_id: str, project_id: str, key: str) -> str:
    h = hashlib.md5(key.encode(), usedforsecurity=False).hexdigest()[:8]
    return f"{check_id}-{project_id}-{h}"


def _is_broad_member(member: str) -> bool:
    """Return True if the member represents a wide/public principal."""
    return member in ("allUsers", "allAuthenticatedUsers") or member.startswith("domain:")


# ---------------------------------------------------------------------------
# CM-040
# ---------------------------------------------------------------------------


@CheckRegistry.register
class CM040BroadComputeCreationRoles(BaseCheck):
    """
    Service account or principal has broad compute creation roles
    (compute.admin, container.admin, etc.) granted to a wide audience.
    """

    check_id = "CM-040"
    title = (
        "Service account or principal has broad compute creation roles "
        "(compute.admin, container.admin)"
    )
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.HIGH
    required_collectors = ["iam"]
    references = ["CIS GCP 1.5", "CIS GCP 7.1"]
    tags = ["iam", "compute", "privilege_escalation", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for binding in inventory.iam_bindings:
            if binding.role not in _BROAD_COMPUTE_ROLES:
                continue

            members = binding.members
            broad_members = [m for m in members if _is_broad_member(m)]
            is_broad = bool(broad_members) or len(members) > 3

            if not is_broad:
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
                        "members": members,
                        "broad_members": broad_members,
                        "member_count": len(members),
                    },
                    description=(
                        f"Role '{binding.role}' — which allows creation and management of "
                        "compute resources — is granted to a broad set of principals "
                        f"({len(members)} member(s)"
                        + (f", including {broad_members}" if broad_members else "")
                        + f") on resource '{binding.resource}'. "
                        "Any principal with this role can spin up VMs, GKE nodes, or "
                        "Cloud Run services for crypto mining at the project's expense."
                    ),
                    impact=(
                        "Broad compute creation roles allow any holder to provision "
                        "high-CPU/GPU instances for crypto mining, leading to runaway "
                        "billing and potential data exfiltration."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Restrict broad compute roles to specific, named service accounts "
                            "with documented justification. Replace with more granular roles "
                            "where possible."
                        ),
                        steps=[
                            "Audit who legitimately needs this role and why.",
                            "Remove the binding for any principal that does not require it.",
                            "Replace 'compute.admin' with narrower roles such as 'compute.instanceAdmin.v1' scoped to specific resources.",
                            "For domain: or allUsers members, remove immediately and investigate for potential compromise.",
                            "Enable Org Policy: constraints/iam.allowedPolicyMemberDomains.",
                        ],
                        gcloud_commands=[
                            f"gcloud projects get-iam-policy {binding.project_id} --format=json > policy.json",
                            "# Edit policy.json to remove the offending binding, then:",
                            f"gcloud projects set-iam-policy {binding.project_id} policy.json",
                        ],
                        iac_reference="google_project_iam_binding",
                        docs=[
                            "https://cloud.google.com/iam/docs/understanding-roles#compute-roles",
                            "https://cloud.google.com/iam/docs/recommender-overview",
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings


# ---------------------------------------------------------------------------
# CM-042
# ---------------------------------------------------------------------------


@CheckRegistry.register
class CM042BroadServiceAccountActAs(BaseCheck):
    """
    iam.serviceAccountTokenCreator or serviceAccountUser granted broadly
    (allUsers, allAuthenticatedUsers, domain:, or group:).
    """

    check_id = "CM-042"
    title = "iam.serviceAccountTokenCreator or serviceAccountUser granted broadly"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.HIGH
    required_collectors = ["iam"]
    references = ["CIS GCP 1.6"]
    tags = ["iam", "service_account", "impersonation", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for binding in inventory.iam_bindings:
            if binding.role not in _ACT_AS_ROLES:
                continue

            broad_members = [m for m in binding.members if self._is_broadly_granted(m)]
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
                    exploitability_score=8.5,
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
                        f"Role '{binding.role}' is granted to broad principals "
                        f"{broad_members} on resource '{binding.resource}'. "
                        "This role allows the holder to impersonate service accounts, "
                        "including those with compute creation permissions, enabling "
                        "privilege escalation and crypto mining under a trusted identity."
                    ),
                    impact=(
                        "An attacker who can impersonate a powerful service account can "
                        "create VMs, GKE clusters, or Cloud Run services for crypto mining, "
                        "with actions attributed to the impersonated SA."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Restrict 'actAs' roles to specific, named service accounts. "
                            "Audit all principals that can impersonate SAs with compute power."
                        ),
                        steps=[
                            "Identify which service accounts are targeted by this binding.",
                            "Remove allUsers, allAuthenticatedUsers, domain:, and group: members.",
                            "Grant 'roles/iam.serviceAccountUser' only to specific, named service accounts or users with documented justification.",
                            "Audit the permissions of the impersonated SA — if it has compute creation roles, treat this as CRITICAL.",
                            "Enable VPC Service Controls to limit SA token usage.",
                        ],
                        gcloud_commands=[
                            f"gcloud projects remove-iam-policy-binding {binding.project_id} --member=BROAD_MEMBER --role={binding.role}",
                        ],
                        iac_reference="google_service_account_iam_binding",
                        docs=[
                            "https://cloud.google.com/iam/docs/impersonating-service-accounts",
                            "https://cloud.google.com/iam/docs/best-practices-service-accounts",
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings

    @staticmethod
    def _is_broadly_granted(member: str) -> bool:
        return (
            member in ("allUsers", "allAuthenticatedUsers")
            or member.startswith("domain:")
            or member.startswith("group:")
        )


# ---------------------------------------------------------------------------
# CM-045
# ---------------------------------------------------------------------------


@CheckRegistry.register
class CM045RecommenderOverpermissionedSA(BaseCheck):
    """
    IAM Recommender identifies a service account with unused compute permissions
    that should be removed or replaced.
    """

    check_id = "CM-045"
    title = "IAM Recommender identifies service account with unused compute permissions"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.MEDIUM
    required_collectors = ["recommender"]
    references = []
    tags = ["iam", "recommender", "least_privilege", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for insight in inventory.recommender_insights:
            if not self._is_relevant(insight):
                continue

            project_id = insight.get("project_id", "unknown")
            description = insight.get("description", "")
            content = insight.get("content", {})
            priority = insight.get("priority", "P4")
            recommender_subtype = insight.get("recommender_subtype", "")

            findings.append(
                Finding(
                    finding_id=_make_id(
                        self.check_id,
                        project_id,
                        insight.get("name", description),
                    ),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=5.0,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="iam.googleapis.com/ServiceAccount",
                        resource_id=insight.get("name", "unknown"),
                        project_id=project_id,
                    ),
                    evidence={
                        "recommender_subtype": recommender_subtype,
                        "description": description,
                        "priority": priority,
                        "content": content,
                    },
                    description=(
                        f"IAM Recommender has flagged a '{recommender_subtype}' recommendation "
                        f'involving compute-related permissions: "{description}". '
                        "Over-permissioned service accounts with unused compute roles represent "
                        "a standing risk — if compromised, they can be used to provision "
                        "resources for crypto mining without triggering immediate alerts."
                    ),
                    impact=(
                        "Unused compute permissions on a service account provide a latent "
                        "attack vector. A compromised SA can create VMs or GKE nodes for "
                        "crypto mining, with the excess permissions going unnoticed."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Apply the IAM Recommender suggestion: remove or replace the "
                            "over-permissioned role with a more granular alternative."
                        ),
                        steps=[
                            "Review the full recommendation in the GCP Console under IAM & Admin > Recommender.",
                            "Validate that removing the role will not break any workload.",
                            "Apply the recommendation (remove or replace the role).",
                            "Set up periodic IAM Recommender reviews (e.g. monthly).",
                        ],
                        gcloud_commands=[
                            "# List active IAM recommendations for a project:",
                            f"gcloud recommender recommendations list --project={project_id} --recommender=google.iam.policy.Recommender --location=global",
                        ],
                        iac_reference="google_project_iam_binding",
                        docs=[
                            "https://cloud.google.com/iam/docs/recommender-overview",
                            "https://cloud.google.com/iam/docs/recommender-managing",
                        ],
                        effort=RemediationEffort.LOW,
                    ),
                    references=self.references,
                )
            )
        return findings

    @staticmethod
    def _is_relevant(insight: dict) -> bool:
        """
        Return True if the insight is a REMOVE_ROLE/REPLACE_ROLE recommendation
        that mentions compute, container, or run roles.
        """
        subtype = insight.get("recommender_subtype", "")
        if subtype not in _RECOMMENDER_REMOVE_SUBTYPES:
            return False

        # Check description and content for compute-related role keywords
        haystack = " ".join(
            [
                insight.get("description", ""),
                str(insight.get("content", "")),
            ]
        ).lower()

        return any(kw in haystack for kw in _COMPUTE_ROLE_KEYWORDS)


# ---------------------------------------------------------------------------
# CM-046
# ---------------------------------------------------------------------------


@CheckRegistry.register
class CM046PersonalAccountPrivilegedRole(BaseCheck):
    """
    A personal (consumer email) account holds Owner or Editor on the project
    or on a resource inside it.

    Personal accounts sit outside the organization's identity lifecycle: no
    enforced 2SV, no centralized offboarding, no password/key rotation policy.
    Ownership is granted to an individual who may leave the organization while
    keeping full control of the project.

    Scope note: this check matches well-known consumer domains only (gmail.com
    and friends). Detecting *external corporate* domains (someone@vendor.com)
    would require the organization's Cloud Identity directory, which the
    scanner does not read — see docs/checks/crypto_mining.md.
    """

    check_id = "CM-046"
    title = "Personal (consumer email) account holds Owner or Editor"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.CRITICAL
    required_collectors = ["iam"]
    references = ["CIS GCP 1.1", "SOP 5.2 — cuentas @gmail.com como Owner/Editor"]
    tags = ["iam", "identity", "crypto_mining", "cloud_identity"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for binding in inventory.iam_bindings:
            if binding.role.lower() not in _PRIVILEGED_ROLES:
                continue

            personal = [m for m in binding.members if _personal_email_domain(m)]
            if not personal:
                continue

            for member in personal:
                domain = _personal_email_domain(member)
                findings.append(
                    Finding(
                        finding_id=_make_id(
                            self.check_id,
                            binding.project_id,
                            f"{binding.resource}-{binding.role}-{member}",
                        ),
                        check_id=self.check_id,
                        vector=self.vector,
                        title=self.title,
                        severity=self.severity_base,
                        status=FindingStatus.FAIL,
                        exploitability_score=9.0,
                        blast_radius="project",
                        resource=GCPResource(
                            resource_type=binding.resource_type,
                            resource_id=binding.resource,
                            project_id=binding.project_id,
                        ),
                        evidence={
                            "role": binding.role,
                            "member": member,
                            "email_domain": domain,
                            "all_members": binding.members,
                        },
                        description=(
                            f"Role '{binding.role}' is granted to the personal account "
                            f"'{member}' (domain '{domain}') on '{binding.resource}'. The "
                            "account is not governed by the organization's Cloud Identity: "
                            "2SV cannot be enforced, access is not revoked when the person "
                            "leaves, and the credential lifecycle is out of your control."
                        ),
                        impact=(
                            f"'{member}' is a full project administrator. If the personal "
                            "account is compromised (reused password, no enforced 2SV, "
                            "phishing), the attacker inherits Owner/Editor rights and can "
                            "provision compute resources, move data, or disable logging — "
                            "billed to this project and invisible to the organization's "
                            "identity controls."
                        ),
                        remediation=Remediation(
                            summary=(
                                "Migrate the personal account to an organization-managed "
                                "identity (Cloud Identity or Workspace), then remove the "
                                "personal binding and enforce the domain restriction policy."
                            ),
                            steps=[
                                "Confirm who owns the personal account and why it has this role.",
                                "Create (or identify) the equivalent identity in Cloud Identity/Workspace.",
                                "Grant the role to that managed identity and validate access.",
                                "Remove the personal account from the binding.",
                                "Enforce constraints/iam.allowedPolicyMemberDomains so personal accounts cannot be re-granted.",
                                "Audit Cloud Audit Logs for actions performed by the personal account.",
                            ],
                            gcloud_commands=[
                                f"gcloud projects add-iam-policy-binding {binding.project_id} --member='user:managed@your-domain.com' --role='{binding.role}'",
                                f"gcloud projects remove-iam-policy-binding {binding.project_id} --member='{member}' --role='{binding.role}'",
                                "# Org-wide (see docs/iam-setup.md for the policy file):\n"
                                "gcloud resource-manager org-policies set-policy --organization=ORG_ID allowed-domains.yaml",
                            ],
                            iac_reference="google_project_iam_binding.members",
                            docs=[
                                "https://cloud.google.com/resource-manager/docs/organization-policy/restricting-domains",
                                "https://cloud.google.com/identity/docs/overview",
                            ],
                            effort=RemediationEffort.MEDIUM,
                        ),
                        references=self.references,
                    )
                )
        return findings


def _personal_email_domain(member: str) -> str:
    """Return the consumer domain of a `user:` member, or '' when it is not one."""
    if not member.startswith("user:"):
        return ""
    email = member.split(":", 1)[1].strip()
    if "@" not in email:
        return ""
    domain = email.rsplit("@", 1)[-1].lower()
    return domain if domain in _PERSONAL_EMAIL_DOMAINS else ""


# ---------------------------------------------------------------------------
# CM-050
# ---------------------------------------------------------------------------


@CheckRegistry.register
class CM050NoEgressRestriction(BaseCheck):
    """
    VPC has no egress deny-all firewall rule, leaving outbound traffic unrestricted.
    Without a low-priority deny-all egress rule, VMs can freely reach crypto mining
    pools on the internet.
    """

    check_id = "CM-050"
    title = "VPC has no egress deny-all firewall rule (unrestricted outbound traffic)"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.HIGH
    required_collectors = ["network"]
    references = ["CIS GCP 3.10"]
    tags = ["network", "firewall", "egress", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []

        # Group firewall rules by project
        rules_by_project: dict[str, list] = defaultdict(list)
        for rule in inventory.firewall_rules:
            rules_by_project[rule.project_id].append(rule)

        for project_id, rules in rules_by_project.items():
            egress_rules = [r for r in rules if r.direction == "EGRESS" and not r.disabled]

            has_deny_all_egress = any(self._is_deny_all_egress(r) for r in egress_rules)
            if has_deny_all_egress:
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(
                        self.check_id,
                        project_id,
                        project_id,
                    ),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=6.0,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="compute.googleapis.com/Project",
                        resource_id=project_id,
                        project_id=project_id,
                    ),
                    evidence={
                        "project_id": project_id,
                        "existing_egress_rules": [
                            {
                                "name": r.name,
                                "network": r.network,
                                "priority": r.priority,
                                "destination_ranges": r.destination_ranges,
                                "denied": r.denied,
                            }
                            for r in egress_rules
                        ],
                    },
                    description=(
                        f"Project '{project_id}' has no egress deny-all firewall rule "
                        "(a DENY rule targeting 0.0.0.0/0 with priority ≥ 65000). "
                        "Without this control, any VM in the project can freely initiate "
                        "outbound connections to crypto mining pools, C2 servers, or "
                        "data exfiltration endpoints on the internet."
                    ),
                    impact=(
                        "Unrestricted egress allows compromised or malicious VMs to "
                        "connect to crypto mining pools, exfiltrate data, or receive "
                        "commands from attacker-controlled infrastructure without detection."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Create a low-priority egress deny-all rule and explicitly "
                            "allowlist only the destination IPs/ports required by workloads."
                        ),
                        steps=[
                            "Inventory all legitimate outbound destinations for workloads in this project.",
                            "Create explicit ALLOW egress rules for those destinations with a priority lower than 65000 (e.g. 1000).",
                            "Create a catch-all DENY egress rule targeting 0.0.0.0/0 with priority 65534.",
                            "Monitor VPC Flow Logs for unexpected egress traffic.",
                            "Consider Cloud Armor or Cloud IDS for additional egress inspection.",
                        ],
                        gcloud_commands=[
                            f"gcloud compute firewall-rules create deny-all-egress-{project_id} --project={project_id} --direction=EGRESS --action=DENY --rules=all --destination-ranges=0.0.0.0/0 --priority=65534 --network=default",
                        ],
                        iac_reference="google_compute_firewall.direction=EGRESS",
                        docs=[
                            "https://cloud.google.com/vpc/docs/firewalls#egress_rules_applicable_to_traffic_leaving_the_network",
                            "https://cloud.google.com/vpc/docs/using-firewalls",
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings

    @staticmethod
    def _is_deny_all_egress(rule) -> bool:
        """
        Return True if the rule is an active EGRESS deny rule targeting 0.0.0.0/0
        with a priority that makes it a catch-all (>= 65000).
        """
        if rule.direction != "EGRESS":
            return False
        if not rule.denied:
            return False
        if "0.0.0.0/0" not in rule.destination_ranges:
            return False
        if rule.priority < 65000:
            return False
        return True


# ---------------------------------------------------------------------------
# CM-060
# ---------------------------------------------------------------------------


@CheckRegistry.register
class CM060NoBudgetAlert(BaseCheck):
    """
    Project or billing account has no budget or budget alert configured.
    Without budget alerts, crypto mining attacks can go undetected until the
    billing cycle closes.
    """

    check_id = "CM-060"
    title = "Project or billing account has no budget or budget alert configured"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.HIGH
    required_collectors = ["billing"]
    references = []
    tags = ["billing", "budget", "cost_control", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []

        # If the budget API was unreadable and nothing was collected, there is nothing to
        # assert: BillingCollector recorded a coverage gap for those accounts, and both
        # "no budget" and "no budget covering Gemini" would be guesses.
        if inventory.budgets_unreadable and not inventory.budgets:
            return findings

        # Case 1: No budgets at all
        if not inventory.budgets:
            findings.append(
                Finding(
                    finding_id=_make_id(
                        self.check_id,
                        "global",
                        "no-budgets-configured",
                    ),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=4.0,
                    blast_radius="billing_account",
                    resource=GCPResource(
                        resource_type="billing.googleapis.com/BillingAccount",
                        resource_id="no-budget-configured",
                        project_id="global",
                    ),
                    evidence={
                        "budgets": [],
                        "reason": "No budgets found in the billing account.",
                    },
                    description=(
                        "No budgets are configured for this billing account. "
                        "Without budget alerts, a crypto mining attack that provisions "
                        "large numbers of VMs or GPUs can go completely undetected until "
                        "the monthly invoice arrives, by which time costs may be enormous."
                    ),
                    impact=(
                        "Crypto mining attacks can generate thousands of dollars in "
                        "compute costs within hours. Without budget alerts, there is no "
                        "automated mechanism to detect or respond to cost anomalies."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Create at least one budget with threshold alerts at 50%, "
                            "90%, and 100% of the expected monthly spend."
                        ),
                        steps=[
                            "Navigate to Billing > Budgets & Alerts in the GCP Console.",
                            "Create a budget covering all projects in the billing account.",
                            "Set threshold rules at 50%, 90%, and 100% of the budget amount.",
                            "Configure email notifications and/or Pub/Sub alerts for automated response (e.g. disable billing on breach).",
                            "Consider setting a budget for each project individually in addition to the account-level budget.",
                        ],
                        gcloud_commands=[
                            "# Create a budget via the Billing API (requires billing admin):",
                            "gcloud billing budgets create --billing-account=BILLING_ACCOUNT_ID --display-name='Monthly Spend Alert' --budget-amount=1000USD --threshold-rule=percent=0.5 --threshold-rule=percent=0.9 --threshold-rule=percent=1.0",
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

        # Case 2: Budgets exist but some have no threshold rules
        for budget in inventory.budgets:
            if budget.threshold_rules:
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(
                        self.check_id,
                        budget.billing_account_id,
                        budget.name,
                    ),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=4.0,
                    blast_radius="billing_account",
                    resource=GCPResource(
                        resource_type="billing.googleapis.com/Budget",
                        resource_id=budget.name,
                        project_id=budget.billing_account_id,
                    ),
                    evidence={
                        "budget_name": budget.name,
                        "display_name": budget.display_name,
                        "billing_account_id": budget.billing_account_id,
                        "amount": budget.amount,
                        "threshold_rules": budget.threshold_rules,
                    },
                    description=(
                        f"Budget '{budget.display_name or budget.name}' on billing account "
                        f"'{budget.billing_account_id}' has no threshold alert rules configured. "
                        "A budget without alerts provides no notification when spend approaches "
                        "or exceeds the limit, leaving crypto mining cost spikes undetected."
                    ),
                    impact=(
                        "Without threshold alerts, a crypto mining attack can exhaust the "
                        "budget silently. Operators will not be notified until the billing "
                        "cycle closes or the budget is manually reviewed."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Add threshold alert rules at 50%, 90%, and 100% to the existing "
                            "budget to ensure timely notification of cost anomalies."
                        ),
                        steps=[
                            "Navigate to Billing > Budgets & Alerts in the GCP Console.",
                            f"Edit budget '{budget.display_name or budget.name}'.",
                            "Add threshold rules at 50%, 90%, and 100% of the budget amount.",
                            "Verify that notification channels (email, Pub/Sub) are configured.",
                        ],
                        gcloud_commands=[
                            f"gcloud billing budgets update {budget.name} --threshold-rule=percent=0.5 --threshold-rule=percent=0.9 --threshold-rule=percent=1.0",
                        ],
                        iac_reference="google_billing_budget.threshold_rules",
                        docs=[
                            "https://cloud.google.com/billing/docs/how-to/budgets#add-threshold-rules",
                        ],
                        effort=RemediationEffort.LOW,
                    ),
                    references=self.references,
                )
            )
        return findings
