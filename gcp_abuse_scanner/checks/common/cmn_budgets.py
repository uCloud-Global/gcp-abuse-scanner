"""
Common checks — Billing budgets and cost controls.

CMN-001: Billing account with no budgets configured
CMN-002: Budget exists but has no threshold alert rules
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
from gcp_abuse_scanner.models.inventory import ResourceInventory


def _make_id(check_id: str, billing_account: str, suffix: str = "") -> str:
    key = f"{billing_account}-{suffix}"
    h = hashlib.md5(key.encode(), usedforsecurity=False).hexdigest()[:8]
    return f"{check_id}-{h}"


@CheckRegistry.register
class CMN001NoBudget(BaseCheck):
    """Billing account has no budget configured."""

    check_id = "CMN-001"
    title = "Billing account has no budget configured"
    vector = Vector.COMMON
    severity_base = Severity.HIGH
    required_collectors = ["billing"]
    tags = ["billing", "budget", "cost_control", "crypto_mining", "gemini_abuse"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []

        # Collect billing accounts referenced by projects
        billing_accounts: set[str] = set()
        for project in inventory.projects:
            if project.billing_account_id:
                billing_accounts.add(project.billing_account_id)

        # Find billing accounts with no budgets. Accounts whose budgets could not be
        # read at all are excluded: "we could not look" is not "there is no budget"
        # (they are reported as a coverage gap instead).
        accounts_with_budgets = {b.billing_account_id for b in inventory.budgets}
        unreadable = set(inventory.budgets_unreadable)

        for account_id in billing_accounts:
            if account_id in accounts_with_budgets or account_id in unreadable:
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, account_id),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=6.0,
                    blast_radius="billing_account",
                    resource=GCPResource(
                        resource_type="billing.googleapis.com/BillingAccount",
                        resource_id=account_id,
                        project_id="",
                    ),
                    evidence={
                        "billing_account_id": account_id,
                        "budgets_found": 0,
                    },
                    description=(
                        f"Billing account '{account_id}' has no budget configured. "
                        "Without a budget, crypto mining or Gemini API abuse can generate "
                        "unbounded costs that go undetected until the invoice arrives."
                    ),
                    impact=(
                        "No budget = no cost alerts. Crypto mining or Gemini abuse can "
                        "run for days/weeks before detection, generating massive bills."
                    ),
                    remediation=Remediation(
                        summary="Create a budget with threshold alerts for the billing account.",
                        steps=[
                            "Go to Cloud Console → Billing → Budgets & alerts.",
                            "Create a budget for the billing account.",
                            "Set threshold alerts at 50%, 90%, and 100% of budget.",
                            "Configure email notifications and/or Pub/Sub for automation.",
                            "Consider separate budgets per project for granular visibility.",
                        ],
                        gcloud_commands=[
                            "# Use Cloud Console or Terraform — gcloud CLI has limited budget support.\n# Terraform: google_billing_budget resource.",
                        ],
                        iac_reference="google_billing_budget",
                        docs=[
                            "https://cloud.google.com/billing/docs/how-to/budgets",
                            "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/billing_budget",
                        ],
                        effort=RemediationEffort.LOW,
                    ),
                    references=["CIS GCP — Cost Management"],
                )
            )
        return findings


@CheckRegistry.register
class CMN002BudgetNoAlerts(BaseCheck):
    """Budget exists but has no threshold alert rules configured."""

    check_id = "CMN-002"
    title = "Budget has no threshold alert rules configured"
    vector = Vector.COMMON
    severity_base = Severity.MEDIUM
    required_collectors = ["billing"]
    tags = ["billing", "budget", "cost_control"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for budget in inventory.budgets:
            if budget.threshold_rules:
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, budget.billing_account_id, budget.name),
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
                        project_id="",
                    ),
                    evidence={
                        "budget_name": budget.name,
                        "display_name": budget.display_name,
                        "billing_account_id": budget.billing_account_id,
                        "threshold_rules": [],
                    },
                    description=(
                        f"Budget '{budget.display_name or budget.name}' exists but has no "
                        "threshold alert rules. The budget limit is set but no notifications "
                        "will be sent when spending approaches or exceeds it."
                    ),
                    impact=(
                        "Budget without alerts provides no early warning of cost anomalies "
                        "from crypto mining or Gemini API abuse."
                    ),
                    remediation=Remediation(
                        summary="Add threshold alert rules (50%, 90%, 100%) to the budget.",
                        steps=[
                            "Go to Cloud Console → Billing → Budgets & alerts.",
                            f"Edit budget '{budget.display_name or budget.name}'.",
                            "Add threshold rules at 50%, 90%, and 100% of budget amount.",
                            "Configure email recipients and/or Pub/Sub topic for alerts.",
                        ],
                        gcloud_commands=[
                            "# Use Cloud Console or Terraform to add threshold rules.\n# Terraform: google_billing_budget.threshold_rules",
                        ],
                        iac_reference="google_billing_budget.threshold_rules",
                        docs=[
                            "https://cloud.google.com/billing/docs/how-to/budgets#add-threshold-rules"
                        ],
                        effort=RemediationEffort.LOW,
                    ),
                    references=[],
                )
            )
        return findings
