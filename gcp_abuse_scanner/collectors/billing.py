"""Billing collector — billing accounts, budgets, and alert thresholds."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from gcp_abuse_scanner.collectors.base import BaseCollector, _fmt_exc
from gcp_abuse_scanner.models.inventory import BudgetInfo, ProjectInfo, ResourceInventory

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class BillingCollector(BaseCollector):
    name = "billing"
    required_apis = ["cloudbilling.googleapis.com"]

    def collect(
        self,
        inventory: ResourceInventory,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> None:
        billing = self.build_client(inventory, "cloudbilling", "v1")
        budget_client = self.build_client(inventory, "billingbudgets", "v1")
        if billing is None or budget_client is None:
            return

        # Collect billing account info per project
        billing_accounts: set[str] = set()
        for project_id in project_ids:
            try:
                info = billing.projects().getBillingInfo(name=f"projects/{project_id}").execute()
                ba_name = info.get("billingAccountName", "")
                if ba_name:
                    ba_id = ba_name.replace("billingAccounts/", "")
                    billing_accounts.add(ba_id)
                    # Update project info
                    for proj in inventory.projects:
                        if proj.project_id == project_id:
                            proj.billing_account_id = ba_id
                    # If project not in inventory yet, add minimal info
                    if not any(p.project_id == project_id for p in inventory.projects):
                        inventory.projects.append(
                            ProjectInfo(project_id=project_id, billing_account_id=ba_id)
                        )
            except Exception as exc:
                fmt = _fmt_exc(exc)
                logger.warning("Billing info failed for %s: %s", project_id, fmt)
                # No billing account for this project → no budget checks for it either.
                self.record_skipped_api(inventory, project_id, "cloudbilling.googleapis.com", fmt)

        # Collect budgets for each billing account
        for ba_id in billing_accounts:
            try:
                request = (
                    budget_client.billingAccounts()
                    .budgets()
                    .list(parent=f"billingAccounts/{ba_id}")
                )
                while request is not None:
                    response = request.execute()
                    for budget in response.get("budgets", []):
                        inventory.budgets.append(
                            BudgetInfo(
                                name=budget["name"],
                                billing_account_id=ba_id,
                                display_name=budget.get("displayName", ""),
                                amount=budget.get("amount", {}),
                                threshold_rules=budget.get("thresholdRules", []),
                                budget_filter=budget.get("budgetFilter", {}),
                            )
                        )
                    request = (
                        budget_client.billingAccounts()
                        .budgets()
                        .list_next(previous_request=request, previous_response=response)
                    )
            except Exception as exc:
                fmt = _fmt_exc(exc)
                logger.warning("Budget collection failed for billing account %s: %s", ba_id, fmt)
                # The API is commonly disabled (billingbudgets.googleapis.com) or the identity
                # lacks roles/billing.viewer. Either way we read nothing, so the budget checks
                # must not report "no budget" — record the gap for the coverage report.
                if ba_id not in inventory.budgets_unreadable:
                    inventory.budgets_unreadable.append(ba_id)
                self.record_collector_error(
                    inventory, None, f"budgets unreadable for billing account {ba_id}: {fmt}"
                )
