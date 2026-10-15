"""IAM collector — project IAM policies, service accounts, and keys."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from google.cloud import asset_v1

from gcp_abuse_scanner.collectors.base import BaseCollector, _fmt_exc
from gcp_abuse_scanner.models.inventory import IAMBinding, ResourceInventory, ServiceAccountInfo

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class IAMCollector(BaseCollector):
    name = "iam"

    def collect(
        self,
        inventory: ResourceInventory,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> None:
        creds = self._auth.get_credentials()
        client = asset_v1.AssetServiceClient(credentials=creds)

        scope = (
            f"organizations/{organization_id}" if organization_id else f"projects/{project_ids[0]}"
        )

        try:
            # Use Cloud Asset to get IAM policies efficiently
            request = asset_v1.SearchAllIamPoliciesRequest(
                scope=scope,
                page_size=500,
            )
            for policy_result in client.search_all_iam_policies(request=request):
                project_id = self._extract_project(policy_result.resource, project_ids)
                if not project_id:
                    continue
                for binding in policy_result.policy.bindings:
                    inventory.iam_bindings.append(
                        IAMBinding(
                            resource=policy_result.resource,
                            resource_type=policy_result.asset_type,
                            project_id=project_id,
                            role=binding.role,
                            members=list(binding.members),
                        )
                    )
        except Exception as exc:
            logger.error("IAM collection failed: %s", _fmt_exc(exc))
            inventory.collector_errors.append({"collector": self.name, "error": str(exc)})

        # Collect service accounts and their keys
        self._collect_service_accounts(inventory, project_ids)

    def _collect_service_accounts(
        self, inventory: ResourceInventory, project_ids: list[str]
    ) -> None:
        iam_service = self.build_client(inventory, "iam", "v1")
        if iam_service is None:
            return

        for project_id in project_ids:
            try:
                sas = (
                    iam_service.projects()
                    .serviceAccounts()
                    .list(name=f"projects/{project_id}")
                    .execute()
                )
                for sa in sas.get("accounts", []):
                    keys_resp = (
                        iam_service.projects()
                        .serviceAccounts()
                        .keys()
                        .list(name=sa["name"], keyTypes=["USER_MANAGED"])
                        .execute()
                    )
                    inventory.service_accounts.append(
                        ServiceAccountInfo(
                            name=sa["name"],
                            email=sa["email"],
                            project_id=project_id,
                            disabled=sa.get("disabled", False),
                            keys=keys_resp.get("keys", []),
                        )
                    )
            except Exception as exc:
                fmt = _fmt_exc(exc)
                logger.warning("SA collection failed for %s: %s", project_id, fmt)
                # No service accounts read → CM-041/CMN-004 (and the SA half of GEM-022)
                # would silently report nothing for this project. Record the gap.
                self.record_skipped_api(inventory, project_id, "iam.googleapis.com", fmt)

    @staticmethod
    def _extract_project(resource: str, project_ids: list[str]) -> str | None:
        for pid in project_ids:
            if pid in resource:
                return pid
        return None
