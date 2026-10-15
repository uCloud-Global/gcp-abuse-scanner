"""Compute Engine collector — instances, metadata, accelerators."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from gcp_abuse_scanner.collectors.base import BaseCollector, _fmt_exc
from gcp_abuse_scanner.models.inventory import ComputeInstance, ResourceInventory

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class ComputeCollector(BaseCollector):
    name = "compute"
    required_apis = ["compute.googleapis.com"]

    def collect(
        self,
        inventory: ResourceInventory,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> None:
        compute = self.build_client(inventory, "compute", "v1")
        if compute is None:
            return

        for project_id in project_ids:
            if not self.is_api_enabled(inventory, project_id):
                self.record_skipped_api(inventory, project_id, "compute.googleapis.com")
                continue
            try:
                self._collect_instances(compute, inventory, project_id)
            except Exception as exc:
                logger.warning("Compute collection failed for %s: %s", project_id, _fmt_exc(exc))
                inventory.collector_errors.append(
                    {
                        "collector": self.name,
                        "project_id": project_id,
                        "error": str(exc),
                    }
                )

    def _collect_instances(
        self, compute: object, inventory: ResourceInventory, project_id: str
    ) -> None:
        # aggregatedList returns instances across all zones
        request = compute.instances().aggregatedList(project=project_id, maxResults=500)  # type: ignore
        while request is not None:
            response = request.execute()
            for zone_data in response.get("items", {}).values():
                for instance in zone_data.get("instances", []):
                    # Parse metadata items into dict
                    metadata_items = {}
                    for item in instance.get("metadata", {}).get("items", []):
                        metadata_items[item["key"]] = item.get("value", "")

                    inventory.compute_instances.append(
                        ComputeInstance(
                            name=instance["name"],
                            project_id=project_id,
                            zone=instance["zone"].split("/")[-1],
                            machine_type=instance.get("machineType", "").split("/")[-1],
                            status=instance.get("status", ""),
                            network_interfaces=instance.get("networkInterfaces", []),
                            metadata=metadata_items,
                            service_accounts=instance.get("serviceAccounts", []),
                            shielded_instance_config=instance.get("shieldedInstanceConfig", {}),
                            labels=instance.get("labels", {}),
                            tags=instance.get("tags", {}).get("items", []),
                            accelerators=instance.get("accelerators", []),
                            self_link=instance.get("selfLink", ""),
                        )
                    )
            request = compute.instances().aggregatedList_next(  # type: ignore
                previous_request=request, previous_response=response
            )
