"""Network collector — firewall rules, VPC, public IPs."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from gcp_abuse_scanner.collectors.base import BaseCollector, _fmt_exc
from gcp_abuse_scanner.models.inventory import FirewallRule, ResourceInventory

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class NetworkCollector(BaseCollector):
    name = "network"
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
                # No Compute API → no firewall rules → CM-003/CM-004/CM-008/CM-050
                # would silently "pass". Record the gap instead.
                self.record_skipped_api(inventory, project_id, "compute.googleapis.com")
                continue
            try:
                request = compute.firewalls().list(project=project_id)  # type: ignore
                while request is not None:
                    response = request.execute()
                    for rule in response.get("items", []):
                        inventory.firewall_rules.append(
                            FirewallRule(
                                name=rule["name"],
                                project_id=project_id,
                                network=rule.get("network", "").split("/")[-1],
                                direction=rule.get("direction", "INGRESS"),
                                priority=rule.get("priority", 1000),
                                source_ranges=rule.get("sourceRanges", []),
                                destination_ranges=rule.get("destinationRanges", []),
                                allowed=rule.get("allowed", []),
                                denied=rule.get("denied", []),
                                target_tags=rule.get("targetTags", []),
                                disabled=rule.get("disabled", False),
                            )
                        )
                    request = compute.firewalls().list_next(  # type: ignore
                        previous_request=request, previous_response=response
                    )
            except Exception as exc:
                fmt = _fmt_exc(exc)
                logger.warning("Network collection failed for %s: %s", project_id, fmt)
                self.record_collector_error(inventory, project_id, fmt)
