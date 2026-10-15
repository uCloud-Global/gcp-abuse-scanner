"""GKE collector — clusters, node pools, autoscaling, workload identity."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from gcp_abuse_scanner.collectors.base import BaseCollector, _fmt_exc
from gcp_abuse_scanner.models.inventory import GKECluster, ResourceInventory

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class GKECollector(BaseCollector):
    name = "gke"
    required_apis = ["container.googleapis.com"]

    def collect(
        self,
        inventory: ResourceInventory,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> None:
        container = self.build_client(inventory, "container", "v1")
        if container is None:
            return

        for project_id in project_ids:
            if not self.is_api_enabled(inventory, project_id):
                self.record_skipped_api(inventory, project_id, "container.googleapis.com")
                continue
            try:
                # list clusters across all locations using '-'
                resp = (
                    container.projects()
                    .locations()
                    .clusters()
                    .list(parent=f"projects/{project_id}/locations/-")
                    .execute()
                )
                for cluster in resp.get("clusters", []):
                    inventory.gke_clusters.append(
                        GKECluster(
                            name=cluster["name"],
                            project_id=project_id,
                            location=cluster.get("location", cluster.get("zone", "")),
                            endpoint=cluster.get("endpoint", ""),
                            master_authorized_networks_config=cluster.get(
                                "masterAuthorizedNetworksConfig", {}
                            ),
                            workload_identity_config=cluster.get("workloadIdentityConfig", {}),
                            node_pools=cluster.get("nodePools", []),
                            legacy_abac=cluster.get("legacyAbac", {}),
                            private_cluster_config=cluster.get("privateClusterConfig", {}),
                            autopilot=cluster.get("autopilot", {}),
                        )
                    )
            except Exception as exc:
                logger.warning("GKE collection failed for %s: %s", project_id, _fmt_exc(exc))
                inventory.collector_errors.append(
                    {
                        "collector": self.name,
                        "project_id": project_id,
                        "error": str(exc),
                    }
                )
