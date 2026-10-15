"""Service Usage collector — determines which APIs are enabled per project."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from google.cloud import service_usage_v1

from gcp_abuse_scanner.collectors.base import BaseCollector, _fmt_exc
from gcp_abuse_scanner.models.inventory import EnabledAPI, ResourceInventory

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class ServiceUsageCollector(BaseCollector):
    name = "service_usage"

    def collect(
        self,
        inventory: ResourceInventory,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> None:
        creds = self._auth.get_credentials()
        client = service_usage_v1.ServiceUsageClient(credentials=creds)

        for project_id in project_ids:
            try:
                request = service_usage_v1.ListServicesRequest(
                    parent=f"projects/{project_id}",
                    filter="state:ENABLED",
                    page_size=200,
                )
                for service in client.list_services(request=request):
                    # service.name format: projects/PROJECT/services/SERVICE_NAME
                    service_name = service.name.split("/")[-1]
                    inventory.enabled_apis.append(
                        EnabledAPI(
                            project_id=project_id,
                            service_name=service_name,
                            state="ENABLED",
                        )
                    )
            except Exception as exc:
                fmt = _fmt_exc(exc)
                logger.warning("ServiceUsage collection failed for %s: %s", project_id, fmt)
                # Every other collector gates on this data: without it they skip the project
                # and the checks behind them report nothing. Record both the project and the
                # API so the coverage gate sees it.
                inventory.inaccessible_projects.append(project_id)
                self.record_skipped_api(inventory, project_id, "serviceusage.googleapis.com", fmt)
