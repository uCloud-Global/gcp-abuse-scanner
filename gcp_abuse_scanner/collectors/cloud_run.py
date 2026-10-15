"""Cloud Run collector — services, jobs, ingress settings, public invokers."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from gcp_abuse_scanner.collectors.base import BaseCollector, _fmt_exc
from gcp_abuse_scanner.models.inventory import CloudRunService, ResourceInventory

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class CloudRunCollector(BaseCollector):
    name = "cloud_run"
    required_apis = ["run.googleapis.com"]

    def collect(
        self,
        inventory: ResourceInventory,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> None:
        run = self.build_client(inventory, "run", "v2")
        if run is None:
            return

        for project_id in project_ids:
            if not self.is_api_enabled(inventory, project_id):
                self.record_skipped_api(inventory, project_id, "run.googleapis.com")
                continue
            try:
                self._collect_services(run, inventory, project_id)
            except Exception as exc:
                logger.warning("Cloud Run collection failed for %s: %s", project_id, _fmt_exc(exc))
                inventory.collector_errors.append(
                    {
                        "collector": self.name,
                        "project_id": project_id,
                        "error": str(exc),
                    }
                )

    def _collect_services(self, run: Any, inventory: ResourceInventory, project_id: str) -> None:
        # List services across all regions using '-'
        parent = f"projects/{project_id}/locations/-"
        request = run.projects().locations().services().list(parent=parent)  # type: ignore
        while request is not None:
            response = request.execute()
            for svc in response.get("services", []):
                # Extract region from name: projects/P/locations/REGION/services/NAME
                parts = svc.get("name", "").split("/")
                region = parts[3] if len(parts) > 3 else ""

                # Get IAM policy for this service to check for allUsers invoker
                iam_bindings = self._get_service_iam(run, svc.get("name", ""))

                # Extract scaling config from template
                template = svc.get("template", {})
                scaling = svc.get("scaling", {})

                inventory.cloud_run_services.append(
                    CloudRunService(
                        name=svc.get("name", "").split("/")[-1],
                        project_id=project_id,
                        region=region,
                        ingress=svc.get("ingress", ""),
                        iam_bindings=iam_bindings,
                        scaling=scaling,
                        template=template,
                    )
                )
            request = (
                run.projects()
                .locations()
                .services()
                .list_next(previous_request=request, previous_response=response)  # type: ignore
            )

    @staticmethod
    def _get_service_iam(run: Any, resource_name: str) -> list[dict[str, Any]]:
        """Fetch IAM policy for a Cloud Run service."""
        try:
            policy = (
                run.projects()  # type: ignore
                .locations()
                .services()
                .getIamPolicy(resource=resource_name)
                .execute()
            )
            return policy.get("bindings", [])
        except Exception as exc:
            logger.debug("Could not get IAM for %s: %s", resource_name, exc)
            return []
