"""Vertex AI collector — endpoints, deployed models, network config."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from gcp_abuse_scanner.collectors.base import BaseCollector
from gcp_abuse_scanner.models.inventory import ResourceInventory, VertexAIEndpoint

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Regions where Vertex AI / Gemini is commonly available
_VERTEX_REGIONS = [
    "us-central1",
    "us-east1",
    "us-east4",
    "us-west1",
    "us-west4",
    "europe-west1",
    "europe-west2",
    "europe-west4",
    "asia-east1",
    "asia-northeast1",
    "asia-southeast1",
    "northamerica-northeast1",
    "southamerica-east1",
    "australia-southeast1",
]


class VertexAICollector(BaseCollector):
    name = "vertex_ai"
    required_apis = ["aiplatform.googleapis.com"]

    def collect(
        self,
        inventory: ResourceInventory,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> None:
        aiplatform = self.build_client(inventory, "aiplatform", "v1")
        if aiplatform is None:
            return

        for project_id in project_ids:
            if not self.is_api_enabled(inventory, project_id):
                self.record_skipped_api(inventory, project_id, "aiplatform.googleapis.com")
                continue
            for region in _VERTEX_REGIONS:
                try:
                    self._collect_endpoints(aiplatform, inventory, project_id, region)
                except Exception as exc:
                    # Many regions won't have endpoints — only log at debug
                    logger.debug(
                        "Vertex AI endpoint collection skipped for %s/%s: %s",
                        project_id,
                        region,
                        exc,
                    )

    def _collect_endpoints(
        self,
        aiplatform: object,
        inventory: ResourceInventory,
        project_id: str,
        region: str,
    ) -> None:
        parent = f"projects/{project_id}/locations/{region}"
        request = aiplatform.projects().locations().endpoints().list(parent=parent)  # type: ignore
        while request is not None:
            response = request.execute()
            for endpoint in response.get("endpoints", []):
                # Try to get IAM policy for the endpoint
                iam_bindings = self._get_endpoint_iam(aiplatform, endpoint.get("name", ""))
                inventory.vertex_ai_endpoints.append(
                    VertexAIEndpoint(
                        name=endpoint.get("name", "").split("/")[-1],
                        project_id=project_id,
                        region=region,
                        display_name=endpoint.get("displayName", ""),
                        network=endpoint.get("network", ""),
                        iam_bindings=iam_bindings,
                    )
                )
            request = (
                aiplatform.projects()  # type: ignore
                .locations()
                .endpoints()
                .list_next(previous_request=request, previous_response=response)
            )

    @staticmethod
    def _get_endpoint_iam(aiplatform: object, resource_name: str) -> list[dict]:
        try:
            policy = (
                aiplatform.projects()  # type: ignore
                .locations()
                .endpoints()
                .getIamPolicy(resource=resource_name)
                .execute()
            )
            return policy.get("bindings", [])
        except Exception as exc:
            logger.debug("Could not get IAM for endpoint %s: %s", resource_name, exc)
            return []
