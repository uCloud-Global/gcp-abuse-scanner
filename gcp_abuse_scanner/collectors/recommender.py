"""Recommender collector — IAM recommender insights (over-permissioned SAs)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from gcp_abuse_scanner.collectors.base import BaseCollector
from gcp_abuse_scanner.models.inventory import ResourceInventory

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# IAM recommender insight type
_IAM_RECOMMENDER_ID = "google.iam.policy.Recommender"

# Locations where IAM recommender is available
_RECOMMENDER_LOCATIONS = ["global"]


class RecommenderCollector(BaseCollector):
    """
    Collects IAM Recommender insights — identifies service accounts with
    permissions they haven't used (over-permissioned), which are prime
    targets for privilege escalation into crypto mining or Gemini abuse.

    Results are stored as raw dicts in inventory.recommender_insights
    (added to ResourceInventory dynamically).
    """

    name = "recommender"
    required_apis = ["recommender.googleapis.com"]

    def collect(
        self,
        inventory: ResourceInventory,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> None:
        recommender = self.build_client(inventory, "recommender", "v1")
        if recommender is None:
            return

        # Initialize recommender_insights on inventory if not present
        if not hasattr(inventory, "recommender_insights"):
            object.__setattr__(inventory, "recommender_insights", [])

        for project_id in project_ids:
            if not self.is_api_enabled(inventory, project_id):
                self.record_skipped_api(inventory, project_id, "recommender.googleapis.com")
                continue
            for location in _RECOMMENDER_LOCATIONS:
                try:
                    self._collect_iam_recommendations(recommender, inventory, project_id, location)
                except Exception as exc:
                    logger.debug(
                        "Recommender collection failed for %s/%s: %s",
                        project_id,
                        location,
                        exc,
                    )

    def _collect_iam_recommendations(
        self,
        recommender: object,
        inventory: ResourceInventory,
        project_id: str,
        location: str,
    ) -> None:
        parent = f"projects/{project_id}/locations/{location}/recommenders/{_IAM_RECOMMENDER_ID}"
        try:
            request = (
                recommender.projects()  # type: ignore
                .locations()
                .recommenders()
                .recommendations()
                .list(parent=parent, filter="stateInfo.state=ACTIVE")
            )
            while request is not None:
                response = request.execute()
                for rec in response.get("recommendations", []):
                    insight: dict[str, Any] = {
                        "project_id": project_id,
                        "name": rec.get("name", ""),
                        "description": rec.get("description", ""),
                        "recommender_subtype": rec.get("recommenderSubtype", ""),
                        "primary_impact": rec.get("primaryImpact", {}),
                        "content": rec.get("content", {}),
                        "state": rec.get("stateInfo", {}).get("state", ""),
                        "priority": rec.get("priority", ""),
                    }
                    inventory.recommender_insights.append(insight)  # type: ignore[attr-defined]
                request = (
                    recommender.projects()  # type: ignore
                    .locations()
                    .recommenders()
                    .recommendations()
                    .list_next(previous_request=request, previous_response=response)
                )
        except Exception as exc:
            logger.debug("IAM recommender list failed for %s: %s", project_id, exc)
