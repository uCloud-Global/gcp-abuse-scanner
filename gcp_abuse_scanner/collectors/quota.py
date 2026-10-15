"""Quota collector — reads service quotas for Vertex AI, Gemini API and Compute Engine."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from gcp_abuse_scanner.collectors.base import BaseCollector, _fmt_exc
from gcp_abuse_scanner.models.inventory import ResourceInventory

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Quotas we care about for abuse detection
# Format: (service, metric_name_pattern, description)
# An empty pattern matches every metric of the service — used for services whose
# metric names are not stable (the Generative Language / Gemini API quota ids
# differ between free and paid tiers and change over time).
_QUOTA_TARGETS: list[tuple[str, str, str]] = [
    # Vertex AI / Gemini
    (
        "aiplatform.googleapis.com",
        "online_prediction_requests_per_base_model_per_minute_per_project",
        "Vertex AI online prediction RPM",
    ),
    (
        "aiplatform.googleapis.com",
        "generate_content_requests_per_minute_per_project_per_base_model",
        "Gemini generateContent RPM",
    ),
    # Gemini API (AI Studio / Generative Language) — the service that API keys with
    # Gemini access target. Vertex AI quotas say nothing about this surface.
    (
        "generativelanguage.googleapis.com",
        "",
        "Gemini API (Generative Language) quota limits",
    ),
    # Compute Engine (for crypto mining scale)
    (
        "compute.googleapis.com",
        "CPUS",
        "Compute Engine CPU quota",
    ),
    (
        "compute.googleapis.com",
        "GPUS_ALL_REGIONS",
        "Compute Engine GPU quota (all regions)",
    ),
    (
        "compute.googleapis.com",
        "INSTANCES",
        "Compute Engine instance quota",
    ),
]


class QuotaCollector(BaseCollector):
    """
    Reads project-level service quotas.
    Results stored as raw dicts in inventory.quota_info (added dynamically).

    The check layer evaluates whether quotas are at default (high) values
    that provide no friction against abuse.
    """

    name = "quota"
    required_apis = ["serviceusage.googleapis.com"]

    def collect(
        self,
        inventory: ResourceInventory,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> None:
        # Initialize quota_info on inventory if not present
        if not hasattr(inventory, "quota_info"):
            object.__setattr__(inventory, "quota_info", [])

        serviceusage = self.build_client(inventory, "serviceusage", "v1beta1")
        if serviceusage is None:
            return

        for project_id in project_ids:
            try:
                self._collect_project_quotas(serviceusage, inventory, project_id)
            except Exception as exc:
                fmt = _fmt_exc(exc)
                logger.debug("Quota collection failed for %s: %s", project_id, fmt)
                self.record_skipped_api(inventory, project_id, "serviceusage.googleapis.com", fmt)

    def _collect_project_quotas(
        self,
        serviceusage: object,
        inventory: ResourceInventory,
        project_id: str,
    ) -> None:
        services_to_check = {svc for svc, _, _ in _QUOTA_TARGETS}

        for service_name in services_to_check:
            try:
                # Check if service is enabled
                enabled = any(
                    api.project_id == project_id and api.service_name == service_name
                    for api in inventory.enabled_apis
                )
                if not enabled:
                    continue

                resp = (
                    serviceusage.services()  # type: ignore
                    .consumerQuotaMetrics()
                    .list(
                        parent=f"projects/{project_id}/services/{service_name}",
                        pageSize=100,
                    )
                    .execute()
                )

                for metric in resp.get("metrics", []):
                    metric_name = metric.get("metric", "")
                    # Filter to only the metrics we care about
                    relevant = [
                        (svc, m, desc)
                        for svc, m, desc in _QUOTA_TARGETS
                        if svc == service_name and (not m or m in metric_name)
                    ]
                    if not relevant:
                        continue

                    for limit_info in metric.get("consumerQuotaLimits", []):
                        quota_entry: dict[str, Any] = {
                            "project_id": project_id,
                            "service": service_name,
                            "metric": metric_name,
                            "limit_name": limit_info.get("name", ""),
                            "unit": limit_info.get("unit", ""),
                            "quota_buckets": limit_info.get("quotaBuckets", []),
                            "is_precise": limit_info.get("isPrecise", False),
                        }
                        inventory.quota_info.append(quota_entry)  # type: ignore[attr-defined]

            except Exception as exc:
                fmt = _fmt_exc(exc)
                logger.debug("Quota fetch failed for %s/%s: %s", project_id, service_name, fmt)
                self.record_skipped_api(inventory, project_id, service_name, fmt)
