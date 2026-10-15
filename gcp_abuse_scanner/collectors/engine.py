"""Collector engine — orchestrates all collectors with concurrency."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING

from gcp_abuse_scanner.collectors.base import _fmt_exc
from gcp_abuse_scanner.models.inventory import ResourceInventory

if TYPE_CHECKING:
    from gcp_abuse_scanner.auth.manager import AuthManager
    from gcp_abuse_scanner.collectors.base import BaseCollector
    from gcp_abuse_scanner.collectors.cache import InventoryCache

logger = logging.getLogger(__name__)

_MAX_WORKERS = 10


class CollectorEngine:
    """
    Runs all collectors concurrently across projects.
    Populates and returns a ResourceInventory.

    Execution order:
      1. ServiceUsageCollector  — must run first so other collectors can
                                  check which APIs are enabled per project.
      2. All remaining collectors — run concurrently.
    """

    def __init__(
        self,
        auth_manager: AuthManager,
        max_workers: int = _MAX_WORKERS,
        cache: InventoryCache | None = None,
        timeout: float | None = None,
        transport: str | None = None,
    ) -> None:
        self._auth = auth_manager
        self._max_workers = max_workers
        self._cache = cache
        self._timeout = timeout
        self._transport = transport

    def _new_collector(self, collector_cls: type[BaseCollector]) -> BaseCollector:
        """Instantiate a collector with the engine's transport settings."""
        return collector_cls(self._auth, timeout=self._timeout, transport=self._transport)

    def collect(
        self,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> ResourceInventory:
        from gcp_abuse_scanner.collectors.api_keys import APIKeysCollector
        from gcp_abuse_scanner.collectors.billing import BillingCollector
        from gcp_abuse_scanner.collectors.cloud_run import CloudRunCollector
        from gcp_abuse_scanner.collectors.compute import ComputeCollector
        from gcp_abuse_scanner.collectors.gke import GKECollector
        from gcp_abuse_scanner.collectors.iam import IAMCollector
        from gcp_abuse_scanner.collectors.network import NetworkCollector
        from gcp_abuse_scanner.collectors.org_policy import OrgPolicyCollector
        from gcp_abuse_scanner.collectors.quota import QuotaCollector
        from gcp_abuse_scanner.collectors.recommender import RecommenderCollector
        from gcp_abuse_scanner.collectors.service_usage import ServiceUsageCollector
        from gcp_abuse_scanner.collectors.vertex_ai import VertexAICollector

        # ── Cache lookup ─────────────────────────────────────────────────────
        if self._cache is not None:
            cached_inventory = self._cache.get(project_ids, organization_id)
            if cached_inventory is not None:
                cache_key = self._cache._cache_key(project_ids, organization_id)
                logger.info("Using cached inventory (key=%s)", cache_key)
                return cached_inventory

        inventory = ResourceInventory(
            organization_id=organization_id,
            project_ids=project_ids,
        )

        # ── Phase 1: must run first (no API-enabled dependency) ──────────────
        priority_collectors: list[BaseCollector] = [
            self._new_collector(ServiceUsageCollector),
        ]
        for collector in priority_collectors:
            try:
                logger.info("Running collector: %s", collector.name)
                collector.collect(inventory, project_ids, organization_id)
            except Exception as exc:
                logger.error("Collector %s failed: %s", collector.name, _fmt_exc(exc))
                inventory.collector_errors.append({"collector": collector.name, "error": str(exc)})

        # ── Phase 2: concurrent collectors ───────────────────────────────────
        concurrent_collectors: list[BaseCollector] = [
            self._new_collector(IAMCollector),
            self._new_collector(ComputeCollector),
            self._new_collector(NetworkCollector),
            self._new_collector(APIKeysCollector),
            self._new_collector(BillingCollector),
            self._new_collector(GKECollector),
            self._new_collector(CloudRunCollector),
            self._new_collector(VertexAICollector),
            self._new_collector(OrgPolicyCollector),
            self._new_collector(RecommenderCollector),
            self._new_collector(QuotaCollector),
        ]

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = {
                executor.submit(
                    self._run_collector,
                    collector,
                    inventory,
                    project_ids,
                    organization_id,
                ): collector.name
                for collector in concurrent_collectors
            }
            for future in as_completed(futures):
                collector_name = futures[future]
                try:
                    future.result()
                    logger.info("Collector %s completed", collector_name)
                except Exception as exc:
                    logger.error("Collector %s failed: %s", collector_name, _fmt_exc(exc))
                    inventory.collector_errors.append(
                        {"collector": collector_name, "error": str(exc)}
                    )

        logger.info(
            "Collection complete: %d projects, %d instances, %d firewall rules, "
            "%d IAM bindings, %d GKE clusters, %d Cloud Run services, "
            "%d API keys, %d Vertex AI endpoints, %d org policies",
            len(project_ids),
            len(inventory.compute_instances),
            len(inventory.firewall_rules),
            len(inventory.iam_bindings),
            len(inventory.gke_clusters),
            len(inventory.cloud_run_services),
            len(inventory.api_keys),
            len(inventory.vertex_ai_endpoints),
            len(inventory.org_policies),
        )

        # ── Cache store ──────────────────────────────────────────────────────
        if self._cache is not None:
            self._cache.set(inventory, project_ids, organization_id)

        return inventory

    @staticmethod
    def _run_collector(
        collector: BaseCollector,
        inventory: ResourceInventory,
        project_ids: list[str],
        org: str | None,
    ) -> None:
        collector.collect(inventory, project_ids, org)
