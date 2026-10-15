"""Base collector with retry, pagination, and API-disabled handling."""

from __future__ import annotations

import abc
import logging
from typing import TYPE_CHECKING, Any

from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

if TYPE_CHECKING:
    from gcp_abuse_scanner.auth.manager import AuthManager
    from gcp_abuse_scanner.models.inventory import ResourceInventory

logger = logging.getLogger(__name__)


class APINotEnabledError(Exception):
    """Raised when a required API is not enabled in a project."""


def _fmt_exc(exc: Exception) -> str:
    """Return a concise one-line summary of a GCP HttpError or any exception.

    googleapiclient.errors.HttpError.__str__ dumps the full JSON response body,
    which is very noisy. We extract just the HTTP status and the first meaningful
    reason string instead.
    """
    exc_str = str(exc)
    # HttpError format: "<HttpError NNN when requesting URL returned "MSG", details: ...>"
    # Extract just "HttpError NNN: MSG"
    try:
        import re

        m = re.match(r"<HttpError (\d+) when requesting .+ returned \"([^\"]+)\"", exc_str)
        if m:
            status, msg = m.group(1), m.group(2)
            # Truncate long billing/API messages to first sentence
            first_sentence = msg.split(".")[0].strip()
            return f"HTTP {status}: {first_sentence}"
    except Exception:  # nosec B110 — intentional fallback; _fmt_exc is best-effort only
        pass
    # Fallback: first 120 chars
    return exc_str[:120] if len(exc_str) > 120 else exc_str


class BaseCollector(abc.ABC):
    """
    Base class for all resource collectors.

    Collectors fetch raw facts from GCP APIs and populate the ResourceInventory.
    They must NOT contain any check logic.
    """

    name: str  # e.g. "compute", "iam"
    required_apis: list[str] = []

    def __init__(
        self,
        auth_manager: AuthManager,
        timeout: float | None = None,
        transport: str | None = None,
    ) -> None:
        self._auth = auth_manager
        self._timeout = timeout
        self._transport = transport
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def build_client(
        self,
        inventory: ResourceInventory,
        api: str,
        version: str,
    ) -> Any | None:
        """Build a discovery client, recording a coverage gap if that fails.

        The client libraries fail open, but a client that could not be built means
        *no data at all* for the checks behind it. Returning ``None`` silently
        would turn a transport failure into "no findings", so the failure is
        recorded in ``inventory.collector_errors`` — which the coverage gate in
        ``scoring/risk.py`` reads (see docs/risk-model.md).
        """
        from gcp_abuse_scanner.utils import transport as transport_module

        try:
            return transport_module.build_service(
                api,
                version,
                credentials=self._auth.get_credentials(),
                timeout=self._timeout,
                transport=self._transport,
            )
        except Exception as exc:
            fmt = _fmt_exc(exc)
            message = f"{api}/{version} client unavailable: {fmt}"
            logger.error("%s collector: %s", self.name, message)
            self.record_collector_error(inventory, None, message)
            return None

    @abc.abstractmethod
    def collect(
        self,
        inventory: ResourceInventory,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> None:
        """
        Populate the inventory with data from this collector.
        Modifies inventory in-place.
        """

    def is_api_enabled(self, inventory: ResourceInventory, project_id: str) -> bool:
        if not self.required_apis:
            return True
        enabled = {
            api.service_name for api in inventory.enabled_apis if api.project_id == project_id
        }
        return any(api in enabled for api in self.required_apis)

    def record_skipped_api(
        self,
        inventory: ResourceInventory,
        project_id: str,
        api: str,
        reason: str = "",
    ) -> None:
        """
        Record that an API could not be read for a project.

        Collectors fail open, but "no data" must never be reported as "no
        findings": every skip lands in ``inventory.skipped_apis`` and blocks
        automatic approval of the assessment (see docs/risk-model.md).
        """
        skipped = inventory.skipped_apis.setdefault(project_id, [])
        if api not in skipped:
            skipped.append(api)
        if reason:
            logger.debug("Skipped %s for %s: %s", api, project_id, reason)

    def record_collector_error(
        self,
        inventory: ResourceInventory,
        project_id: str | None,
        error: str,
    ) -> None:
        """Record a collector failure attributed to this collector (and project).

        ``project_id`` is ``None`` for failures that are not tied to a single
        project (a client that could not be built, a credential problem).
        """
        entry: dict[str, str] = {"collector": self.name, "error": error}
        if project_id:
            entry["project_id"] = project_id
        inventory.collector_errors.append(entry)

    @staticmethod
    @retry(
        retry=retry_if_exception_type(Exception),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(4),
        reraise=True,
    )
    def _with_retry(fn: Any, *args: Any, **kwargs: Any) -> Any:
        return fn(*args, **kwargs)
