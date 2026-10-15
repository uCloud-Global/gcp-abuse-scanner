"""Org Policy collector — reads Organization Policy constraints."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from gcp_abuse_scanner.collectors.base import BaseCollector, _fmt_exc
from gcp_abuse_scanner.models.inventory import OrgPolicy, ResourceInventory

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Key constraints relevant to crypto mining and Gemini abuse prevention
_RELEVANT_CONSTRAINTS = [
    "constraints/compute.vmExternalIpAccess",
    "constraints/compute.requireShieldedVm",
    "constraints/compute.restrictCloudRunRegion",
    "constraints/gcp.resourceLocations",
    "constraints/iam.disableServiceAccountKeyCreation",
    "constraints/iam.disableServiceAccountKeyUpload",
    "constraints/iam.allowedPolicyMemberDomains",
    "constraints/compute.restrictXpnProjectLienRemoval",
    "constraints/compute.skipDefaultNetworkCreation",
    "constraints/run.allowedIngress",
    "constraints/run.allowedVPCEgress",
    "constraints/aiplatform.allowedModels",
    "constraints/compute.restrictProtocolForwardingCreationForTypes",
]


def _is_not_found(exc: Exception) -> bool:
    """
    True when the API said "this policy does not exist" (404 / NOT_FOUND).

    ``_fmt_exc`` does not always render the status as "HTTP 404" (a mocked or wrapped
    error can read "404 Not Found"), and an HttpError carries the code on ``resp``, so
    check both. Only this case means "constraint not configured"; a 403 or a timeout
    means the policy was never read.
    """
    resp = getattr(exc, "resp", None)
    if getattr(resp, "status", None) == 404:
        return True
    text = _fmt_exc(exc).lower()
    return "404" in text or "not found" in text or "notfound" in text


class OrgPolicyCollector(BaseCollector):
    name = "org_policy"
    required_apis = ["orgpolicy.googleapis.com"]

    def collect(
        self,
        inventory: ResourceInventory,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> None:
        orgpolicy = self.build_client(inventory, "orgpolicy", "v2")
        if orgpolicy is None:
            return

        # Collect at org level if available
        resources_to_check: list[str] = []
        if organization_id:
            resources_to_check.append(f"organizations/{organization_id}")

        # Also check at project level for project-specific overrides
        for project_id in project_ids[:20]:  # cap to avoid quota exhaustion
            resources_to_check.append(f"projects/{project_id}")

        for resource in resources_to_check:
            try:
                self._collect_policies(orgpolicy, inventory, resource)
            except Exception as exc:
                fmt = _fmt_exc(exc)
                logger.warning("Org Policy collection failed for %s: %s", resource, fmt)
                # An unreadable policy is not an absent policy: CM-002/CM-011/GEM-050/CMN-005
                # must not report "not enforced" from a failed read.
                if resource.startswith("projects/"):
                    self.record_skipped_api(
                        inventory, resource.split("/")[-1], "orgpolicy.googleapis.com", fmt
                    )
                else:
                    self.record_collector_error(
                        inventory, None, f"org policy unreadable for {resource}: {fmt}"
                    )

    def _collect_policies(
        self, orgpolicy: object, inventory: ResourceInventory, resource: str
    ) -> None:
        for constraint in _RELEVANT_CONSTRAINTS:
            try:
                policy = (
                    orgpolicy.organizations()  # type: ignore
                    .policies()
                    .get(name=f"{resource}/policies/{constraint.replace('constraints/', '')}")
                    .execute()
                    if resource.startswith("organizations/")
                    else (
                        orgpolicy.projects()  # type: ignore
                        .policies()
                        .get(name=f"{resource}/policies/{constraint.replace('constraints/', '')}")
                        .execute()
                    )
                )
                inventory.org_policies.append(
                    OrgPolicy(
                        resource=resource,
                        constraint=constraint,
                        policy=policy,
                    )
                )
            except Exception as exc:
                fmt = _fmt_exc(exc)
                if _is_not_found(exc):
                    # Genuinely not set = constraint not enforced (important signal)
                    inventory.org_policies.append(
                        OrgPolicy(
                            resource=resource,
                            constraint=constraint,
                            policy={},  # empty = not configured
                        )
                    )
                    continue
                # Anything else (403, transport timeout) means we could not read the
                # policy: recording it as "not configured" would make CM-002/CM-011/
                # GEM-050/CMN-005 report a finding nobody verified.
                logger.warning("Org Policy read failed for %s/%s: %s", resource, constraint, fmt)
                if resource.startswith("projects/"):
                    self.record_skipped_api(
                        inventory, resource.split("/")[-1], "orgpolicy.googleapis.com", fmt
                    )
                else:
                    self.record_collector_error(
                        inventory, None, f"org policy unreadable for {resource}: {fmt}"
                    )
