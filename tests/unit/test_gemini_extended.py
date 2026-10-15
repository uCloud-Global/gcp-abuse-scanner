"""Unit tests for extended Gemini abuse checks and Common checks — offline, no API calls."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from gcp_abuse_scanner.checks.common.cmn_extended import (
    CMN003ProjectNoOwnerLabel,
    CMN004DefaultSAWithActiveKeys,
    CMN005OrgSecurityPoliciesAbsent,
    CMN006AuditLogsDisabled,
)
from gcp_abuse_scanner.checks.gemini_abuse.gem_extended import (
    GEM004APIKeyNoRotation,
    GEM005OrphanAPIKeys,
    GEM006APIKeyNoReferrerRestriction,
    GEM010GenerativeLanguageAPIEnabled,
    GEM011VertexAIEnabledNoBroadIAMControls,
    GEM022SAWithVertexAccessAndExportedKeys,
    GEM023BroadVertexPredictAccess,
    GEM030VertexEndpointNoPrivateNetwork,
    GEM040VertexAIQuotaAtDefault,
    GEM041GeminiAPIQuotaAtDefault,
    GEM050NoAPIKeyCreationRestriction,
    GEM051NoBudgetForVertexAI,
)
from gcp_abuse_scanner.models.finding import FindingStatus, Severity
from gcp_abuse_scanner.models.inventory import (
    APIKey,
    BudgetInfo,
    ComputeInstance,
    EnabledAPI,
    IAMBinding,
    OrgPolicy,
    ResourceInventory,
    ServiceAccountInfo,
    VertexAIEndpoint,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def empty_inventory() -> ResourceInventory:
    return ResourceInventory(project_ids=["test-project"])


@pytest.fixture
def empty_inventory_with_org() -> ResourceInventory:
    return ResourceInventory(
        project_ids=["test-project"],
        organization_id="org-123456",
    )


# ---------------------------------------------------------------------------
# GEM-004 — API key rotation
# ---------------------------------------------------------------------------


class TestGEM004APIKeyNoRotation:
    def test_fail_when_key_older_than_90_days(self, empty_inventory: ResourceInventory) -> None:
        old_time = datetime.now(UTC) - timedelta(days=100)
        empty_inventory.api_keys.append(
            APIKey(
                name="projects/test-project/locations/global/keys/old-key",
                project_id="test-project",
                display_name="Old Key",
                create_time=old_time.isoformat(),
                uid="uid-old-key",
            )
        )
        check = GEM004APIKeyNoRotation()
        findings = check.evaluate(empty_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "GEM-004"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence["age_days"] >= 100

    def test_pass_when_key_recent(self, empty_inventory: ResourceInventory) -> None:
        recent_time = datetime.now(UTC) - timedelta(days=10)
        empty_inventory.api_keys.append(
            APIKey(
                name="projects/test-project/locations/global/keys/recent-key",
                project_id="test-project",
                display_name="Recent Key",
                create_time=recent_time.isoformat(),
                uid="uid-recent-key",
            )
        )
        check = GEM004APIKeyNoRotation()
        findings = check.evaluate(empty_inventory)
        assert findings == []

    def test_fail_when_create_time_missing(self, empty_inventory: ResourceInventory) -> None:
        empty_inventory.api_keys.append(
            APIKey(
                name="projects/test-project/locations/global/keys/no-time-key",
                project_id="test-project",
                display_name="No Time Key",
                create_time="",  # missing
                uid="uid-no-time",
            )
        )
        check = GEM004APIKeyNoRotation()
        findings = check.evaluate(empty_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "GEM-004"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].evidence["age_days"] is None
        assert "missing" in findings[0].evidence["reason"].lower()


# ---------------------------------------------------------------------------
# GEM-005 — Orphaned API keys
# ---------------------------------------------------------------------------


class TestGEM005OrphanAPIKeys:
    def test_fail_when_more_than_3_unrestricted_keys(
        self, empty_inventory: ResourceInventory
    ) -> None:
        for i in range(4):
            empty_inventory.api_keys.append(
                APIKey(
                    name=f"projects/test-project/locations/global/keys/orphan-key-{i}",
                    project_id="test-project",
                    display_name=f"Orphan Key {i}",
                    restrictions={},  # no apiTargets
                    uid=f"uid-orphan-{i}",
                )
            )
        check = GEM005OrphanAPIKeys()
        findings = check.evaluate(empty_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "GEM-005"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].evidence["unrestricted_key_count"] == 4

    def test_pass_when_few_unrestricted_keys(self, empty_inventory: ResourceInventory) -> None:
        # Only 3 unrestricted keys — at or below threshold, no finding
        for i in range(3):
            empty_inventory.api_keys.append(
                APIKey(
                    name=f"projects/test-project/locations/global/keys/key-{i}",
                    project_id="test-project",
                    restrictions={},
                    uid=f"uid-few-{i}",
                )
            )
        check = GEM005OrphanAPIKeys()
        findings = check.evaluate(empty_inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# GEM-006 — Gemini API key without HTTP referrer restriction
# ---------------------------------------------------------------------------


class TestGEM006APIKeyNoReferrerRestriction:
    def test_fail_when_gemini_key_no_referrer_restriction(
        self, empty_inventory: ResourceInventory
    ) -> None:
        empty_inventory.api_keys.append(
            APIKey(
                name="projects/test-project/locations/global/keys/gemini-no-referrer",
                project_id="test-project",
                display_name="Gemini No Referrer",
                restrictions={
                    "apiTargets": [{"service": "generativelanguage.googleapis.com"}],
                    # no browserKeyRestrictions
                },
                uid="uid-gem-no-ref",
            )
        )
        check = GEM006APIKeyNoReferrerRestriction()
        findings = check.evaluate(empty_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "GEM-006"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.HIGH

    def test_pass_when_gemini_key_has_referrer(self, empty_inventory: ResourceInventory) -> None:
        empty_inventory.api_keys.append(
            APIKey(
                name="projects/test-project/locations/global/keys/gemini-with-referrer",
                project_id="test-project",
                display_name="Gemini With Referrer",
                restrictions={
                    "apiTargets": [{"service": "generativelanguage.googleapis.com"}],
                    "browserKeyRestrictions": {"allowedReferrers": ["https://example.com/*"]},
                },
                uid="uid-gem-ref",
            )
        )
        check = GEM006APIKeyNoReferrerRestriction()
        findings = check.evaluate(empty_inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# GEM-010 — generativelanguage.googleapis.com enabled
# ---------------------------------------------------------------------------


class TestGEM010GenerativeLanguageAPIEnabled:
    def test_fail_when_generative_language_api_enabled(
        self, empty_inventory: ResourceInventory
    ) -> None:
        empty_inventory.enabled_apis.append(
            EnabledAPI(
                project_id="test-project",
                service_name="generativelanguage.googleapis.com",
                state="ENABLED",
            )
        )
        check = GEM010GenerativeLanguageAPIEnabled()
        findings = check.evaluate(empty_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "GEM-010"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].evidence["service"] == "generativelanguage.googleapis.com"

    def test_pass_when_api_not_enabled(self, empty_inventory: ResourceInventory) -> None:
        # Only a different API is enabled
        empty_inventory.enabled_apis.append(
            EnabledAPI(
                project_id="test-project",
                service_name="compute.googleapis.com",
                state="ENABLED",
            )
        )
        check = GEM010GenerativeLanguageAPIEnabled()
        findings = check.evaluate(empty_inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# GEM-011 — Vertex AI enabled with broad IAM
# ---------------------------------------------------------------------------


class TestGEM011VertexAIEnabledNoBroadIAMControls:
    def test_fail_when_vertex_enabled_with_broad_iam(
        self, empty_inventory: ResourceInventory
    ) -> None:
        empty_inventory.enabled_apis.append(
            EnabledAPI(
                project_id="test-project",
                service_name="aiplatform.googleapis.com",
                state="ENABLED",
            )
        )
        empty_inventory.iam_bindings.append(
            IAMBinding(
                resource="//cloudresourcemanager.googleapis.com/projects/test-project",
                resource_type="cloudresourcemanager.googleapis.com/Project",
                project_id="test-project",
                role="roles/aiplatform.user",
                members=["domain:example.com"],
            )
        )
        check = GEM011VertexAIEnabledNoBroadIAMControls()
        findings = check.evaluate(empty_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "GEM-011"
        assert findings[0].status == FindingStatus.FAIL
        assert len(findings[0].evidence["problematic_bindings"]) >= 1

    def test_pass_when_vertex_enabled_restricted_iam(
        self, empty_inventory: ResourceInventory
    ) -> None:
        empty_inventory.enabled_apis.append(
            EnabledAPI(
                project_id="test-project",
                service_name="aiplatform.googleapis.com",
                state="ENABLED",
            )
        )
        # Only specific service account — not broad
        empty_inventory.iam_bindings.append(
            IAMBinding(
                resource="//cloudresourcemanager.googleapis.com/projects/test-project",
                resource_type="cloudresourcemanager.googleapis.com/Project",
                project_id="test-project",
                role="roles/aiplatform.user",
                members=["serviceAccount:specific-sa@test-project.iam.gserviceaccount.com"],
            )
        )
        check = GEM011VertexAIEnabledNoBroadIAMControls()
        findings = check.evaluate(empty_inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# GEM-022 — SA with Vertex AI access and user-managed keys
# ---------------------------------------------------------------------------


class TestGEM022SAWithVertexAccessAndExportedKeys:
    def test_fail_when_sa_has_vertex_role_and_user_managed_key(
        self, empty_inventory: ResourceInventory
    ) -> None:
        sa_email = "vertex-sa@test-project.iam.gserviceaccount.com"
        empty_inventory.iam_bindings.append(
            IAMBinding(
                resource="//cloudresourcemanager.googleapis.com/projects/test-project",
                resource_type="cloudresourcemanager.googleapis.com/Project",
                project_id="test-project",
                role="roles/aiplatform.user",
                members=[f"serviceAccount:{sa_email}"],
            )
        )
        empty_inventory.service_accounts.append(
            ServiceAccountInfo(
                name=f"projects/test-project/serviceAccounts/{sa_email}",
                email=sa_email,
                project_id="test-project",
                keys=[
                    {
                        "name": "projects/test-project/serviceAccounts/vertex-sa/keys/key-abc",
                        "keyType": "USER_MANAGED",
                        "validAfterTime": "2024-01-01T00:00:00Z",
                        "validBeforeTime": "2025-01-01T00:00:00Z",
                    }
                ],
            )
        )
        check = GEM022SAWithVertexAccessAndExportedKeys()
        findings = check.evaluate(empty_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "GEM-022"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence["sa_email"] == sa_email

    def test_pass_when_sa_has_vertex_role_but_no_user_key(
        self, empty_inventory: ResourceInventory
    ) -> None:
        sa_email = "vertex-sa-clean@test-project.iam.gserviceaccount.com"
        empty_inventory.iam_bindings.append(
            IAMBinding(
                resource="//cloudresourcemanager.googleapis.com/projects/test-project",
                resource_type="cloudresourcemanager.googleapis.com/Project",
                project_id="test-project",
                role="roles/aiplatform.user",
                members=[f"serviceAccount:{sa_email}"],
            )
        )
        empty_inventory.service_accounts.append(
            ServiceAccountInfo(
                name=f"projects/test-project/serviceAccounts/{sa_email}",
                email=sa_email,
                project_id="test-project",
                keys=[
                    {
                        "name": "projects/test-project/serviceAccounts/vertex-sa-clean/keys/key-sys",
                        "keyType": "SYSTEM_MANAGED",
                    }
                ],
            )
        )
        check = GEM022SAWithVertexAccessAndExportedKeys()
        findings = check.evaluate(empty_inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# GEM-023 — Broad Vertex predict access
# ---------------------------------------------------------------------------


class TestGEM023BroadVertexPredictAccess:
    def test_fail_when_aiplatform_user_granted_to_domain(
        self, empty_inventory: ResourceInventory
    ) -> None:
        empty_inventory.iam_bindings.append(
            IAMBinding(
                resource="//cloudresourcemanager.googleapis.com/projects/test-project",
                resource_type="cloudresourcemanager.googleapis.com/Project",
                project_id="test-project",
                role="roles/aiplatform.user",
                members=[
                    "domain:example.com",
                    "serviceAccount:specific@test-project.iam.gserviceaccount.com",
                ],
            )
        )
        check = GEM023BroadVertexPredictAccess()
        findings = check.evaluate(empty_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "GEM-023"
        assert findings[0].status == FindingStatus.FAIL
        assert "domain:example.com" in findings[0].evidence["broad_members"]

    def test_pass_when_aiplatform_user_restricted(self, empty_inventory: ResourceInventory) -> None:
        empty_inventory.iam_bindings.append(
            IAMBinding(
                resource="//cloudresourcemanager.googleapis.com/projects/test-project",
                resource_type="cloudresourcemanager.googleapis.com/Project",
                project_id="test-project",
                role="roles/aiplatform.user",
                members=["serviceAccount:specific@test-project.iam.gserviceaccount.com"],
            )
        )
        check = GEM023BroadVertexPredictAccess()
        findings = check.evaluate(empty_inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# GEM-030 — Vertex AI endpoint without private network
# ---------------------------------------------------------------------------


class TestGEM030VertexEndpointNoPrivateNetwork:
    def test_fail_when_endpoint_has_no_private_network(
        self, empty_inventory: ResourceInventory
    ) -> None:
        empty_inventory.vertex_ai_endpoints.append(
            VertexAIEndpoint(
                name="projects/test-project/locations/us-central1/endpoints/public-endpoint",
                project_id="test-project",
                region="us-central1",
                display_name="Public Endpoint",
                network="",  # no private network
            )
        )
        check = GEM030VertexEndpointNoPrivateNetwork()
        findings = check.evaluate(empty_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "GEM-030"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.HIGH

    def test_pass_when_endpoint_has_private_network(
        self, empty_inventory: ResourceInventory
    ) -> None:
        empty_inventory.vertex_ai_endpoints.append(
            VertexAIEndpoint(
                name="projects/test-project/locations/us-central1/endpoints/private-endpoint",
                project_id="test-project",
                region="us-central1",
                display_name="Private Endpoint",
                network="projects/12345/global/networks/my-vpc",
            )
        )
        check = GEM030VertexEndpointNoPrivateNetwork()
        findings = check.evaluate(empty_inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# GEM-040 — Vertex AI quota at default
# ---------------------------------------------------------------------------


class TestGEM040VertexAIQuotaAtDefault:
    def test_fail_when_quota_at_default(self, empty_inventory: ResourceInventory) -> None:
        empty_inventory.quota_info.append(
            {
                "service": "aiplatform.googleapis.com",
                "project_id": "test-project",
                "metric": "aiplatform.googleapis.com/online_prediction_requests",
                "limit_name": "ONLINE-PREDICTION-REQUESTS-per-minute-per-project-per-base-model",
                "quota_buckets": [
                    {
                        "effectiveLimit": 600,
                        "defaultLimit": 600,
                    }
                ],
            }
        )
        check = GEM040VertexAIQuotaAtDefault()
        findings = check.evaluate(empty_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "GEM-040"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].evidence["metrics_at_default"] == 1
        assert findings[0].evidence["limit_entries_at_default"] == 1
        assert findings[0].evidence["min_effective_limit"] == 60

    def test_pass_when_quota_reduced(self, empty_inventory: ResourceInventory) -> None:
        empty_inventory.quota_info.append(
            {
                "service": "aiplatform.googleapis.com",
                "project_id": "test-project",
                "metric": "aiplatform.googleapis.com/online_prediction_requests",
                "limit_name": "ONLINE-PREDICTION-REQUESTS-per-minute",
                "quota_buckets": [
                    {
                        "effectiveLimit": 10,  # reduced from default
                        "defaultLimit": 600,
                    }
                ],
            }
        )
        check = GEM040VertexAIQuotaAtDefault()
        findings = check.evaluate(empty_inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# GEM-041 — Gemini API (Generative Language) quota at default
# ---------------------------------------------------------------------------


def _gemini_quota(project_id: str = "test-project", **bucket: object) -> dict:
    return {
        "service": "generativelanguage.googleapis.com",
        "project_id": project_id,
        "metric": "generativelanguage.googleapis.com/generate_content_requests",
        "limit_name": "GENERATE-CONTENT-REQUESTS-per-minute-per-project",
        "quota_buckets": [
            {"effectiveLimit": 4000, "defaultLimit": 4000, **bucket},
        ],
    }


class TestGEM041GeminiAPIQuotaAtDefault:
    def test_fail_when_gemini_api_quota_at_default(
        self, empty_inventory: ResourceInventory
    ) -> None:
        empty_inventory.quota_info.append(_gemini_quota())
        check = GEM041GeminiAPIQuotaAtDefault()
        findings = check.evaluate(empty_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "GEM-041"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].evidence["service"] == "generativelanguage.googleapis.com"
        assert findings[0].evidence["metrics_at_default"] == 1
        assert findings[0].evidence["metric_examples"] == [
            "generativelanguage.googleapis.com/generate_content_requests"
        ]

    def test_one_finding_per_project_not_per_metric(
        self, empty_inventory: ResourceInventory
    ) -> None:
        """Regression: a real project produced 1016 buckets across 56 metrics."""
        for i in range(56):
            entry = _gemini_quota()
            entry["metric"] = f"generativelanguage.googleapis.com/metric_{i}"
            empty_inventory.quota_info.append(entry)

        findings = GEM041GeminiAPIQuotaAtDefault().evaluate(empty_inventory)

        assert len(findings) == 1, "one aggregated finding, not one per metric"
        assert findings[0].evidence["metrics_at_default"] == 56
        assert findings[0].evidence["limit_entries_at_default"] == 56
        assert len(findings[0].evidence["metric_examples"]) == 10  # capped sample

    def test_two_projects_produce_two_findings(self, empty_inventory: ResourceInventory) -> None:
        empty_inventory.quota_info.append(_gemini_quota(project_id="proj-a"))
        empty_inventory.quota_info.append(_gemini_quota(project_id="proj-b"))

        findings = GEM041GeminiAPIQuotaAtDefault().evaluate(empty_inventory)

        assert len(findings) == 2
        assert {f.resource.project_id for f in findings} == {"proj-a", "proj-b"}
        assert len({f.finding_id for f in findings}) == 2

    def test_finding_id_is_stable_across_metric_changes(
        self, empty_inventory: ResourceInventory
    ) -> None:
        empty_inventory.quota_info.append(_gemini_quota())
        first = GEM041GeminiAPIQuotaAtDefault().evaluate(empty_inventory)[0].finding_id

        entry = _gemini_quota()
        entry["metric"] = "generativelanguage.googleapis.com/embed_content_requests"
        empty_inventory.quota_info.append(entry)
        second = GEM041GeminiAPIQuotaAtDefault().evaluate(empty_inventory)[0].finding_id

        assert first == second  # aggregated finding is keyed by project, not by metric

    def test_pass_when_quota_reduced(self, empty_inventory: ResourceInventory) -> None:
        empty_inventory.quota_info.append(_gemini_quota(effectiveLimit=200, defaultLimit=4000))
        assert GEM041GeminiAPIQuotaAtDefault().evaluate(empty_inventory) == []

    def test_pass_when_default_is_already_low(self, empty_inventory: ResourceInventory) -> None:
        empty_inventory.quota_info.append(_gemini_quota(effectiveLimit=10, defaultLimit=10))
        assert GEM041GeminiAPIQuotaAtDefault().evaluate(empty_inventory) == []

    def test_ignores_vertex_ai_quotas(self, empty_inventory: ResourceInventory) -> None:
        empty_inventory.quota_info.append(
            {
                "service": "aiplatform.googleapis.com",
                "project_id": "test-project",
                "metric": "aiplatform.googleapis.com/online_prediction_requests",
                "limit_name": "ONLINE-PREDICTION-REQUESTS",
                "quota_buckets": [{"effectiveLimit": 600, "defaultLimit": 600}],
            }
        )
        assert GEM041GeminiAPIQuotaAtDefault().evaluate(empty_inventory) == []

    def test_both_quota_checks_fire_independently(self, empty_inventory: ResourceInventory) -> None:
        empty_inventory.quota_info.append(_gemini_quota())
        empty_inventory.quota_info.append(
            {
                "service": "aiplatform.googleapis.com",
                "project_id": "test-project",
                "metric": "aiplatform.googleapis.com/online_prediction_requests",
                "limit_name": "ONLINE-PREDICTION-REQUESTS",
                "quota_buckets": [{"effectiveLimit": 600, "defaultLimit": 600}],
            }
        )
        assert len(GEM041GeminiAPIQuotaAtDefault().evaluate(empty_inventory)) == 1
        assert len(GEM040VertexAIQuotaAtDefault().evaluate(empty_inventory)) == 1

    def test_pass_on_missing_or_malformed_limits(self, empty_inventory: ResourceInventory) -> None:
        empty_inventory.quota_info.append(
            {
                "service": "generativelanguage.googleapis.com",
                "project_id": "test-project",
                "metric": "generativelanguage.googleapis.com/generate_content_requests",
                "limit_name": "GENERATE-CONTENT-REQUESTS",
                "quota_buckets": [
                    {"effectiveLimit": None, "defaultLimit": 4000},
                    {"effectiveLimit": "unlimited", "defaultLimit": 4000},
                    {},
                ],
            }
        )
        assert GEM041GeminiAPIQuotaAtDefault().evaluate(empty_inventory) == []


# ---------------------------------------------------------------------------
# CMN-001 — Billing account with no budget (and the unreadable-budget guard)
# ---------------------------------------------------------------------------


class TestCMN001NoBudget:
    def _inventory(self, unreadable: list[str] | None = None) -> ResourceInventory:
        from gcp_abuse_scanner.models.inventory import ProjectInfo

        return ResourceInventory(
            project_ids=["proj-1"],
            projects=[ProjectInfo(project_id="proj-1", billing_account_id="ACCT-1")],
            budgets_unreadable=unreadable or [],
        )

    def test_fail_when_account_has_no_budget(self) -> None:
        from gcp_abuse_scanner.checks.common.cmn_budgets import CMN001NoBudget

        findings = CMN001NoBudget().evaluate(self._inventory())
        assert len(findings) == 1
        assert findings[0].check_id == "CMN-001"
        assert findings[0].evidence["billing_account_id"] == "ACCT-1"

    def test_no_finding_when_the_budgets_could_not_be_read(self) -> None:
        """'We could not look' must not be reported as 'there is no budget'."""
        from gcp_abuse_scanner.checks.common.cmn_budgets import CMN001NoBudget

        findings = CMN001NoBudget().evaluate(self._inventory(unreadable=["ACCT-1"]))

        assert findings == []

    def test_pass_when_a_budget_exists(self) -> None:
        from gcp_abuse_scanner.checks.common.cmn_budgets import CMN001NoBudget
        from gcp_abuse_scanner.models.inventory import BudgetInfo

        inventory = self._inventory()
        inventory.budgets.append(
            BudgetInfo(name="billingAccounts/ACCT-1/budgets/b", billing_account_id="ACCT-1")
        )
        assert CMN001NoBudget().evaluate(inventory) == []


# ---------------------------------------------------------------------------
# GEM-050 — No Org Policy restricting SA key creation
# ---------------------------------------------------------------------------


class TestGEM050NoAPIKeyCreationRestriction:
    def test_fail_when_sa_key_creation_not_restricted(
        self, empty_inventory_with_org: ResourceInventory
    ) -> None:
        # No org policies at all
        check = GEM050NoAPIKeyCreationRestriction()
        findings = check.evaluate(empty_inventory_with_org)
        assert len(findings) == 1
        assert findings[0].check_id == "GEM-050"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].evidence["constraint_present"] is False

    def test_pass_when_sa_key_creation_restricted(
        self, empty_inventory_with_org: ResourceInventory
    ) -> None:
        empty_inventory_with_org.org_policies.append(
            OrgPolicy(
                resource="organizations/org-123456",
                constraint="constraints/iam.disableServiceAccountKeyCreation",
                policy={"spec": {"rules": [{"enforce": True}]}},
            )
        )
        check = GEM050NoAPIKeyCreationRestriction()
        findings = check.evaluate(empty_inventory_with_org)
        assert findings == []


# ---------------------------------------------------------------------------
# GEM-051 — No budget alert covering Vertex AI / Gemini
# ---------------------------------------------------------------------------


class TestGEM051NoBudgetForVertexAI:
    def test_no_finding_when_budgets_could_not_be_read(self) -> None:
        """GEM-051 asserts absence of budgets — only valid if the API was readable."""
        from gcp_abuse_scanner.checks.gemini_abuse.gem_extended import GEM051NoBudgetForVertexAI

        inventory = ResourceInventory(
            project_ids=["proj-1"],
            organization_id="123456789",
            budgets_unreadable=["ACCT-1"],
        )
        assert GEM051NoBudgetForVertexAI().evaluate(inventory) == []

    def test_fail_when_no_budgets(self, empty_inventory_with_org: ResourceInventory) -> None:
        # No budgets at all
        check = GEM051NoBudgetForVertexAI()
        findings = check.evaluate(empty_inventory_with_org)
        assert len(findings) == 1
        assert findings[0].check_id == "GEM-051"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].evidence["budgets_found"] == 0
        assert "No budgets" in findings[0].evidence["reason"]

    def test_fail_when_budget_not_covering_vertex(
        self, empty_inventory_with_org: ResourceInventory
    ) -> None:
        # Budget exists but only covers compute, not Vertex AI
        empty_inventory_with_org.budgets.append(
            BudgetInfo(
                name="billingAccounts/ACCT/budgets/compute-budget",
                billing_account_id="ACCT",
                display_name="Compute Budget",
                budget_filter={"services": ["services/compute.googleapis.com"]},
            )
        )
        check = GEM051NoBudgetForVertexAI()
        findings = check.evaluate(empty_inventory_with_org)
        assert len(findings) == 1
        assert findings[0].check_id == "GEM-051"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].evidence["gemini_covered"] is False

    def test_pass_when_budget_covers_vertex(
        self, empty_inventory_with_org: ResourceInventory
    ) -> None:
        empty_inventory_with_org.budgets.append(
            BudgetInfo(
                name="billingAccounts/ACCT/budgets/vertex-budget",
                billing_account_id="ACCT",
                display_name="Vertex AI Budget",
                budget_filter={"services": ["services/aiplatform.googleapis.com"]},
            )
        )
        check = GEM051NoBudgetForVertexAI()
        findings = check.evaluate(empty_inventory_with_org)
        assert findings == []


# ---------------------------------------------------------------------------
# CMN-003 — Project has no owner or team label
# ---------------------------------------------------------------------------


class TestCMN003ProjectNoOwnerLabel:
    def test_fail_when_instances_have_no_owner_label(
        self, empty_inventory: ResourceInventory
    ) -> None:
        empty_inventory.compute_instances.append(
            ComputeInstance(
                name="instance-no-label",
                project_id="test-project",
                zone="us-central1-a",
                machine_type="n1-standard-1",
                status="RUNNING",
                labels={},  # no owner/team label
            )
        )
        check = CMN003ProjectNoOwnerLabel()
        findings = check.evaluate(empty_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CMN-003"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].evidence["instance_count"] == 1

    def test_pass_when_instances_have_owner_label(self, empty_inventory: ResourceInventory) -> None:
        empty_inventory.compute_instances.append(
            ComputeInstance(
                name="instance-with-label",
                project_id="test-project",
                zone="us-central1-a",
                machine_type="n1-standard-1",
                status="RUNNING",
                labels={"owner": "platform-team"},
            )
        )
        check = CMN003ProjectNoOwnerLabel()
        findings = check.evaluate(empty_inventory)
        assert findings == []

    def test_pass_when_no_instances(self, empty_inventory: ResourceInventory) -> None:
        # No compute instances — check is skipped (cannot determine accountability gap)
        check = CMN003ProjectNoOwnerLabel()
        findings = check.evaluate(empty_inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# CMN-004 — Default Compute Engine SA has user-managed keys
# ---------------------------------------------------------------------------


class TestCMN004DefaultSAWithActiveKeys:
    def test_fail_when_default_sa_has_user_managed_key(
        self, empty_inventory: ResourceInventory
    ) -> None:
        default_sa_email = "123456789-compute@developer.gserviceaccount.com"
        empty_inventory.service_accounts.append(
            ServiceAccountInfo(
                name=f"projects/test-project/serviceAccounts/{default_sa_email}",
                email=default_sa_email,
                project_id="test-project",
                keys=[
                    {
                        "name": "projects/test-project/serviceAccounts/default-sa/keys/key-xyz",
                        "keyType": "USER_MANAGED",
                        "validAfterTime": "2024-01-01T00:00:00Z",
                        "validBeforeTime": "2025-01-01T00:00:00Z",
                    }
                ],
            )
        )
        check = CMN004DefaultSAWithActiveKeys()
        findings = check.evaluate(empty_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CMN-004"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence["service_account_email"] == default_sa_email

    def test_pass_when_default_sa_has_no_user_managed_key(
        self, empty_inventory: ResourceInventory
    ) -> None:
        default_sa_email = "987654321-compute@developer.gserviceaccount.com"
        empty_inventory.service_accounts.append(
            ServiceAccountInfo(
                name=f"projects/test-project/serviceAccounts/{default_sa_email}",
                email=default_sa_email,
                project_id="test-project",
                keys=[
                    {
                        "name": "projects/test-project/serviceAccounts/default-sa/keys/key-sys",
                        "keyType": "SYSTEM_MANAGED",
                    }
                ],
            )
        )
        check = CMN004DefaultSAWithActiveKeys()
        findings = check.evaluate(empty_inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# CMN-005 — Critical org-level security policies absent
# ---------------------------------------------------------------------------


class TestCMN005OrgSecurityPoliciesAbsent:
    def test_fail_when_multiple_policies_absent(
        self, empty_inventory_with_org: ResourceInventory
    ) -> None:
        # No org policies at all — all 4 critical constraints are missing
        check = CMN005OrgSecurityPoliciesAbsent()
        findings = check.evaluate(empty_inventory_with_org)
        assert len(findings) == 1
        assert findings[0].check_id == "CMN-005"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].evidence["total_not_enforced"] >= 2

    def test_pass_when_all_policies_enforced(
        self, empty_inventory_with_org: ResourceInventory
    ) -> None:
        critical_constraints = [
            "constraints/compute.vmExternalIpAccess",
            "constraints/iam.disableServiceAccountKeyCreation",
            "constraints/compute.skipDefaultNetworkCreation",
            "constraints/iam.allowedPolicyMemberDomains",
        ]
        for constraint in critical_constraints:
            empty_inventory_with_org.org_policies.append(
                OrgPolicy(
                    resource="organizations/org-123456",
                    constraint=constraint,
                    policy={"spec": {"rules": [{"enforce": True}]}},
                )
            )
        check = CMN005OrgSecurityPoliciesAbsent()
        findings = check.evaluate(empty_inventory_with_org)
        assert findings == []


# ---------------------------------------------------------------------------
# CMN-006 — Cloud Audit Logs (Data Access) may not be enabled
# ---------------------------------------------------------------------------


class TestCMN006AuditLogsDisabled:
    def test_fail_when_logging_api_not_enabled(self, empty_inventory: ResourceInventory) -> None:
        # Project has compute instances but logging API is absent
        empty_inventory.compute_instances.append(
            ComputeInstance(
                name="instance-no-logging",
                project_id="test-project",
                zone="us-central1-a",
                machine_type="n1-standard-1",
                status="RUNNING",
            )
        )
        # Only compute API enabled, not logging
        empty_inventory.enabled_apis.append(
            EnabledAPI(
                project_id="test-project",
                service_name="compute.googleapis.com",
                state="ENABLED",
            )
        )
        check = CMN006AuditLogsDisabled()
        findings = check.evaluate(empty_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CMN-006"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].evidence["logging_api_enabled"] is False

    def test_pass_when_logging_api_enabled(self, empty_inventory: ResourceInventory) -> None:
        empty_inventory.compute_instances.append(
            ComputeInstance(
                name="instance-with-logging",
                project_id="test-project",
                zone="us-central1-a",
                machine_type="n1-standard-1",
                status="RUNNING",
            )
        )
        empty_inventory.enabled_apis.append(
            EnabledAPI(
                project_id="test-project",
                service_name="logging.googleapis.com",
                state="ENABLED",
            )
        )
        check = CMN006AuditLogsDisabled()
        findings = check.evaluate(empty_inventory)
        assert findings == []
