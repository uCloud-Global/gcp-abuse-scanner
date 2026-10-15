"""Unit tests for Phase 1 collectors using mocked GCP API responses."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from gcp_abuse_scanner.models.inventory import (
    EnabledAPI,
    ResourceInventory,
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _make_auth(creds: object = None) -> MagicMock:
    auth = MagicMock()
    auth.get_credentials.return_value = creds or MagicMock()
    return auth


def _inventory_with_apis(*service_names: str, project_id: str = "proj-1") -> ResourceInventory:
    inv = ResourceInventory(project_ids=[project_id])
    for svc in service_names:
        inv.enabled_apis.append(EnabledAPI(project_id=project_id, service_name=svc))
    return inv


# ─────────────────────────────────────────────────────────────────────────────
# GKECollector
# ─────────────────────────────────────────────────────────────────────────────


class TestGKECollector:
    def test_collects_clusters(self):
        from gcp_abuse_scanner.collectors.gke import GKECollector

        inv = _inventory_with_apis("container.googleapis.com")
        auth = _make_auth()

        mock_cluster = {
            "name": "prod-cluster",
            "location": "us-central1",
            "endpoint": "10.0.0.1",
            "masterAuthorizedNetworksConfig": {"enabled": True},
            "workloadIdentityConfig": {"workloadPool": "proj-1.svc.id.goog"},
            "nodePools": [
                {
                    "name": "default-pool",
                    "config": {"serviceAccount": "default"},
                    "autoscaling": {"enabled": True, "maxNodeCount": 100},
                }
            ],
            "legacyAbac": {"enabled": False},
            "privateClusterConfig": {"enablePrivateNodes": True},
            "autopilot": {},
        }

        mock_response = {"clusters": [mock_cluster]}

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_container = MagicMock()
            mock_build.return_value = mock_container
            mock_container.projects().locations().clusters().list().execute.return_value = (
                mock_response
            )

            collector = GKECollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.gke_clusters) == 1
        cluster = inv.gke_clusters[0]
        assert cluster.name == "prod-cluster"
        assert cluster.project_id == "proj-1"
        assert cluster.location == "us-central1"
        assert cluster.workload_identity_config == {"workloadPool": "proj-1.svc.id.goog"}
        assert cluster.legacy_abac == {"enabled": False}

    def test_skips_when_api_not_enabled(self):
        from gcp_abuse_scanner.collectors.gke import GKECollector

        inv = ResourceInventory(project_ids=["proj-1"])  # no APIs enabled
        auth = _make_auth()

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_build.return_value = MagicMock()
            collector = GKECollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.gke_clusters) == 0
        assert "container.googleapis.com" in inv.skipped_apis.get(
            "proj-1", []
        )  # lgtm[py/incomplete-url-substring-sanitization]

    def test_handles_api_error_gracefully(self):
        from gcp_abuse_scanner.collectors.gke import GKECollector

        inv = _inventory_with_apis("container.googleapis.com")
        auth = _make_auth()

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_container = MagicMock()
            mock_build.return_value = mock_container
            mock_container.projects().locations().clusters().list().execute.side_effect = Exception(
                "403 Forbidden"
            )

            collector = GKECollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.gke_clusters) == 0
        assert any("gke" in e.get("collector", "") for e in inv.collector_errors)

    def test_node_pool_high_autoscaling_captured(self):
        from gcp_abuse_scanner.collectors.gke import GKECollector

        inv = _inventory_with_apis("container.googleapis.com")
        auth = _make_auth()

        mock_cluster = {
            "name": "big-cluster",
            "location": "us-east1",
            "endpoint": "10.0.0.2",
            "nodePools": [
                {
                    "name": "gpu-pool",
                    "config": {"serviceAccount": "compute@developer.gserviceaccount.com"},
                    "autoscaling": {"enabled": True, "maxNodeCount": 1000},
                }
            ],
            "legacyAbac": {"enabled": True},
            "privateClusterConfig": {},
            "autopilot": {},
        }

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_container = MagicMock()
            mock_build.return_value = mock_container
            mock_container.projects().locations().clusters().list().execute.return_value = {
                "clusters": [mock_cluster]
            }

            collector = GKECollector(auth)
            collector.collect(inv, ["proj-1"])

        assert inv.gke_clusters[0].legacy_abac == {"enabled": True}
        assert inv.gke_clusters[0].node_pools[0]["autoscaling"]["maxNodeCount"] == 1000


# ─────────────────────────────────────────────────────────────────────────────
# CloudRunCollector
# ─────────────────────────────────────────────────────────────────────────────


class TestCloudRunCollector:
    def test_collects_services(self):
        from gcp_abuse_scanner.collectors.cloud_run import CloudRunCollector

        inv = _inventory_with_apis("run.googleapis.com")
        auth = _make_auth()

        mock_service = {
            "name": "projects/proj-1/locations/us-central1/services/my-svc",
            "ingress": "INGRESS_TRAFFIC_ALL",
            "scaling": {"minInstanceCount": 0, "maxInstanceCount": 1000},
            "template": {},
        }
        mock_iam = {"bindings": [{"role": "roles/run.invoker", "members": ["allUsers"]}]}

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_run = MagicMock()
            mock_build.return_value = mock_run

            # list services
            mock_run.projects().locations().services().list().execute.return_value = {
                "services": [mock_service]
            }
            # list_next returns None (no more pages)
            mock_run.projects().locations().services().list_next.return_value = None

            # getIamPolicy
            mock_run.projects().locations().services().getIamPolicy().execute.return_value = (
                mock_iam
            )

            collector = CloudRunCollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.cloud_run_services) == 1
        svc = inv.cloud_run_services[0]
        assert svc.name == "my-svc"
        assert svc.region == "us-central1"
        assert svc.ingress == "INGRESS_TRAFFIC_ALL"
        # IAM bindings should include allUsers
        assert any("allUsers" in b.get("members", []) for b in svc.iam_bindings)

    def test_skips_when_api_not_enabled(self):
        from gcp_abuse_scanner.collectors.cloud_run import CloudRunCollector

        inv = ResourceInventory(project_ids=["proj-1"])
        auth = _make_auth()

        with patch("googleapiclient.discovery.build"):
            collector = CloudRunCollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.cloud_run_services) == 0
        assert "run.googleapis.com" in inv.skipped_apis.get(
            "proj-1", []
        )  # lgtm[py/incomplete-url-substring-sanitization]

    def test_handles_error_gracefully(self):
        from gcp_abuse_scanner.collectors.cloud_run import CloudRunCollector

        inv = _inventory_with_apis("run.googleapis.com")
        auth = _make_auth()

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_run = MagicMock()
            mock_build.return_value = mock_run
            mock_run.projects().locations().services().list().execute.side_effect = Exception(
                "500 Internal Server Error"
            )

            collector = CloudRunCollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.cloud_run_services) == 0
        assert any("cloud_run" in e.get("collector", "") for e in inv.collector_errors)


# ─────────────────────────────────────────────────────────────────────────────
# VertexAICollector
# ─────────────────────────────────────────────────────────────────────────────


class TestVertexAICollector:
    def test_collects_endpoints(self):
        from gcp_abuse_scanner.collectors.vertex_ai import VertexAICollector

        inv = _inventory_with_apis("aiplatform.googleapis.com")
        auth = _make_auth()

        mock_endpoint = {
            "name": "projects/proj-1/locations/us-central1/endpoints/12345",
            "displayName": "gemini-endpoint",
            "network": "",  # no private network = public
        }
        mock_iam = {"bindings": [{"role": "roles/aiplatform.user", "members": ["allUsers"]}]}

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_ai = MagicMock()
            mock_build.return_value = mock_ai

            mock_ai.projects().locations().endpoints().list().execute.return_value = {
                "endpoints": [mock_endpoint]
            }
            mock_ai.projects().locations().endpoints().list_next.return_value = None

            mock_ai.projects().locations().endpoints().getIamPolicy().execute.return_value = (
                mock_iam
            )

            collector = VertexAICollector(auth)
            collector.collect(inv, ["proj-1"])

        # At least one endpoint collected (from us-central1)
        assert len(inv.vertex_ai_endpoints) >= 1
        ep = inv.vertex_ai_endpoints[0]
        assert ep.name == "12345"
        assert ep.display_name == "gemini-endpoint"
        assert ep.network == ""

    def test_skips_when_api_not_enabled(self):
        from gcp_abuse_scanner.collectors.vertex_ai import VertexAICollector

        inv = ResourceInventory(project_ids=["proj-1"])
        auth = _make_auth()

        with patch("googleapiclient.discovery.build"):
            collector = VertexAICollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.vertex_ai_endpoints) == 0
        assert "aiplatform.googleapis.com" in inv.skipped_apis.get(
            "proj-1", []
        )  # lgtm[py/incomplete-url-substring-sanitization]


# ─────────────────────────────────────────────────────────────────────────────
# NetworkCollector
# ─────────────────────────────────────────────────────────────────────────────


class TestNetworkCollector:
    def test_collects_firewall_rules(self):
        from gcp_abuse_scanner.collectors.network import NetworkCollector

        inv = _inventory_with_apis("compute.googleapis.com")
        rule = {
            "name": "allow-ssh",
            "network": "https://www.googleapis.com/compute/v1/projects/proj-1/global/networks/default",
            "direction": "INGRESS",
            "priority": 1000,
            "sourceRanges": ["0.0.0.0/0"],
            "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
        }
        with patch("googleapiclient.discovery.build") as mock_build:
            mock_compute = MagicMock()
            mock_build.return_value = mock_compute
            mock_compute.firewalls().list().execute.return_value = {"items": [rule]}
            mock_compute.firewalls().list_next.return_value = None

            NetworkCollector(_make_auth()).collect(inv, ["proj-1"])

        assert len(inv.firewall_rules) == 1
        assert inv.firewall_rules[0].network == "default"  # self-link trimmed
        assert inv.skipped_apis == {}

    def test_records_a_coverage_gap_when_api_not_enabled(self):
        """No Compute API → no firewall rules → CM-003/004/008/050 must not read as PASS."""
        from gcp_abuse_scanner.collectors.network import NetworkCollector

        inv = _inventory_with_apis("serviceusage.googleapis.com")
        with patch("googleapiclient.discovery.build"):
            NetworkCollector(_make_auth()).collect(inv, ["proj-1"])

        assert inv.firewall_rules == []
        assert "compute.googleapis.com" in inv.skipped_apis.get("proj-1", [])

    def test_records_a_collector_error_on_api_failure(self):
        from gcp_abuse_scanner.collectors.network import NetworkCollector

        inv = _inventory_with_apis("compute.googleapis.com")
        with patch("googleapiclient.discovery.build") as mock_build:
            mock_build.return_value.firewalls().list().execute.side_effect = RuntimeError(
                "HTTP 500: backend error"
            )
            NetworkCollector(_make_auth()).collect(inv, ["proj-1"])

        assert [e["collector"] for e in inv.collector_errors] == ["network"]
        assert inv.collector_errors[0]["project_id"] == "proj-1"


# ─────────────────────────────────────────────────────────────────────────────
# IAMCollector
# ─────────────────────────────────────────────────────────────────────────────


class TestIAMCollector:
    def test_sa_collection_failure_is_recorded_as_a_coverage_gap(self):
        """A failed SA listing hides CM-041/CMN-004 — it must not pass silently."""
        from gcp_abuse_scanner.collectors.iam import IAMCollector

        inv = ResourceInventory(project_ids=["proj-1"])
        with (
            patch("gcp_abuse_scanner.collectors.iam.asset_v1.AssetServiceClient") as asset_cls,
            patch("googleapiclient.discovery.build") as mock_build,
        ):
            asset_cls.return_value.search_all_iam_policies.return_value = []
            mock_build.return_value.projects().serviceAccounts().list().execute.side_effect = (
                RuntimeError("HTTP 403: permission denied")
            )

            IAMCollector(_make_auth()).collect(inv, ["proj-1"])

        assert inv.service_accounts == []
        assert "iam.googleapis.com" in inv.skipped_apis.get("proj-1", [])


# ─────────────────────────────────────────────────────────────────────────────
# BillingCollector
# ─────────────────────────────────────────────────────────────────────────────


_BA = "015EC6-4BFF3F-9DC247"


def _billing_build(api, version, **kwargs):
    """cloudbilling and billingbudgets clients, mocked per API name."""
    if api == "cloudbilling":
        client = MagicMock()
        client.projects().getBillingInfo().execute.return_value = {
            "billingAccountName": f"billingAccounts/{_BA}"
        }
        return client
    client = MagicMock()
    client.billingAccounts().budgets().list().execute.return_value = {
        "budgets": [
            {
                "name": f"billingAccounts/{_BA}/budgets/b1",
                "displayName": "Monthly",
                "amount": {"specifiedAmount": {"units": "100"}},
                "thresholdRules": [{"thresholdPercent": 0.9}],
            }
        ]
    }
    client.billingAccounts().budgets().list_next.return_value = None
    return client


class TestBillingCollector:
    def test_collects_budgets_and_links_the_project(self):
        from gcp_abuse_scanner.collectors.billing import BillingCollector

        inv = _inventory_with_apis("cloudbilling.googleapis.com", "billingbudgets.googleapis.com")
        with patch("googleapiclient.discovery.build", side_effect=_billing_build):
            BillingCollector(_make_auth()).collect(inv, ["proj-1"])

        assert [b.billing_account_id for b in inv.budgets] == [_BA]
        assert inv.budgets_unreadable == []
        assert inv.projects[0].billing_account_id == _BA
        assert inv.collector_errors == []

    def test_budget_api_disabled_is_recorded_as_a_coverage_gap(self):
        """A 403 on the budgets API must not turn into 'the account has no budget'."""
        from gcp_abuse_scanner.collectors.billing import BillingCollector

        def _failing_build(api, version, **kwargs):
            client = _billing_build(api, version, **kwargs)
            if api == "billingbudgets":
                client.billingAccounts().budgets().list().execute.side_effect = RuntimeError(
                    "HTTP 403: Cloud Billing Budget API has not been used in project x before "
                    "or it is disabled"
                )
            return client

        inv = _inventory_with_apis("cloudbilling.googleapis.com", "billingbudgets.googleapis.com")
        with patch("googleapiclient.discovery.build", side_effect=_failing_build):
            BillingCollector(_make_auth()).collect(inv, ["proj-1"])

        assert inv.budgets == []
        assert inv.budgets_unreadable == [_BA]
        assert [e["collector"] for e in inv.collector_errors] == ["billing"]
        assert _BA in inv.collector_errors[0]["error"]

    def test_the_same_account_is_recorded_once(self):
        from gcp_abuse_scanner.collectors.billing import BillingCollector

        def _failing_build(api, version, **kwargs):
            client = _billing_build(api, version, **kwargs)
            if api == "billingbudgets":
                client.billingAccounts().budgets().list().execute.side_effect = RuntimeError("boom")
            return client

        inv = _inventory_with_apis("cloudbilling.googleapis.com", "billingbudgets.googleapis.com")
        with patch("googleapiclient.discovery.build", side_effect=_failing_build):
            BillingCollector(_make_auth()).collect(inv, ["proj-1", "proj-2"])

        assert inv.budgets_unreadable == [_BA]  # both projects share the account


# ─────────────────────────────────────────────────────────────────────────────
# OrgPolicyCollector
# ─────────────────────────────────────────────────────────────────────────────


class TestOrgPolicyCollector:
    def test_collects_org_level_policies(self):
        from gcp_abuse_scanner.collectors.org_policy import OrgPolicyCollector

        inv = ResourceInventory(project_ids=["proj-1"])
        auth = _make_auth()

        mock_policy = {
            "name": "organizations/123/policies/compute.vmExternalIpAccess",
            "spec": {"rules": [{"denyAll": "TRUE"}]},
        }

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_orgpolicy = MagicMock()
            mock_build.return_value = mock_orgpolicy

            # Org-level get returns a policy
            mock_orgpolicy.organizations().policies().get().execute.return_value = mock_policy

            # Project-level get raises (not set)
            mock_orgpolicy.projects().policies().get().execute.side_effect = Exception(
                "404 Not Found"
            )

            collector = OrgPolicyCollector(auth)
            collector.collect(inv, ["proj-1"], organization_id="123")

        # Should have entries for org + project for each constraint
        assert len(inv.org_policies) > 0
        # At least one should have the deny-all policy
        policies_with_spec = [p for p in inv.org_policies if p.policy]
        assert len(policies_with_spec) > 0

    def test_records_empty_policy_when_not_set(self):
        from gcp_abuse_scanner.collectors.org_policy import OrgPolicyCollector

        inv = ResourceInventory(project_ids=["proj-1"])
        auth = _make_auth()

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_orgpolicy = MagicMock()
            mock_build.return_value = mock_orgpolicy

            # All gets raise 404 (policy not configured)
            mock_orgpolicy.organizations().policies().get().execute.side_effect = Exception(
                "404 Not Found"
            )
            mock_orgpolicy.projects().policies().get().execute.side_effect = Exception(
                "404 Not Found"
            )

            collector = OrgPolicyCollector(auth)
            collector.collect(inv, ["proj-1"], organization_id="123")

        # Empty policy dicts recorded (not configured = important signal)
        empty_policies = [p for p in inv.org_policies if p.policy == {}]
        assert len(empty_policies) > 0


# ─────────────────────────────────────────────────────────────────────────────
# RecommenderCollector
# ─────────────────────────────────────────────────────────────────────────────


class TestRecommenderCollector:
    def test_collects_iam_recommendations(self):
        from gcp_abuse_scanner.collectors.recommender import RecommenderCollector

        inv = _inventory_with_apis("recommender.googleapis.com")
        auth = _make_auth()

        mock_rec = {
            "name": "projects/proj-1/locations/global/recommenders/google.iam.policy.Recommender/recommendations/abc123",
            "description": "Remove unused role from service account",
            "recommenderSubtype": "REMOVE_ROLE",
            "primaryImpact": {"category": "SECURITY"},
            "content": {
                "operationGroups": [
                    {
                        "operations": [
                            {
                                "action": "remove",
                                "resourceType": "cloudresourcemanager.googleapis.com/Project",
                                "resource": "//cloudresourcemanager.googleapis.com/projects/proj-1",
                                "path": "/iamPolicy",
                            }
                        ]
                    }
                ]
            },
            "stateInfo": {"state": "ACTIVE"},
            "priority": "P2",
        }

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_recommender = MagicMock()
            mock_build.return_value = mock_recommender

            (
                mock_recommender.projects()
                .locations()
                .recommenders()
                .recommendations()
                .list()
                .execute.return_value
            ) = {"recommendations": [mock_rec]}
            (
                mock_recommender.projects()
                .locations()
                .recommenders()
                .recommendations()
                .list_next.return_value
            ) = None

            collector = RecommenderCollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.recommender_insights) == 1
        insight = inv.recommender_insights[0]
        assert insight["project_id"] == "proj-1"
        assert insight["recommender_subtype"] == "REMOVE_ROLE"
        assert insight["priority"] == "P2"

    def test_skips_when_api_not_enabled(self):
        from gcp_abuse_scanner.collectors.recommender import RecommenderCollector

        inv = ResourceInventory(project_ids=["proj-1"])
        auth = _make_auth()

        with patch("googleapiclient.discovery.build"):
            collector = RecommenderCollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.recommender_insights) == 0
        assert "recommender.googleapis.com" in inv.skipped_apis.get(
            "proj-1", []
        )  # lgtm[py/incomplete-url-substring-sanitization]


# ─────────────────────────────────────────────────────────────────────────────
# QuotaCollector
# ─────────────────────────────────────────────────────────────────────────────


class TestQuotaCollector:
    @staticmethod
    def _metrics_by_service() -> dict[str, dict]:
        """Per-service responses — the real API only returns its own metrics."""
        return {
            "aiplatform.googleapis.com": {
                "metrics": [
                    {
                        "metric": "aiplatform.googleapis.com/online_prediction_requests_per_base_model_per_minute_per_project",
                        "consumerQuotaLimits": [
                            {
                                "name": "projects/proj-1/services/aiplatform.googleapis.com/consumerQuotaMetrics/online_prediction_requests_per_base_model_per_minute_per_project/limits/%2Fmin%2Fproject%2Fbase_model",
                                "unit": "1/min/{project}/{base_model}",
                                "isPrecise": True,
                                "quotaBuckets": [
                                    {
                                        "effectiveLimit": "60",
                                        "defaultLimit": "60",
                                        "dimensions": {},
                                    }
                                ],
                            }
                        ],
                    }
                ]
            },
            "generativelanguage.googleapis.com": {
                "metrics": [
                    {
                        "metric": "generativelanguage.googleapis.com/generate_content_requests",
                        "consumerQuotaLimits": [
                            {
                                "name": "projects/proj-1/services/generativelanguage.googleapis.com/consumerQuotaMetrics/generate_content_requests/limits/%2Fmin%2Fproject",
                                "unit": "1/min/{project}",
                                "quotaBuckets": [
                                    {"effectiveLimit": "4000", "defaultLimit": "4000"}
                                ],
                            }
                        ],
                    },
                    {
                        # Not a target metric for any other service — only the
                        # generativelanguage wildcard target picks it up.
                        "metric": "generativelanguage.googleapis.com/embed_content_requests",
                        "consumerQuotaLimits": [
                            {
                                "name": "projects/proj-1/services/generativelanguage.googleapis.com/consumerQuotaMetrics/embed_content_requests/limits/%2Fmin%2Fproject",
                                "unit": "1/min/{project}",
                                "quotaBuckets": [
                                    {"effectiveLimit": "3000", "defaultLimit": "3000"}
                                ],
                            }
                        ],
                    },
                ]
            },
        }

    def _collect(self, inv, project_id: str = "proj-1"):
        from gcp_abuse_scanner.collectors.quota import QuotaCollector

        responses = self._metrics_by_service()

        def _list(parent: str, **kwargs: object):
            service = parent.rsplit("/services/", 1)[-1]
            mock_request = MagicMock()
            mock_request.execute.return_value = responses.get(service, {"metrics": []})
            return mock_request

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_su = MagicMock()
            mock_build.return_value = mock_su
            mock_su.services().consumerQuotaMetrics().list.side_effect = _list

            QuotaCollector(_make_auth()).collect(inv, [project_id])

    def test_collects_vertex_ai_quota_info(self):
        inv = _inventory_with_apis(
            "serviceusage.googleapis.com",
            "aiplatform.googleapis.com",
            "compute.googleapis.com",
        )
        self._collect(inv)

        entries = [e for e in inv.quota_info if e["service"] == "aiplatform.googleapis.com"]
        assert len(entries) == 1
        assert entries[0]["project_id"] == "proj-1"
        assert entries[0]["quota_buckets"][0]["effectiveLimit"] == "60"

    def test_collects_gemini_api_quota_metrics(self):
        """The Generative Language service is a quota target on its own."""
        inv = _inventory_with_apis(
            "serviceusage.googleapis.com",
            "generativelanguage.googleapis.com",
        )
        self._collect(inv)

        metrics = {
            e["metric"]
            for e in inv.quota_info
            if e["service"] == "generativelanguage.googleapis.com"
        }
        assert metrics == {
            "generativelanguage.googleapis.com/generate_content_requests",
            "generativelanguage.googleapis.com/embed_content_requests",
        }

    def test_no_quota_when_service_not_enabled(self):
        # Only serviceusage enabled, not aiplatform, generativelanguage or compute
        inv = _inventory_with_apis("serviceusage.googleapis.com")
        self._collect(inv)

        # No quotas collected because target services not enabled
        assert len(inv.quota_info) == 0


# ─────────────────────────────────────────────────────────────────────────────
# APIKeysCollector
# ─────────────────────────────────────────────────────────────────────────────


class TestAPIKeysCollector:
    """APIKeysCollector always attempts collection regardless of enabled_apis."""

    def test_collects_keys_without_api_in_enabled_list(self):
        """Keys are collected even when apikeys.googleapis.com is NOT in enabled_apis."""
        from gcp_abuse_scanner.collectors.api_keys import APIKeysCollector

        # No apikeys.googleapis.com in enabled_apis — old code would skip entirely
        inv = ResourceInventory(project_ids=["proj-1"])
        auth = _make_auth()

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_client = MagicMock()
            mock_build.return_value = mock_client
            mock_client.projects().locations().keys().list().execute.return_value = {
                "keys": [
                    {
                        "name": "projects/proj-1/locations/global/keys/key-abc",
                        "displayName": "My Key",
                        "restrictions": {},
                        "createTime": "2024-01-01T00:00:00Z",
                        "uid": "abc123",
                    }
                ]
            }
            mock_client.projects().locations().keys().list_next.return_value = None

            collector = APIKeysCollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.api_keys) == 1
        assert inv.api_keys[0].uid == "abc123"

    def test_collects_keys_with_api_in_enabled_list(self):
        """Keys are also collected when apikeys.googleapis.com IS in enabled_apis."""
        from gcp_abuse_scanner.collectors.api_keys import APIKeysCollector

        inv = _inventory_with_apis("apikeys.googleapis.com", project_id="proj-1")
        auth = _make_auth()

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_client = MagicMock()
            mock_build.return_value = mock_client
            mock_client.projects().locations().keys().list().execute.return_value = {
                "keys": [
                    {
                        "name": "projects/proj-1/locations/global/keys/key-xyz",
                        "displayName": "Server Key",
                        "restrictions": {"serverKeyRestrictions": {"allowedIps": ["1.2.3.4"]}},
                        "createTime": "2025-01-01T00:00:00Z",
                        "uid": "xyz789",
                    }
                ]
            }
            mock_client.projects().locations().keys().list_next.return_value = None

            collector = APIKeysCollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.api_keys) == 1
        assert inv.api_keys[0].uid == "xyz789"

    def test_403_is_silent_debug_not_warning(self, caplog):
        """HTTP 403 from the API Keys API is logged at DEBUG, not WARNING."""
        import logging
        from unittest.mock import MagicMock, patch

        from googleapiclient.errors import HttpError

        from gcp_abuse_scanner.collectors.api_keys import APIKeysCollector

        inv = ResourceInventory(project_ids=["proj-1"])
        auth = _make_auth()

        resp = MagicMock()
        resp.status = 403
        resp.reason = "Forbidden"
        http_err = HttpError(
            resp=resp,
            content=b'{"error": {"code": 403, "message": "API Keys API not enabled."}}',
            uri="https://apikeys.googleapis.com/v2/projects/proj-1/locations/global/keys",
        )

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_client = MagicMock()
            mock_build.return_value = mock_client
            mock_client.projects().locations().keys().list().execute.side_effect = http_err

            with caplog.at_level(logging.WARNING, logger="gcp_abuse_scanner.collectors.api_keys"):
                collector = APIKeysCollector(auth)
                collector.collect(inv, ["proj-1"])

        # No WARNING should be emitted for 403
        warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert len(warnings) == 0
        assert len(inv.api_keys) == 0
        # ... but it is a coverage gap: "could not read the keys" != "there are no keys"
        assert inv.skipped_apis["proj-1"] == ["apikeys.googleapis.com"]
        assert inv.collector_errors == []

    def test_non_403_error_is_warning(self, caplog):
        """Unexpected errors (e.g. 500) are still logged as WARNING."""
        import logging
        from unittest.mock import MagicMock, patch

        from googleapiclient.errors import HttpError

        from gcp_abuse_scanner.collectors.api_keys import APIKeysCollector

        inv = ResourceInventory(project_ids=["proj-1"])
        auth = _make_auth()

        resp = MagicMock()
        resp.status = 500
        resp.reason = "Internal Server Error"
        http_err = HttpError(
            resp=resp,
            content=b'{"error": {"code": 500, "message": "Backend error."}}',
            uri="https://apikeys.googleapis.com/v2/projects/proj-1/locations/global/keys",
        )

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_client = MagicMock()
            mock_build.return_value = mock_client
            mock_client.projects().locations().keys().list().execute.side_effect = http_err

            with caplog.at_level(logging.WARNING, logger="gcp_abuse_scanner.collectors.api_keys"):
                collector = APIKeysCollector(auth)
                collector.collect(inv, ["proj-1"])

        warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert len(warnings) == 1
        assert "HTTP 500" in warnings[0].message
        # an unexpected failure is recorded as a collector error (not as a skipped API)
        assert inv.skipped_apis == {}
        assert [e["collector"] for e in inv.collector_errors] == ["api_keys"]
        assert inv.collector_errors[0]["project_id"] == "proj-1"


# ─────────────────────────────────────────────────────────────────────────────
# CollectorEngine integration (smoke test)
# ─────────────────────────────────────────────────────────────────────────────


class TestCollectorEngine:
    """
    Engine tests patch at the source module level (imports are local inside
    CollectorEngine.collect, so we patch the actual collector classes).
    """

    _PATCH_TARGETS = [
        "gcp_abuse_scanner.collectors.service_usage.ServiceUsageCollector",
        "gcp_abuse_scanner.collectors.iam.IAMCollector",
        "gcp_abuse_scanner.collectors.compute.ComputeCollector",
        "gcp_abuse_scanner.collectors.network.NetworkCollector",
        "gcp_abuse_scanner.collectors.api_keys.APIKeysCollector",
        "gcp_abuse_scanner.collectors.billing.BillingCollector",
        "gcp_abuse_scanner.collectors.gke.GKECollector",
        "gcp_abuse_scanner.collectors.cloud_run.CloudRunCollector",
        "gcp_abuse_scanner.collectors.vertex_ai.VertexAICollector",
        "gcp_abuse_scanner.collectors.org_policy.OrgPolicyCollector",
        "gcp_abuse_scanner.collectors.recommender.RecommenderCollector",
        "gcp_abuse_scanner.collectors.quota.QuotaCollector",
    ]

    def test_engine_returns_inventory(self):
        from gcp_abuse_scanner.collectors.engine import CollectorEngine

        auth = _make_auth()

        patches = [patch(t) for t in self._PATCH_TARGETS]
        mocks = [p.start() for p in patches]
        try:
            for m in mocks:
                instance = m.return_value
                instance.collect.return_value = None
                instance.name = "mock_collector"
                instance.required_apis = []

            engine = CollectorEngine(auth, max_workers=2)
            inventory = engine.collect(["proj-1", "proj-2"], organization_id="org-123")
        finally:
            for p in patches:
                p.stop()

        assert isinstance(inventory, ResourceInventory)
        assert inventory.organization_id == "org-123"
        assert set(inventory.project_ids) == {"proj-1", "proj-2"}

    def test_engine_handles_collector_failure(self):
        from gcp_abuse_scanner.collectors.engine import CollectorEngine

        auth = _make_auth()

        patches = [patch(t) for t in self._PATCH_TARGETS]
        mocks = [p.start() for p in patches]
        try:
            for m in mocks:
                instance = m.return_value
                instance.collect.return_value = None
                instance.name = "mock_collector"
                instance.required_apis = []

            # Make IAMCollector raise
            iam_mock = mocks[1]  # index 1 = IAMCollector
            iam_mock.return_value.collect.side_effect = RuntimeError("IAM API down")
            iam_mock.return_value.name = "iam"

            engine = CollectorEngine(auth, max_workers=2)
            inventory = engine.collect(["proj-1"])
        finally:
            for p in patches:
                p.stop()

        # Should not raise — errors captured in inventory
        assert isinstance(inventory, ResourceInventory)


# ─────────────────────────────────────────────────────────────────────────────
# A failed read must be recorded as a coverage gap (never a silent "no findings")
# ─────────────────────────────────────────────────────────────────────────────


class TestFailuresAreRecordedAsCoverageGaps:
    def test_service_usage_failure_blinds_the_scan_and_is_recorded(self):
        from gcp_abuse_scanner.collectors.service_usage import ServiceUsageCollector

        inv = ResourceInventory(project_ids=["proj-1"])
        with patch("gcp_abuse_scanner.collectors.service_usage.service_usage_v1") as su:
            su.ServiceUsageClient.return_value.list_services.side_effect = RuntimeError(
                "HTTP 403: permission denied"
            )
            ServiceUsageCollector(_make_auth()).collect(inv, ["proj-1"])

        assert inv.enabled_apis == []
        assert inv.inaccessible_projects == ["proj-1"]
        assert "serviceusage.googleapis.com" in inv.skipped_apis["proj-1"]

    def test_org_policy_unreadable_is_a_gap_not_a_not_configured_policy(self):
        """403 on a policy read must not become 'the constraint is not enforced'."""
        from gcp_abuse_scanner.collectors.org_policy import OrgPolicyCollector

        inv = _inventory_with_apis("orgpolicy.googleapis.com")
        with patch("googleapiclient.discovery.build") as mock_build:
            client = MagicMock()
            mock_build.return_value = client
            client.projects().policies().get().execute.side_effect = RuntimeError("HTTP 403")
            OrgPolicyCollector(_make_auth()).collect(inv, ["proj-1"])

        assert "orgpolicy.googleapis.com" in inv.skipped_apis["proj-1"]
        assert inv.org_policies == []  # nothing recorded as "not configured"

    def test_org_policy_404_still_means_not_configured(self):
        from gcp_abuse_scanner.collectors.org_policy import OrgPolicyCollector

        inv = _inventory_with_apis("orgpolicy.googleapis.com")
        with patch("googleapiclient.discovery.build") as mock_build:
            client = MagicMock()
            mock_build.return_value = client
            client.projects().policies().get().execute.side_effect = RuntimeError("HTTP 404")
            OrgPolicyCollector(_make_auth()).collect(inv, ["proj-1"])

        assert inv.skipped_apis == {}
        assert inv.org_policies and all(p.policy == {} for p in inv.org_policies)

    def test_org_policy_org_level_failure_is_recorded_as_a_collector_error(self):
        from gcp_abuse_scanner.collectors.org_policy import OrgPolicyCollector

        inv = _inventory_with_apis("orgpolicy.googleapis.com")
        with patch("googleapiclient.discovery.build") as mock_build:
            client = MagicMock()
            mock_build.return_value = client
            client.organizations().policies().get().execute.side_effect = RuntimeError(
                "transport timeout after 30s"
            )
            OrgPolicyCollector(_make_auth()).collect(inv, ["proj-1"], organization_id="123")

        errors = [e for e in inv.collector_errors if e["collector"] == "org_policy"]
        assert errors and "organizations/123" in errors[0]["error"]

    def test_quota_failure_is_recorded_as_a_skipped_api(self):
        from gcp_abuse_scanner.collectors.quota import QuotaCollector

        inv = _inventory_with_apis("serviceusage.googleapis.com", "aiplatform.googleapis.com")
        with patch("googleapiclient.discovery.build") as mock_build:
            client = MagicMock()
            mock_build.return_value = client
            client.services().consumerQuotaMetrics().list().execute.side_effect = RuntimeError(
                "transport timeout after 30s"
            )
            QuotaCollector(_make_auth()).collect(inv, ["proj-1"])

        skipped = inv.skipped_apis["proj-1"]
        assert any(
            "serviceusage.googleapis.com" in s or "aiplatform.googleapis.com" in s for s in skipped
        )

    def test_billing_info_failure_is_recorded_as_a_skipped_api(self):
        from gcp_abuse_scanner.collectors.billing import BillingCollector

        inv = _inventory_with_apis("cloudbilling.googleapis.com", "billingbudgets.googleapis.com")

        def _build(api, version, **kwargs):
            client = MagicMock()
            if api == "cloudbilling":
                client.projects().getBillingInfo().execute.side_effect = RuntimeError(
                    "HTTP 403: permission denied"
                )
            return client

        with patch("googleapiclient.discovery.build", side_effect=_build):
            BillingCollector(_make_auth()).collect(inv, ["proj-1"])

        assert "cloudbilling.googleapis.com" in inv.skipped_apis["proj-1"]
