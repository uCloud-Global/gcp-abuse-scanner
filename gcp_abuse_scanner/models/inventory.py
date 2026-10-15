"""Resource inventory — normalized facts collected from GCP APIs."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ProjectInfo(BaseModel):
    project_id: str
    project_number: str | None = None
    display_name: str | None = None
    organization_id: str | None = None
    folder_ids: list[str] = Field(default_factory=list)
    state: str = "ACTIVE"
    labels: dict[str, str] = Field(default_factory=dict)
    billing_account_id: str | None = None


class ComputeInstance(BaseModel):
    name: str
    project_id: str
    zone: str
    machine_type: str
    status: str
    network_interfaces: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)
    service_accounts: list[dict[str, Any]] = Field(default_factory=list)
    shielded_instance_config: dict[str, Any] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    accelerators: list[dict[str, Any]] = Field(default_factory=list)
    self_link: str = ""


class FirewallRule(BaseModel):
    name: str
    project_id: str
    network: str
    direction: str  # INGRESS | EGRESS
    priority: int = 1000
    source_ranges: list[str] = Field(default_factory=list)
    destination_ranges: list[str] = Field(default_factory=list)
    allowed: list[dict[str, Any]] = Field(default_factory=list)
    denied: list[dict[str, Any]] = Field(default_factory=list)
    target_tags: list[str] = Field(default_factory=list)
    disabled: bool = False


class IAMBinding(BaseModel):
    resource: str  # full resource name
    resource_type: str
    project_id: str
    role: str
    members: list[str] = Field(default_factory=list)


class ServiceAccountInfo(BaseModel):
    name: str
    email: str
    project_id: str
    disabled: bool = False
    keys: list[dict[str, Any]] = Field(default_factory=list)


class GKECluster(BaseModel):
    name: str
    project_id: str
    location: str
    endpoint: str = ""
    master_authorized_networks_config: dict[str, Any] = Field(default_factory=dict)
    workload_identity_config: dict[str, Any] = Field(default_factory=dict)
    node_pools: list[dict[str, Any]] = Field(default_factory=list)
    legacy_abac: dict[str, Any] = Field(default_factory=dict)
    private_cluster_config: dict[str, Any] = Field(default_factory=dict)
    autopilot: dict[str, Any] = Field(default_factory=dict)


class CloudRunService(BaseModel):
    name: str
    project_id: str
    region: str
    ingress: str = ""
    iam_bindings: list[dict[str, Any]] = Field(default_factory=list)
    scaling: dict[str, Any] = Field(default_factory=dict)
    template: dict[str, Any] = Field(default_factory=dict)


class APIKey(BaseModel):
    name: str
    project_id: str
    display_name: str = ""
    restrictions: dict[str, Any] = Field(default_factory=dict)
    create_time: str = ""
    uid: str = ""


class EnabledAPI(BaseModel):
    project_id: str
    service_name: str
    state: str = "ENABLED"


class BudgetInfo(BaseModel):
    name: str
    billing_account_id: str
    display_name: str = ""
    amount: dict[str, Any] = Field(default_factory=dict)
    threshold_rules: list[dict[str, Any]] = Field(default_factory=list)
    budget_filter: dict[str, Any] = Field(default_factory=dict)


class OrgPolicy(BaseModel):
    resource: str
    constraint: str
    policy: dict[str, Any] = Field(default_factory=dict)


class VertexAIEndpoint(BaseModel):
    name: str
    project_id: str
    region: str
    display_name: str = ""
    network: str = ""
    iam_bindings: list[dict[str, Any]] = Field(default_factory=list)


class ResourceInventory(BaseModel):
    """
    Normalized collection of GCP resource facts gathered by collectors.
    Checks evaluate this inventory — no direct API calls from checks.
    """

    # Scope
    organization_id: str | None = None
    project_ids: list[str] = Field(default_factory=list)

    # Resources
    projects: list[ProjectInfo] = Field(default_factory=list)
    compute_instances: list[ComputeInstance] = Field(default_factory=list)
    firewall_rules: list[FirewallRule] = Field(default_factory=list)
    iam_bindings: list[IAMBinding] = Field(default_factory=list)
    service_accounts: list[ServiceAccountInfo] = Field(default_factory=list)
    gke_clusters: list[GKECluster] = Field(default_factory=list)
    cloud_run_services: list[CloudRunService] = Field(default_factory=list)
    api_keys: list[APIKey] = Field(default_factory=list)
    enabled_apis: list[EnabledAPI] = Field(default_factory=list)
    budgets: list[BudgetInfo] = Field(default_factory=list)
    budgets_unreadable: list[str] = Field(
        default_factory=list,
        description=(
            "Billing account IDs whose budgets could not be read (API disabled, 403). "
            "The budget checks must not assert 'no budget' for these accounts."
        ),
    )
    org_policies: list[OrgPolicy] = Field(default_factory=list)
    vertex_ai_endpoints: list[VertexAIEndpoint] = Field(default_factory=list)

    # Extended data from Phase 1 collectors
    recommender_insights: list[dict] = Field(
        default_factory=list,
        description="IAM Recommender active recommendations (over-permissioned SAs)",
    )
    quota_info: list[dict] = Field(
        default_factory=list,
        description="Service quota entries for Vertex AI and Compute Engine",
    )

    # Coverage tracking
    inaccessible_projects: list[str] = Field(default_factory=list)
    skipped_apis: dict[str, list[str]] = Field(
        default_factory=dict,
        description="project_id -> list of APIs that were not enabled/accessible",
    )
    collector_errors: list[dict[str, str]] = Field(default_factory=list)
