"""Unit tests for crypto mining checks — offline, using inventory fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gcp_abuse_scanner.checks.crypto_mining.cm_compute import (
    CM001ExternalIP,
    CM004FirewallAdminPortsOpen,
    CM008FirewallDatabasePortsOpen,
    CM009ShieldedVMDisabled,
)
from gcp_abuse_scanner.checks.crypto_mining.cm_iam import (
    CM041SAUserManagedKeys,
    CM043PublicIAMBinding,
    CM044DefaultComputeSAEditor,
)
from gcp_abuse_scanner.models.finding import FindingStatus, Severity
from gcp_abuse_scanner.models.inventory import ResourceInventory

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def crypto_inventory() -> ResourceInventory:
    data = json.loads((FIXTURES_DIR / "inventory_crypto_mining.json").read_text())
    return ResourceInventory(**data)


@pytest.fixture
def clean_inventory() -> ResourceInventory:
    """Inventory with no security issues."""
    return ResourceInventory(project_ids=["clean-project"])


# --- CM-001 ---


class TestCM001ExternalIP:
    def test_fail_when_vm_has_external_ip(self, crypto_inventory: ResourceInventory) -> None:
        check = CM001ExternalIP()
        findings = check.evaluate(crypto_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-001"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].status == FindingStatus.FAIL
        assert "34.123.45.67" in findings[0].evidence["external_ips"]

    def test_pass_when_no_external_ip(self, clean_inventory: ResourceInventory) -> None:
        check = CM001ExternalIP()
        findings = check.evaluate(clean_inventory)
        assert findings == []


# --- CM-004 ---


class TestCM004FirewallAdminPorts:
    def test_fail_when_ssh_open_to_internet(self, crypto_inventory: ResourceInventory) -> None:
        check = CM004FirewallAdminPortsOpen()
        findings = check.evaluate(crypto_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-004"
        assert findings[0].severity == Severity.CRITICAL
        assert "22" in findings[0].evidence["exposed_ports"]

    def test_pass_when_no_open_admin_ports(self, clean_inventory: ResourceInventory) -> None:
        check = CM004FirewallAdminPortsOpen()
        findings = check.evaluate(clean_inventory)
        assert findings == []

    def test_pass_when_rule_disabled(self, crypto_inventory: ResourceInventory) -> None:
        for rule in crypto_inventory.firewall_rules:
            rule.disabled = True
        check = CM004FirewallAdminPortsOpen()
        findings = check.evaluate(crypto_inventory)
        assert findings == []


# --- CM-008 ---


def _firewall_rule(
    name: str = "allow-db-from-internet",
    source_ranges: list[str] | None = None,
    allowed: list[dict] | None = None,
    direction: str = "INGRESS",
    disabled: bool = False,
):
    from gcp_abuse_scanner.models.inventory import FirewallRule

    return FirewallRule(
        name=name,
        project_id="test-project-001",
        network="default",
        direction=direction,
        source_ranges=source_ranges if source_ranges is not None else ["0.0.0.0/0"],
        allowed=allowed if allowed is not None else [{"IPProtocol": "tcp", "ports": ["3306"]}],
        disabled=disabled,
    )


class TestCM008FirewallDatabasePorts:
    def test_fail_when_mysql_open_to_internet(self, clean_inventory: ResourceInventory) -> None:
        clean_inventory.firewall_rules.append(_firewall_rule())
        findings = CM008FirewallDatabasePortsOpen().evaluate(clean_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-008"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].evidence["exposed_ports"] == ["3306"]

    def test_fail_when_postgres_open_to_internet(self, clean_inventory: ResourceInventory) -> None:
        clean_inventory.firewall_rules.append(
            _firewall_rule(allowed=[{"IPProtocol": "tcp", "ports": ["5432"]}])
        )
        findings = CM008FirewallDatabasePortsOpen().evaluate(clean_inventory)
        assert len(findings) == 1
        assert findings[0].evidence["exposed_ports"] == ["5432"]

    def test_fail_when_all_ports_open(self, clean_inventory: ResourceInventory) -> None:
        clean_inventory.firewall_rules.append(_firewall_rule(allowed=[{"IPProtocol": "all"}]))
        findings = CM008FirewallDatabasePortsOpen().evaluate(clean_inventory)
        assert len(findings) == 1
        assert sorted(findings[0].evidence["exposed_ports"]) == ["3306", "5432"]

    def test_pass_when_source_range_restricted(self, clean_inventory: ResourceInventory) -> None:
        clean_inventory.firewall_rules.append(
            _firewall_rule(source_ranges=["10.0.0.0/8", "192.168.1.0/24"])
        )
        findings = CM008FirewallDatabasePortsOpen().evaluate(clean_inventory)
        assert findings == []

    def test_pass_when_ports_are_not_database_ports(
        self, clean_inventory: ResourceInventory
    ) -> None:
        clean_inventory.firewall_rules.append(
            _firewall_rule(allowed=[{"IPProtocol": "tcp", "ports": ["443", "8080"]}])
        )
        findings = CM008FirewallDatabasePortsOpen().evaluate(clean_inventory)
        assert findings == []

    def test_pass_when_rule_is_egress_or_disabled(self, clean_inventory: ResourceInventory) -> None:
        clean_inventory.firewall_rules.append(_firewall_rule(direction="EGRESS"))
        clean_inventory.firewall_rules.append(_firewall_rule(name="disabled-rule", disabled=True))
        findings = CM008FirewallDatabasePortsOpen().evaluate(clean_inventory)
        assert findings == []

    def test_remediation_has_commands_and_iac(self, clean_inventory: ResourceInventory) -> None:
        clean_inventory.firewall_rules.append(_firewall_rule())
        finding = CM008FirewallDatabasePortsOpen().evaluate(clean_inventory)[0]
        assert finding.remediation.summary
        assert finding.remediation.steps
        assert finding.remediation.gcloud_commands
        assert finding.remediation.iac_reference


# --- CM-009 ---


class TestCM009ShieldedVM:
    def test_fail_when_shielded_vm_disabled(self, crypto_inventory: ResourceInventory) -> None:
        check = CM009ShieldedVMDisabled()
        findings = check.evaluate(crypto_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-009"
        assert "Secure Boot" in findings[0].evidence["missing_features"]

    def test_pass_when_shielded_vm_enabled(self, crypto_inventory: ResourceInventory) -> None:
        for instance in crypto_inventory.compute_instances:
            instance.shielded_instance_config = {
                "enableSecureBoot": True,
                "enableVtpm": True,
                "enableIntegrityMonitoring": True,
            }
        check = CM009ShieldedVMDisabled()
        findings = check.evaluate(crypto_inventory)
        assert findings == []


# --- CM-043 ---


class TestCM043PublicIAMBinding:
    def test_pass_when_no_public_bindings(self, crypto_inventory: ResourceInventory) -> None:
        check = CM043PublicIAMBinding()
        findings = check.evaluate(crypto_inventory)
        assert findings == []

    def test_fail_when_all_users_binding(self, crypto_inventory: ResourceInventory) -> None:
        from gcp_abuse_scanner.models.inventory import IAMBinding

        crypto_inventory.iam_bindings.append(
            IAMBinding(
                resource="//cloudresourcemanager.googleapis.com/projects/test-project-001",
                resource_type="cloudresourcemanager.googleapis.com/Project",
                project_id="test-project-001",
                role="roles/compute.instanceAdmin",
                members=["allUsers"],
            )
        )
        check = CM043PublicIAMBinding()
        findings = check.evaluate(crypto_inventory)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL


# --- CM-044 ---


class TestCM044DefaultComputeSAEditor:
    def test_fail_when_default_sa_has_editor(self, crypto_inventory: ResourceInventory) -> None:
        check = CM044DefaultComputeSAEditor()
        findings = check.evaluate(crypto_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-044"
        assert findings[0].severity == Severity.HIGH

    def test_pass_when_no_default_sa_editor(self, clean_inventory: ResourceInventory) -> None:
        check = CM044DefaultComputeSAEditor()
        findings = check.evaluate(clean_inventory)
        assert findings == []


# --- CM-041 ---


class TestCM041SAUserManagedKeys:
    def test_fail_when_user_managed_keys_exist(self, crypto_inventory: ResourceInventory) -> None:
        check = CM041SAUserManagedKeys()
        findings = check.evaluate(crypto_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-041"

    def test_pass_when_no_user_managed_keys(self, clean_inventory: ResourceInventory) -> None:
        check = CM041SAUserManagedKeys()
        findings = check.evaluate(clean_inventory)
        assert findings == []
