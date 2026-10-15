"""
Crypto Mining checks — Compute Engine.

CM-001: VMs with external IP
CM-004: Firewall ingress open on admin ports from 0.0.0.0/0
CM-006: Project metadata with serial-port-enable or OS Login disabled
CM-008: Firewall ingress open on database ports (MySQL 3306, PostgreSQL 5432) from 0.0.0.0/0
CM-009: Shielded VM not enabled
"""

from __future__ import annotations

import hashlib

from gcp_abuse_scanner.checks.base import BaseCheck, CheckRegistry
from gcp_abuse_scanner.models.finding import (
    Finding,
    FindingStatus,
    GCPResource,
    Remediation,
    RemediationEffort,
    Severity,
    Vector,
)
from gcp_abuse_scanner.models.inventory import ComputeInstance, ResourceInventory

_ADMIN_PORTS = {"22", "3389", "5985", "5986"}
_DB_PORTS = {"3306", "5432"}  # MySQL, PostgreSQL


def _make_id(check_id: str, project_id: str, resource: str) -> str:
    h = hashlib.md5(resource.encode(), usedforsecurity=False).hexdigest()[:8]
    return f"{check_id}-{project_id}-{h}"


@CheckRegistry.register
class CM001ExternalIP(BaseCheck):
    """VMs with an external (public) IP address unnecessarily exposed."""

    check_id = "CM-001"
    title = "VM instance has an external IP address"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.HIGH
    required_collectors = ["compute"]
    references = ["CIS GCP 4.9"]
    tags = ["compute", "network", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for instance in inventory.compute_instances:
            external_ips = self._get_external_ips(instance)
            if not external_ips:
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, instance.project_id, instance.self_link),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=7.5,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="compute.googleapis.com/Instance",
                        resource_id=instance.self_link or instance.name,
                        project_id=instance.project_id,
                        region=instance.zone,
                    ),
                    evidence={
                        "instance_name": instance.name,
                        "zone": instance.zone,
                        "external_ips": external_ips,
                    },
                    description=(
                        f"Instance '{instance.name}' in zone '{instance.zone}' has "
                        f"external IP(s) {external_ips}. External IPs increase attack surface "
                        "and can be used as C2 endpoints or to connect to mining pools."
                    ),
                    impact=(
                        "A compromised or misconfigured VM with an external IP can communicate "
                        "directly with crypto mining pools, bypassing internal controls."
                    ),
                    remediation=Remediation(
                        summary="Remove external IPs and use Cloud NAT for outbound connectivity.",
                        steps=[
                            "Assess whether the external IP is required for the workload.",
                            "If not required, delete the access config: remove the external IP.",
                            "Configure Cloud NAT for outbound internet access if needed.",
                            "Enforce via Org Policy: constraints/compute.vmExternalIpAccess.",
                        ],
                        gcloud_commands=[
                            "gcloud compute instances delete-access-config INSTANCE_NAME --access-config-name='External NAT' --zone=ZONE",
                            "# Enforce org-wide:\ngcloud resource-manager org-policies set-policy --organization=ORG_ID policy.yaml",
                        ],
                        iac_reference="google_compute_instance.network_interface.access_config",
                        docs=[
                            "https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address#deleting_a_static_external_ip_address",
                            "https://cloud.google.com/nat/docs/overview",
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings

    @staticmethod
    def _get_external_ips(instance: ComputeInstance) -> list[str]:
        ips = []
        for nic in instance.network_interfaces:
            for ac in nic.get("accessConfigs", []):
                nat_ip = ac.get("natIP")
                if nat_ip:
                    ips.append(nat_ip)
        return ips


@CheckRegistry.register
class CM004FirewallAdminPortsOpen(BaseCheck):
    """Firewall ingress rule allows SSH/RDP from 0.0.0.0/0."""

    check_id = "CM-004"
    title = "Firewall rule allows admin port access from the internet (0.0.0.0/0)"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.CRITICAL
    required_collectors = ["network"]
    references = ["CIS GCP 3.6", "CIS GCP 3.7"]
    tags = ["network", "firewall", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for rule in inventory.firewall_rules:
            if rule.direction != "INGRESS" or rule.disabled:
                continue
            if not self._is_open_to_internet(rule):
                continue
            exposed_ports = self._exposed_admin_ports(rule)
            if not exposed_ports:
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, rule.project_id, rule.name),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=9.5,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="compute.googleapis.com/Firewall",
                        resource_id=rule.name,
                        project_id=rule.project_id,
                    ),
                    evidence={
                        "rule_name": rule.name,
                        "network": rule.network,
                        "source_ranges": rule.source_ranges,
                        "exposed_ports": exposed_ports,
                        "allowed": rule.allowed,
                    },
                    description=(
                        f"Firewall rule '{rule.name}' allows inbound traffic on admin "
                        f"port(s) {exposed_ports} from 0.0.0.0/0 (any source). "
                        "This enables brute-force or exploitation attacks that can lead "
                        "to VM compromise and subsequent crypto mining."
                    ),
                    impact=(
                        "Direct internet access to SSH/RDP allows attackers to compromise "
                        "VMs and install crypto mining software."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Restrict SSH/RDP access to specific trusted IP ranges or use "
                            "Identity-Aware Proxy (IAP) for zero-trust access."
                        ),
                        steps=[
                            "Identify who legitimately needs SSH/RDP access.",
                            "Replace 0.0.0.0/0 source range with specific IP ranges.",
                            "Alternatively, enable IAP for TCP forwarding and remove direct SSH/RDP rules.",
                            "Consider using OS Login for SSH key management.",
                        ],
                        gcloud_commands=[
                            f"gcloud compute firewall-rules update {rule.name} --source-ranges=TRUSTED_IP_RANGE",
                            f"# Or delete and use IAP:\ngcloud compute firewall-rules delete {rule.name}",
                        ],
                        iac_reference="google_compute_firewall.source_ranges",
                        docs=[
                            "https://cloud.google.com/iap/docs/using-tcp-forwarding",
                            "https://cloud.google.com/compute/docs/oslogin",
                        ],
                        effort=RemediationEffort.LOW,
                    ),
                    references=self.references,
                )
            )
        return findings

    @staticmethod
    def _is_open_to_internet(rule: object) -> bool:
        return "0.0.0.0/0" in getattr(rule, "source_ranges", []) or "::/0" in getattr(
            rule, "source_ranges", []
        )

    @staticmethod
    def _exposed_admin_ports(rule: object) -> list[str]:
        exposed = []
        for allow in getattr(rule, "allowed", []):
            ports = allow.get("ports", [])
            proto = allow.get("IPProtocol", "")
            if proto in ("tcp", "all"):
                if not ports:  # all ports
                    exposed.extend(list(_ADMIN_PORTS))
                else:
                    for p in ports:
                        if str(p) in _ADMIN_PORTS:
                            exposed.append(str(p))
        return list(set(exposed))


@CheckRegistry.register
class CM008FirewallDatabasePortsOpen(BaseCheck):
    """Firewall ingress rule allows database access (MySQL/PostgreSQL) from 0.0.0.0/0."""

    check_id = "CM-008"
    title = "Firewall rule allows database port access from the internet (0.0.0.0/0)"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.CRITICAL
    required_collectors = ["network"]
    references = ["CIS GCP 3.6"]
    tags = ["network", "firewall", "database", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for rule in inventory.firewall_rules:
            if rule.direction != "INGRESS" or rule.disabled:
                continue
            if not CM004FirewallAdminPortsOpen._is_open_to_internet(rule):
                continue
            exposed_ports = self._exposed_db_ports(rule)
            if not exposed_ports:
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, rule.project_id, rule.name),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=9.2,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="compute.googleapis.com/Firewall",
                        resource_id=rule.name,
                        project_id=rule.project_id,
                    ),
                    evidence={
                        "rule_name": rule.name,
                        "network": rule.network,
                        "source_ranges": rule.source_ranges,
                        "exposed_ports": exposed_ports,
                        "allowed": rule.allowed,
                    },
                    description=(
                        f"Firewall rule '{rule.name}' allows inbound traffic on database "
                        f"port(s) {exposed_ports} from 0.0.0.0/0 (any source). Internet-facing "
                        "databases are brute-forced, scanned, and exploited continuously; "
                        "compromised data or compute resources can be abused for crypto "
                        "mining or data exfiltration."
                    ),
                    impact=(
                        "Direct internet access to MySQL/PostgreSQL enables credential "
                        "brute-force, exploitation of unpatched database engines, and full "
                        "data exfiltration or VM compromise leading to crypto mining."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Restrict database access to specific trusted IP ranges, or "
                            "remove public access entirely and use private IP / Cloud SQL "
                            "Auth Proxy."
                        ),
                        steps=[
                            "Identify the legitimate clients that need database access.",
                            "Replace 0.0.0.0/0 source range with specific IP ranges or VPC CIDR.",
                            "For Cloud SQL, disable public IP and use Private IP or the Auth Proxy.",
                            "Consider VPC Service Controls and private services access.",
                        ],
                        gcloud_commands=[
                            f"gcloud compute firewall-rules update {rule.name} --source-ranges=TRUSTED_IP_RANGE",
                            "# Cloud SQL: disable public IP\n"
                            "gcloud sql instances patch INSTANCE_NAME --no-assign-ip",
                        ],
                        iac_reference="google_compute_firewall.source_ranges",
                        docs=[
                            "https://cloud.google.com/sql/docs/mysql/configure-private-ip",
                            "https://cloud.google.com/sql/docs/postgres/connect-auth-proxy",
                        ],
                        effort=RemediationEffort.LOW,
                    ),
                    references=self.references,
                )
            )
        return findings

    @staticmethod
    def _exposed_db_ports(rule: object) -> list[str]:
        exposed = []
        for allow in getattr(rule, "allowed", []):
            ports = allow.get("ports", [])
            proto = allow.get("IPProtocol", "")
            if proto in ("tcp", "all"):
                if not ports:  # all ports
                    exposed.extend(list(_DB_PORTS))
                else:
                    for p in ports:
                        if str(p) in _DB_PORTS:
                            exposed.append(str(p))
        return list(set(exposed))


@CheckRegistry.register
class CM009ShieldedVMDisabled(BaseCheck):
    """VM instances without Shielded VM (Secure Boot / vTPM) enabled."""

    check_id = "CM-009"
    title = "VM instance does not have Shielded VM enabled"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.MEDIUM
    required_collectors = ["compute"]
    references = ["CIS GCP 4.8"]
    tags = ["compute", "crypto_mining", "hardening"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for instance in inventory.compute_instances:
            cfg = instance.shielded_instance_config
            secure_boot = cfg.get("enableSecureBoot", False)
            vtpm = cfg.get("enableVtpm", False)
            integrity = cfg.get("enableIntegrityMonitoring", False)

            if secure_boot and vtpm and integrity:
                continue

            missing = []
            if not secure_boot:
                missing.append("Secure Boot")
            if not vtpm:
                missing.append("vTPM")
            if not integrity:
                missing.append("Integrity Monitoring")

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, instance.project_id, instance.self_link),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=4.0,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="compute.googleapis.com/Instance",
                        resource_id=instance.self_link or instance.name,
                        project_id=instance.project_id,
                        region=instance.zone,
                    ),
                    evidence={
                        "instance_name": instance.name,
                        "zone": instance.zone,
                        "missing_features": missing,
                        "shielded_config": cfg,
                    },
                    description=(
                        f"Instance '{instance.name}' is missing Shielded VM features: "
                        f"{', '.join(missing)}. Without these controls, rootkits or "
                        "bootkit-based crypto miners can persist across reboots."
                    ),
                    impact=(
                        "Crypto mining malware can achieve boot-level persistence, "
                        "surviving OS reinstalls and evading detection."
                    ),
                    remediation=Remediation(
                        summary="Enable Secure Boot, vTPM, and Integrity Monitoring on all VMs.",
                        steps=[
                            "Stop the instance.",
                            "Enable Shielded VM features (requires compatible image).",
                            "Restart the instance.",
                            "Enforce via Org Policy: constraints/compute.requireShieldedVm.",
                        ],
                        gcloud_commands=[
                            f"gcloud compute instances stop {instance.name} --zone={instance.zone}",
                            f"gcloud compute instances update {instance.name} --zone={instance.zone} --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring",
                            f"gcloud compute instances start {instance.name} --zone={instance.zone}",
                        ],
                        iac_reference="google_compute_instance.shielded_instance_config",
                        docs=["https://cloud.google.com/compute/shielded-vm/docs/shielded-vm"],
                        effort=RemediationEffort.LOW,
                    ),
                    references=self.references,
                )
            )
        return findings
