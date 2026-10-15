# Crypto Mining Checks

> Checks that detect GCP misconfigurations enabling unauthorized crypto mining.

## Summary Table

| Check ID | Title | Severity | Collectors | CIS Reference |
|---|---|---|---|---|
| CM-001 | VM instance has an external IP address | HIGH | `compute` | CIS GCP 4.9 |
| CM-002 | Org Policy compute.vmExternalIpAccess is not enforced | HIGH | `org_policy` | CIS GCP 4.9 |
| CM-003 | Firewall allows unrestricted egress to the internet (0.0.0.0/0) | HIGH | `network` | CIS GCP 3.8 |
| CM-004 | Firewall rule allows admin port access from the internet (0.0.0.0/0) | CRITICAL | `network` | CIS GCP 3.6, 3.7 |
| CM-005 | VM instances with GPU accelerators detected without org-level restriction | MEDIUM | `compute` | — |
| CM-006 | VM instance or project has insecure metadata (serial port enabled or OS Login disabled) | MEDIUM | `compute` | CIS GCP 4.4, 4.5 |
| CM-007 | VM startup script downloads or executes content from external URLs | MEDIUM | `compute` | — |
| CM-008 | Firewall rule allows database port access from the internet (0.0.0.0/0) | CRITICAL | `network` | CIS GCP 3.6 |
| CM-009 | VM instance does not have Shielded VM enabled | MEDIUM | `compute` | CIS GCP 4.8 |
| CM-011 | Org Policy gcp.resourceLocations is not configured (no region restriction) | MEDIUM | `org_policy` | — |
| CM-020 | GKE node pool has autoscaling enabled without a maxNodeCount limit | HIGH | `gke` | CIS GKE 6.8.1 |
| CM-021 | GKE cluster has Node Auto-Provisioning enabled without resource limits | HIGH | `gke` | CIS GKE 6.8.2 |
| CM-023 | GKE cluster has a public control plane endpoint without authorized networks configured | HIGH | `gke` | CIS GKE 6.6.2, 6.6.3 |
| CM-024 | GKE cluster does not have Workload Identity enabled | MEDIUM | `gke` | CIS GKE 6.2.2 |
| CM-025 | GKE cluster has Legacy ABAC (Attribute-Based Access Control) enabled | MEDIUM | `gke` | CIS GKE 6.8.4 |
| CM-026 | GKE node pool uses the default Compute Engine service account | HIGH | `gke` | CIS GKE 6.2.1 |
| CM-030 | Cloud Run service allows public invocation (allUsers invoker) | HIGH | `cloud_run` | CIS GCP 2.13 |
| CM-031 | Cloud Run service has no maxScale limit configured (unbounded scaling) | MEDIUM | `cloud_run` | — |
| CM-040 | Service account or principal has broad compute creation roles (compute.admin, container.admin) | HIGH | `iam` | CIS GCP 1.5, 7.1 |
| CM-041 | Service account has user-managed (exported) keys | HIGH | `iam` | CIS GCP 1.4 |
| CM-042 | iam.serviceAccountTokenCreator or serviceAccountUser granted broadly | HIGH | `iam` | CIS GCP 1.6 |
| CM-043 | IAM binding grants access to allUsers or allAuthenticatedUsers | CRITICAL | `iam` | CIS GCP 1.18 |
| CM-044 | Default Compute Engine service account has Editor or Owner role | HIGH | `iam` | CIS GCP 4.1 |
| CM-045 | IAM Recommender identifies service account with unused compute permissions | MEDIUM | `recommender` | — |
| CM-046 | Personal (consumer email) account holds Owner or Editor | CRITICAL | `iam` | CIS GCP 1.1 |
| CM-050 | VPC has no egress deny-all firewall rule (unrestricted outbound traffic) | HIGH | `network` | CIS GCP 3.10 |
| CM-060 | Project or billing account has no budget or budget alert configured | HIGH | `billing` | — |

---

## Check Details

### CM-001 — VM instance has an external IP address

**Severity:** HIGH
**Vector:** Crypto Mining
**Collectors required:** `compute`
**CIS Reference:** [CIS GCP 4.9](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)

**What it detects:**
VM instances that have one or more external (public) IP addresses assigned via access configs on their network interfaces.

**Why it matters:**
A VM with an external IP can communicate directly with crypto mining pools on the internet without going through any internal network controls. Attackers who compromise or deploy such a VM can immediately begin mining without additional network configuration. External IPs also increase the attack surface, making the VM reachable from the internet for initial compromise.

**Remediation:**
1. Assess whether the external IP is required for the workload.
2. If not required, delete the access config to remove the external IP.
3. Configure Cloud NAT for outbound internet access if needed.
4. Enforce organization-wide via Org Policy: `constraints/compute.vmExternalIpAccess`.

```bash
gcloud compute instances delete-access-config INSTANCE_NAME \
  --access-config-name='External NAT' --zone=ZONE

# Enforce org-wide:
gcloud resource-manager org-policies set-policy \
  --organization=ORG_ID policy.yaml
```

**References:**
- [Reserve static external IP addresses](https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address#deleting_a_static_external_ip_address)
- [Cloud NAT overview](https://cloud.google.com/nat/docs/overview)

---

### CM-002 — Org Policy compute.vmExternalIpAccess is not enforced

**Severity:** HIGH
**Vector:** Crypto Mining
**Collectors required:** `org_policy`
**CIS Reference:** [CIS GCP 4.9](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)

**What it detects:**
The org policy constraint `constraints/compute.vmExternalIpAccess` is either absent or present but not configured with a restrictive rule (no `denyAll` and no empty `allowList`). Without this constraint, any VM in any project can be assigned an external IP.

**Why it matters:**
Even if individual VMs are remediated (CM-001), without an org-level policy enforcement, new VMs can be created with external IPs at any time. This constraint is the preventive control that stops the misconfiguration at the source.

**Remediation:**
1. Identify all VMs that currently have external IPs.
2. Migrate outbound connectivity to Cloud NAT.
3. Apply the org policy to deny external IPs organization-wide.

```bash
gcloud resource-manager org-policies deny \
  constraints/compute.vmExternalIpAccess --organization=ORG_ID
```

**References:**
- [Org Policy constraints](https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints)

---

### CM-003 — Firewall allows unrestricted egress to the internet (0.0.0.0/0)

**Severity:** HIGH
**Vector:** Crypto Mining
**Collectors required:** `network`
**CIS Reference:** [CIS GCP 3.8](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)

**What it detects:**
Active EGRESS firewall rules (priority < 65534) that allow traffic to `0.0.0.0/0` or `::/0`, permitting VMs to freely initiate outbound connections to any destination on the internet.

**Why it matters:**
Compromised or malicious VMs can establish outbound connections to crypto mining pools, exfiltrate data, or receive commands from attacker-controlled C2 infrastructure without restriction. Unrestricted egress is a key enabler of crypto mining attacks.

**Remediation:**
1. Audit legitimate outbound traffic requirements for the network.
2. Create a deny-all egress rule at low priority (e.g., priority 65000).
3. Create specific allow rules for required destinations (e.g., Google APIs, known SaaS).
4. Use Cloud NAT with logging enabled for outbound internet access.
5. Delete or restrict the permissive egress rule.

```bash
# Restrict an existing rule to specific destinations:
gcloud compute firewall-rules update RULE_NAME \
  --destination-ranges=SPECIFIC_CIDR_RANGE

# Or create a deny-all egress rule:
gcloud compute firewall-rules create deny-all-egress \
  --network=NETWORK_NAME --direction=EGRESS --action=DENY \
  --rules=all --destination-ranges=0.0.0.0/0 --priority=65000
```

**References:**
- [VPC firewall rules](https://cloud.google.com/vpc/docs/firewalls)
- [Cloud NAT overview](https://cloud.google.com/nat/docs/overview)

---

### CM-004 — Firewall rule allows admin port access from the internet (0.0.0.0/0)

**Severity:** CRITICAL
**Vector:** Crypto Mining
**Collectors required:** `network`
**CIS Reference:** [CIS GCP 3.6](https://www.cisecurity.org/benchmark/google_cloud_computing_platform), [CIS GCP 3.7](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)

**What it detects:**
Active INGRESS firewall rules that allow traffic from `0.0.0.0/0` or `::/0` on administrative ports: SSH (22), RDP (3389), WinRM (5985, 5986).

**Why it matters:**
Direct internet access to SSH/RDP allows attackers to perform brute-force or credential-stuffing attacks against VMs. A successful compromise gives the attacker full shell access to install and run crypto mining software. This is one of the most common initial access vectors for crypto mining attacks on GCP.

**Remediation:**
1. Identify who legitimately needs SSH/RDP access.
2. Replace `0.0.0.0/0` source range with specific trusted IP ranges.
3. Alternatively, enable IAP for TCP forwarding and remove direct SSH/RDP rules.
4. Consider using OS Login for centralized SSH key management.

```bash
# Restrict to trusted IP range:
gcloud compute firewall-rules update RULE_NAME \
  --source-ranges=TRUSTED_IP_RANGE

# Or delete and use IAP:
gcloud compute firewall-rules delete RULE_NAME
```

**References:**
- [IAP for TCP forwarding](https://cloud.google.com/iap/docs/using-tcp-forwarding)
- [OS Login](https://cloud.google.com/compute/docs/oslogin)

---

### CM-005 — VM instances with GPU accelerators detected without org-level restriction

**Severity:** MEDIUM
**Vector:** Crypto Mining
**Collectors required:** `compute`
**CIS Reference:** —

**What it detects:**
VM instances that have one or more GPU accelerators attached (`acceleratorCount > 0`), indicating high-value compute resources that are prime targets for crypto mining abuse.

**Why it matters:**
GPU-equipped VMs can mine cryptocurrency at significantly higher rates than CPU-only instances, leading to massive unexpected billing charges. Without org-level restrictions on GPU machine types or quotas, attackers who gain access can exploit these resources for mining at scale.

**Remediation:**
1. Verify that the GPU instance has a legitimate business purpose.
2. Review the instance's workload and owner.
3. Apply org policy constraints or quota limits to restrict GPU availability.
4. Enable billing alerts and anomaly detection for GPU usage.
5. Use labels and resource hierarchy to track GPU instances.

```bash
# List all GPU instances:
gcloud compute instances list \
  --filter='accelerators:*' \
  --format='table(name,zone,accelerators)'

# Set GPU quota to 0 in a region:
# Use Cloud Console: IAM & Admin > Quotas > filter by GPU
```

**References:**
- [Compute Engine GPUs](https://cloud.google.com/compute/docs/gpus)
- [Org Policy overview](https://cloud.google.com/resource-manager/docs/organization-policy/overview)

---

### CM-006 — VM instance or project has insecure metadata (serial port enabled or OS Login disabled)

**Severity:** MEDIUM
**Vector:** Crypto Mining
**Collectors required:** `compute`
**CIS Reference:** [CIS GCP 4.4](https://www.cisecurity.org/benchmark/google_cloud_computing_platform), [CIS GCP 4.5](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)

**What it detects:**
VM instances where the instance metadata contains `serial-port-enable=true` (or `1`) or `enable-oslogin=false`. These settings weaken the security posture of the instance.

**Why it matters:**
Serial port access provides an out-of-band channel that can be exploited by attackers to interact with a compromised VM without going through normal network channels, aiding persistence of crypto mining software. Disabling OS Login weakens centralized SSH key management, making it harder to revoke access when a compromise is detected.

**Remediation:**
1. Disable serial port: set metadata `serial-port-enable` to `false`.
2. Enable OS Login: set metadata `enable-oslogin` to `true`.
3. Enforce via Org Policy: `constraints/compute.disableSerialPortAccess`.
4. Enforce OS Login via Org Policy: `constraints/compute.requireOsLogin`.

```bash
gcloud compute instances add-metadata INSTANCE_NAME \
  --zone=ZONE --metadata=serial-port-enable=false

gcloud compute instances add-metadata INSTANCE_NAME \
  --zone=ZONE --metadata=enable-oslogin=true

# Enforce org-wide:
gcloud resource-manager org-policies enable-enforce \
  constraints/compute.disableSerialPortAccess --organization=ORG_ID
```

**References:**
- [Serial console](https://cloud.google.com/compute/docs/instances/interacting-with-serial-console)
- [OS Login](https://cloud.google.com/compute/docs/oslogin)

---

### CM-007 — VM startup script downloads or executes content from external URLs

**Severity:** MEDIUM
**Vector:** Crypto Mining
**Collectors required:** `compute`
**CIS Reference:** —

**What it detects:**
VM instances whose `startup-script` metadata contains patterns associated with downloading or executing external content: `curl`, `wget`, `pip install`, `apt-get install`, `yum install`, `bash <(`, `sh <(`, `python -c`, `exec(`.

**Why it matters:**
Startup scripts that fetch and execute external content can be used to deploy crypto mining software, backdoors, or other malware on every VM boot — including after restarts. This is a common supply-chain attack vector where a compromised external URL delivers a miner payload.

**Remediation:**
1. Review the startup script for legitimate vs. suspicious downloads.
2. Move any required scripts or binaries to a private GCS bucket.
3. Reference the GCS path using the `startup-script-url` metadata key.
4. Consider using Container-Optimized OS or hardened images.
5. Enable VM startup script logging and alerting.

```bash
# Upload script to GCS:
gsutil cp startup.sh gs://YOUR_BUCKET/startup.sh

gcloud compute instances add-metadata INSTANCE_NAME \
  --zone=ZONE \
  --metadata=startup-script-url=gs://YOUR_BUCKET/startup.sh

# Remove inline startup script:
gcloud compute instances remove-metadata INSTANCE_NAME \
  --zone=ZONE --keys=startup-script
```

**References:**
- [Startup scripts for Linux](https://cloud.google.com/compute/docs/instances/startup-scripts/linux)
- [Container-Optimized OS](https://cloud.google.com/container-optimized-os/docs/concepts/features-and-benefits)

---

### CM-008 — Firewall rule allows database port access from the internet (0.0.0.0/0)

**Severity:** CRITICAL
**Vector:** Crypto Mining
**Collectors required:** `network`
**CIS Reference:** [CIS GCP 3.6](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)

**What it detects:**
Active INGRESS firewall rules that allow traffic from `0.0.0.0/0` or `::/0` on database ports: MySQL/MariaDB (3306) and PostgreSQL (5432). A rule that allows all TCP ports (or `IPProtocol: all`) matches as well, because it exposes those ports too.

**Why it matters:**
Internet-facing databases are scanned and brute-forced continuously. A compromised database either yields credentials that lead to the surrounding GCP project (where they can be used to provision mining VMs), or the database itself runs on a VM that can be taken over for mining. It is the same class of exposure as CM-004, on the data tier instead of the admin tier.

**Notes:**
Some managed database engines legitimately need public connectivity. In that case restrict the source range instead of suppressing the check — suppression hides the exposure from every future scan.

**Remediation:**
1. Identify the legitimate clients that need database access.
2. Replace the `0.0.0.0/0` source range with specific IP ranges or a VPC CIDR.
3. For Cloud SQL, disable the public IP and use Private IP or the Cloud SQL Auth Proxy.
4. Consider VPC Service Controls and private services access.

```bash
# Restrict to trusted IP range:
gcloud compute firewall-rules update RULE_NAME \
  --source-ranges=TRUSTED_IP_RANGE

# Cloud SQL: disable public IP
gcloud sql instances patch INSTANCE_NAME --no-assign-ip
```

**References:**
- [Cloud SQL private IP](https://cloud.google.com/sql/docs/mysql/configure-private-ip)
- [Cloud SQL Auth Proxy](https://cloud.google.com/sql/docs/postgres/connect-auth-proxy)

---

### CM-009 — VM instance does not have Shielded VM enabled

**Severity:** MEDIUM
**Vector:** Crypto Mining
**Collectors required:** `compute`
**CIS Reference:** [CIS GCP 4.8](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)

**What it detects:**
VM instances where one or more Shielded VM features are disabled: Secure Boot (`enableSecureBoot`), vTPM (`enableVtpm`), or Integrity Monitoring (`enableIntegrityMonitoring`).

**Why it matters:**
Without Shielded VM features, rootkits or bootkit-based crypto miners can persist across reboots, surviving OS reinstalls and evading detection. Secure Boot prevents unsigned code from running at boot time, vTPM provides hardware-based attestation, and Integrity Monitoring detects changes to the boot sequence.

**Remediation:**
1. Stop the instance.
2. Enable Shielded VM features (requires a compatible image).
3. Restart the instance.
4. Enforce via Org Policy: `constraints/compute.requireShieldedVm`.

```bash
gcloud compute instances stop INSTANCE_NAME --zone=ZONE

gcloud compute instances update INSTANCE_NAME --zone=ZONE \
  --shielded-secure-boot \
  --shielded-vtpm \
  --shielded-integrity-monitoring

gcloud compute instances start INSTANCE_NAME --zone=ZONE
```

**References:**
- [Shielded VM](https://cloud.google.com/compute/shielded-vm/docs/shielded-vm)

---

### CM-011 — Org Policy gcp.resourceLocations is not configured (no region restriction)

**Severity:** MEDIUM
**Vector:** Crypto Mining
**Collectors required:** `org_policy`
**CIS Reference:** —

**What it detects:**
The org policy constraint `constraints/gcp.resourceLocations` is either absent or present but does not have any `allowedValues` configured, meaning resources can be created in any GCP region.

**Why it matters:**
Without region restrictions, attackers can spin up crypto mining VMs in unexpected or distant regions to evade detection and monitoring. Resources created in non-approved regions may also violate data sovereignty requirements and bypass region-specific security controls.

**Remediation:**
1. Identify the list of approved GCP regions for your organization.
2. Create an org policy that allowlists only approved regions.
3. Apply the policy at the organization level.
4. Review existing resources in non-approved regions.

```bash
# Create a policy file (policy.yaml) with allowed locations, then:
gcloud resource-manager org-policies set-policy policy.yaml \
  --organization=ORG_ID

# Example policy.yaml content:
# constraint: constraints/gcp.resourceLocations
# listPolicy:
#   allowedValues:
#     - in:us-locations
#     - in:eu-locations
```

**References:**
- [Defining resource locations](https://cloud.google.com/resource-manager/docs/organization-policy/defining-locations)
- [Org Policy constraints](https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints)

---

### CM-020 — GKE node pool has autoscaling enabled without a maxNodeCount limit

**Severity:** HIGH
**Vector:** Crypto Mining
**Collectors required:** `gke`
**CIS Reference:** [CIS GKE 6.8.1](https://www.cisecurity.org/benchmark/google_kubernetes_engine)

**What it detects:**
GKE node pools where autoscaling is enabled but `maxNodeCount` is absent, zero, or set to an extremely high value (≥ 1000), effectively removing any upper bound on the number of nodes that can be provisioned.

**Why it matters:**
An unbounded node pool allows an attacker (or a compromised workload) to scale the cluster to thousands of nodes, running crypto mining at massive scale and generating enormous costs before the anomaly is detected. This is particularly dangerous for GPU node pools.

**Remediation:**
1. Determine the maximum number of nodes legitimately needed by the workloads.
2. Update the node pool autoscaling configuration with an appropriate `maxNodeCount`.
3. Set up billing alerts and quota limits as an additional safeguard.

```bash
gcloud container node-pools update POOL_NAME \
  --max-nodes=MAX_NODES \
  --cluster=CLUSTER_NAME \
  --zone=ZONE
```

**References:**
- [Cluster Autoscaler](https://cloud.google.com/kubernetes-engine/docs/concepts/cluster-autoscaler)
- [How to use Cluster Autoscaler](https://cloud.google.com/kubernetes-engine/docs/how-to/cluster-autoscaler)

---

### CM-021 — GKE cluster has Node Auto-Provisioning enabled without resource limits

**Severity:** HIGH
**Vector:** Crypto Mining
**Collectors required:** `gke`
**CIS Reference:** [CIS GKE 6.8.2](https://www.cisecurity.org/benchmark/google_kubernetes_engine)

**What it detects:**
GKE clusters (non-Autopilot) that have Node Auto-Provisioning (NAP) active — detected via autoprovisioned node pools — without cluster-level resource limits for CPU and memory.

**Why it matters:**
Without resource limits, NAP can provision an unlimited number of nodes in response to workload demand. A compromised workload or malicious deployment can trigger the creation of arbitrary numbers of nodes for crypto mining, leading to runaway billing.

**Remediation:**
1. Identify the maximum CPU and memory your cluster legitimately needs.
2. Update the cluster's NAP configuration with explicit resource limits.
3. Monitor cluster resource usage and billing to detect anomalies.

```bash
gcloud container clusters update CLUSTER_NAME \
  --enable-autoprovisioning \
  --max-cpu=MAX_CPU \
  --max-memory=MAX_MEMORY_GB \
  --zone=ZONE
```

**References:**
- [Node Auto-Provisioning](https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-provisioning)

---

### CM-023 — GKE cluster has a public control plane endpoint without authorized networks configured

**Severity:** HIGH
**Vector:** Crypto Mining
**Collectors required:** `gke`
**CIS Reference:** [CIS GKE 6.6.2](https://www.cisecurity.org/benchmark/google_kubernetes_engine), [CIS GKE 6.6.3](https://www.cisecurity.org/benchmark/google_kubernetes_engine)

**What it detects:**
GKE clusters that do not use private nodes and have not enabled Master Authorized Networks, meaning the Kubernetes API server is reachable from any IP address on the internet.

**Why it matters:**
An unrestricted public API server allows attackers to attempt authentication attacks (brute-force, credential stuffing, token theft). A successful compromise grants full cluster control, enabling deployment of crypto mining pods across all nodes.

**Remediation:**
1. Identify all IP ranges that legitimately need access to the Kubernetes API server.
2. Enable Master Authorized Networks with those specific CIDR ranges.
3. Alternatively, enable private nodes and use a private endpoint.
4. Audit existing cluster credentials and rotate if exposure is suspected.

```bash
# Enable authorized networks:
gcloud container clusters update CLUSTER_NAME \
  --enable-master-authorized-networks \
  --master-authorized-networks=CIDR1,CIDR2 \
  --zone=ZONE

# Or enable private cluster (requires recreation):
gcloud container clusters create CLUSTER_NAME \
  --enable-private-nodes \
  --master-ipv4-cidr=172.16.0.0/28 \
  --zone=ZONE
```

**References:**
- [Authorized networks](https://cloud.google.com/kubernetes-engine/docs/how-to/authorized-networks)
- [Private clusters](https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters)

---

### CM-024 — GKE cluster does not have Workload Identity enabled

**Severity:** MEDIUM
**Vector:** Crypto Mining
**Collectors required:** `gke`
**CIS Reference:** [CIS GKE 6.2.2](https://www.cisecurity.org/benchmark/google_kubernetes_engine)

**What it detects:**
GKE clusters where `workloadIdentityConfig.workloadPool` is not set, meaning pods cannot use fine-grained, per-workload GCP identities and must rely on the node's Compute Engine service account.

**Why it matters:**
Without Workload Identity, pods inherit the node service account's permissions. If that SA is over-privileged (e.g., has Editor role), a single compromised container can create additional compute resources for crypto mining or exfiltrate sensitive data.

**Remediation:**
1. Enable Workload Identity on the cluster.
2. Annotate Kubernetes service accounts with the corresponding GCP service account.
3. Grant only the minimum required IAM roles to each GCP SA.
4. Remove broad IAM roles from the node service account.

```bash
gcloud container clusters update CLUSTER_NAME \
  --workload-pool=PROJECT_ID.svc.id.goog \
  --zone=ZONE

# Annotate a Kubernetes SA:
kubectl annotate serviceaccount KSA_NAME \
  --namespace=NAMESPACE \
  iam.gke.io/gcp-service-account=GSA_NAME@PROJECT_ID.iam.gserviceaccount.com
```

**References:**
- [Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)

---

### CM-025 — GKE cluster has Legacy ABAC (Attribute-Based Access Control) enabled

**Severity:** MEDIUM
**Vector:** Crypto Mining
**Collectors required:** `gke`
**CIS Reference:** [CIS GKE 6.8.4](https://www.cisecurity.org/benchmark/google_kubernetes_engine)

**What it detects:**
GKE clusters where `legacyAbac.enabled` is `true`, bypassing Kubernetes RBAC and granting all service accounts in the cluster broad permissions.

**Why it matters:**
Legacy ABAC grants all authenticated users and service accounts broad Kubernetes permissions, effectively bypassing RBAC. An attacker who gains access to any pod can exploit these permissions to deploy crypto mining workloads across the entire cluster.

**Remediation:**
1. Audit existing RBAC roles and bindings to ensure they cover all legitimate access requirements before disabling ABAC.
2. Disable Legacy ABAC on the cluster.
3. Verify that workloads continue to function correctly after the change.

```bash
gcloud container clusters update CLUSTER_NAME \
  --no-enable-legacy-authorization \
  --zone=ZONE
```

**References:**
- [Hardening your cluster — disable ABAC](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#leave_abac_disabled_default_for_110)

---

### CM-026 — GKE node pool uses the default Compute Engine service account

**Severity:** HIGH
**Vector:** Crypto Mining
**Collectors required:** `gke`
**CIS Reference:** [CIS GKE 6.2.1](https://www.cisecurity.org/benchmark/google_kubernetes_engine)

**What it detects:**
GKE node pools whose `config.serviceAccount` ends with `@developer.gserviceaccount.com`, indicating use of the default Compute Engine service account which has the Editor role on the project.

**Why it matters:**
The default Compute Engine SA has the Editor role on the project, granting every pod running on these nodes broad GCP permissions. A compromised pod can use these credentials to create VMs, access storage, or perform other actions that enable crypto mining at scale.

**Remediation:**
1. Create a new GCP service account dedicated to this node pool.
2. Grant only the minimum IAM roles required by GKE nodes (e.g., `roles/logging.logWriter`, `roles/monitoring.metricWriter`, `roles/monitoring.viewer`).
3. Recreate the node pool specifying the new service account.
4. Enable Workload Identity (CM-024) to further restrict per-pod GCP access.

```bash
# Create a dedicated SA:
gcloud iam service-accounts create gke-node-sa \
  --display-name='GKE Node Pool SA' \
  --project=PROJECT_ID

# Grant minimum roles:
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member=serviceAccount:gke-node-sa@PROJECT_ID.iam.gserviceaccount.com \
  --role=roles/logging.logWriter

# Recreate node pool with the new SA:
gcloud container node-pools create POOL_NAME \
  --cluster=CLUSTER_NAME \
  --service-account=gke-node-sa@PROJECT_ID.iam.gserviceaccount.com \
  --zone=ZONE
```

**References:**
- [Hardening your cluster — use least privilege SA](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#use_least_privilege_sa)

---

### CM-030 — Cloud Run service allows public invocation (allUsers invoker)

**Severity:** HIGH
**Vector:** Crypto Mining
**Collectors required:** `cloud_run`
**CIS Reference:** [CIS GCP 2.13](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)

**What it detects:**
Cloud Run services where `roles/run.invoker` is granted to `allUsers` in the IAM policy, allowing any unauthenticated internet user to invoke the service.

**Why it matters:**
Unrestricted public invocation allows attackers to trigger arbitrary executions of the service, driving up compute costs and potentially enabling crypto mining via the service's runtime. The attacker pays nothing while the project owner bears all costs.

**Remediation:**
1. Identify the legitimate callers of this Cloud Run service.
2. Remove `allUsers` from the `roles/run.invoker` IAM binding.
3. Grant `roles/run.invoker` only to specific service accounts or user groups.
4. If public access is required, front the service with Cloud Endpoints or API Gateway with authentication enforced.
5. Consider enabling IAP for browser-based access.

```bash
gcloud run services remove-iam-policy-binding SERVICE_NAME \
  --region=REGION \
  --member=allUsers \
  --role=roles/run.invoker
```

**References:**
- [Managing access to Cloud Run](https://cloud.google.com/run/docs/securing/managing-access)
- [Authenticating to Cloud Run](https://cloud.google.com/run/docs/authenticating/overview)

---

### CM-031 — Cloud Run service has no maxScale limit configured (unbounded scaling)

**Severity:** MEDIUM
**Vector:** Crypto Mining
**Collectors required:** `cloud_run`
**CIS Reference:** —

**What it detects:**
Cloud Run services where `maxInstanceCount` is absent, null, or zero in both the top-level scaling configuration and the template scaling configuration, allowing the service to scale to an unlimited number of instances.

**Why it matters:**
Without an upper bound, a burst of requests — whether legitimate or adversarially triggered — can scale the service to thousands of instances, generating unbounded compute costs that mirror the financial impact of a crypto mining attack. Combined with a public endpoint (CM-030), this creates a severe cost exposure.

**Remediation:**
1. Determine the maximum expected concurrency for this service.
2. Set `maxInstanceCount` to a value that covers peak load with headroom.
3. Combine with budget alerts (see CM-060) to detect anomalous spend.
4. Review Cloud Run metrics to right-size the limit over time.

```bash
gcloud run services update SERVICE_NAME \
  --region=REGION \
  --max-instances=N
```

**References:**
- [Configuring max instances](https://cloud.google.com/run/docs/configuring/max-instances)
- [Cloud Run tips](https://cloud.google.com/run/docs/tips/general#setting-concurrency)

---

### CM-040 — Service account or principal has broad compute creation roles (compute.admin, container.admin)

**Severity:** HIGH
**Vector:** Crypto Mining
**Collectors required:** `iam`
**CIS Reference:** [CIS GCP 1.5](https://www.cisecurity.org/benchmark/google_cloud_computing_platform), [CIS GCP 7.1](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)

**What it detects:**
IAM bindings where roles such as `roles/compute.admin`, `roles/compute.instanceAdmin`, `roles/compute.instanceAdmin.v1`, `roles/container.admin`, or `roles/container.clusterAdmin` are granted to broad principals (allUsers, allAuthenticatedUsers, domain:, or groups with more than 3 members).

**Why it matters:**
Broad compute creation roles allow any holder to provision high-CPU/GPU instances for crypto mining, leading to runaway billing and potential data exfiltration. These roles should be tightly scoped to specific, named service accounts with documented justification.

**Remediation:**
1. Audit who legitimately needs this role and why.
2. Remove the binding for any principal that does not require it.
3. Replace `compute.admin` with narrower roles such as `compute.instanceAdmin.v1` scoped to specific resources.
4. For `domain:` or `allUsers` members, remove immediately and investigate for potential compromise.
5. Enable Org Policy: `constraints/iam.allowedPolicyMemberDomains`.

```bash
gcloud projects get-iam-policy PROJECT_ID \
  --format=json > policy.json
# Edit policy.json to remove the offending binding, then:
gcloud projects set-iam-policy PROJECT_ID policy.json
```

**References:**
- [Compute IAM roles](https://cloud.google.com/iam/docs/understanding-roles#compute-roles)
- [IAM Recommender](https://cloud.google.com/iam/docs/recommender-overview)

---

### CM-041 — Service account has user-managed (exported) keys

**Severity:** HIGH
**Vector:** Crypto Mining
**Collectors required:** `iam`
**CIS Reference:** [CIS GCP 1.4](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)

**What it detects:**
Service accounts that have one or more keys of type `USER_MANAGED` — long-lived credentials that have been exported and can be used from outside GCP.

**Why it matters:**
User-managed SA keys, if leaked (e.g., in source code, CI logs, container images), can be used to authenticate as the SA from anywhere and create compute resources for crypto mining. Unlike short-lived tokens, these keys remain valid until explicitly deleted.

**Remediation:**
1. Identify all consumers of this SA key.
2. Migrate consumers to Workload Identity Federation or Application Default Credentials.
3. Delete the user-managed key(s).
4. Enforce via Org Policy: `constraints/iam.disableServiceAccountKeyCreation`.

```bash
gcloud iam service-accounts keys delete KEY_ID \
  --iam-account=SA_EMAIL
```

**References:**
- [Best practices for managing SA keys](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys)
- [Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)

---

### CM-042 — iam.serviceAccountTokenCreator or serviceAccountUser granted broadly

**Severity:** HIGH
**Vector:** Crypto Mining
**Collectors required:** `iam`
**CIS Reference:** [CIS GCP 1.6](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)

**What it detects:**
IAM bindings where `roles/iam.serviceAccountTokenCreator` or `roles/iam.serviceAccountUser` is granted to broad principals: `allUsers`, `allAuthenticatedUsers`, `domain:*`, or `group:*`.

**Why it matters:**
These roles allow the holder to impersonate service accounts, including those with compute creation permissions. An attacker who can impersonate a powerful SA can create VMs, GKE clusters, or Cloud Run services for crypto mining, with actions attributed to the impersonated SA.

**Remediation:**
1. Identify which service accounts are targeted by this binding.
2. Remove allUsers, allAuthenticatedUsers, domain:, and group: members.
3. Grant `roles/iam.serviceAccountUser` only to specific, named service accounts or users with documented justification.
4. Audit the permissions of the impersonated SA — if it has compute creation roles, treat this as CRITICAL.
5. Enable VPC Service Controls to limit SA token usage.

```bash
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member=BROAD_MEMBER --role=roles/iam.serviceAccountTokenCreator
```

**References:**
- [Impersonating service accounts](https://cloud.google.com/iam/docs/impersonating-service-accounts)
- [Best practices for service accounts](https://cloud.google.com/iam/docs/best-practices-service-accounts)

---

### CM-043 — IAM binding grants access to allUsers or allAuthenticatedUsers

**Severity:** CRITICAL
**Vector:** Crypto Mining
**Collectors required:** `iam`
**CIS Reference:** [CIS GCP 1.18](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)

**What it detects:**
IAM bindings on project resources where `allUsers` or `allAuthenticatedUsers` is a member, granting access to any internet user or any Google-authenticated user respectively.

**Why it matters:**
Any attacker can use this binding to create compute resources for crypto mining, billed to the project owner. This is the highest-severity IAM misconfiguration — it requires no credential theft, just knowledge of the project ID.

**Remediation:**
1. Identify the legitimate principals that need this role.
2. Remove allUsers/allAuthenticatedUsers from the binding.
3. Grant the role only to specific, authenticated identities.
4. Enable Org Policy: `constraints/iam.allowedPolicyMemberDomains`.

```bash
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member=allUsers --role=ROLE

gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member=allAuthenticatedUsers --role=ROLE
```

**References:**
- [IAM access control concepts](https://cloud.google.com/iam/docs/overview#concepts_related_to_access_control)

---

### CM-044 — Default Compute Engine service account has Editor or Owner role

**Severity:** HIGH
**Vector:** Crypto Mining
**Collectors required:** `iam`
**CIS Reference:** [CIS GCP 4.1](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)

**What it detects:**
IAM bindings where the default Compute Engine service account (email ending in `-compute@developer.gserviceaccount.com`) has `roles/editor` or `roles/owner`.

**Why it matters:**
Any VM using this SA can create new compute resources, enabling crypto mining at scale. A compromised VM can use the default SA to spin up additional instances for mining, escalating costs rapidly. This is a default GCP configuration that should be remediated in all production environments.

**Remediation:**
1. Create a dedicated service account for each workload.
2. Grant only the permissions required by that workload.
3. Remove the default Compute SA from Editor/Owner bindings.
4. Update VMs to use the dedicated SA.

```bash
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member=serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com \
  --role=roles/editor
```

**References:**
- [Default service account](https://cloud.google.com/compute/docs/access/service-accounts#default_service_account)

---

### CM-045 — IAM Recommender identifies service account with unused compute permissions

**Severity:** MEDIUM
**Vector:** Crypto Mining
**Collectors required:** `recommender`
**CIS Reference:** —

**What it detects:**
IAM Recommender insights of subtype `REMOVE_ROLE` or `REPLACE_ROLE` that reference compute-related roles (containing `compute.`, `container.`, or `run.` in the description or content).

**Why it matters:**
Over-permissioned service accounts with unused compute roles represent a standing risk. If compromised, they can be used to provision resources for crypto mining without triggering immediate alerts. IAM Recommender identifies these excess permissions based on actual usage data.

**Remediation:**
1. Review the full recommendation in the GCP Console under IAM & Admin > Recommender.
2. Validate that removing the role will not break any workload.
3. Apply the recommendation (remove or replace the role).
4. Set up periodic IAM Recommender reviews (e.g., monthly).

```bash
# List active IAM recommendations for a project:
gcloud recommender recommendations list \
  --project=PROJECT_ID \
  --recommender=google.iam.policy.Recommender \
  --location=global
```

**References:**
- [IAM Recommender overview](https://cloud.google.com/iam/docs/recommender-overview)
- [Managing IAM recommendations](https://cloud.google.com/iam/docs/recommender-managing)

---

### CM-046 — Personal (consumer email) account holds Owner or Editor

**Severity:** CRITICAL
**Vector:** Crypto Mining
**Collectors required:** `iam`
**CIS Reference:** [CIS GCP 1.1](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)

**What it detects:**
IAM bindings where a `user:` member with a well-known consumer email domain (gmail.com, googlemail.com, yahoo.com, hotmail.com, outlook.com, live.com, msn.com, icloud.com, aol.com, protonmail.com, proton.me, gmx.com, mail.com, yandex.com, zoho.com) holds `roles/owner` or `roles/editor` on the project or on a resource inside it. One finding is emitted per personal member per binding.

**Why it matters:**
A personal account is outside the organization's identity lifecycle: 2SV cannot be enforced on it, it is not disabled when the person leaves, and its credential hygiene (password reuse, recovery email, personal device) is unknown. Whoever holds it is a full project administrator of a project that is about to be transferred — exactly the profile an SOP review must catch before handover, because the personal account keeps Owner access after the transfer regardless of what the new IAM design says.

**Scope / limitations:**
- Only consumer domains are matched, from a fixed list. It is intentionally narrow to avoid false positives on corporate domains.
- **External corporate accounts** (e.g. `user:alice@vendor.com` with Owner) are **not** detected: identifying them requires the organization's Cloud Identity directory or the enforced `constraints/iam.allowedPolicyMemberDomains` policy, which the scanner does not read. Treat that as a manual question in the review, or export the IAM policy and cross-check domains against the org's verified domains.

**Remediation:**
1. Confirm who owns the personal account and why it has this role.
2. Create (or identify) the equivalent identity in Cloud Identity / Workspace.
3. Grant the role to that managed identity and validate access.
4. Remove the personal account from the binding.
5. Enforce `constraints/iam.allowedPolicyMemberDomains` so personal accounts cannot be re-granted.
6. Audit Cloud Audit Logs for actions performed by the personal account.

```bash
# Grant to the managed identity first, then remove the personal account:
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member='user:managed@your-domain.com' --role='roles/owner'

gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member='user:someone@gmail.com' --role='roles/owner'
```

**References:**
- [Restricting domains with org policy](https://cloud.google.com/resource-manager/docs/organization-policy/restricting-domains)
- [Cloud Identity overview](https://cloud.google.com/identity/docs/overview)

---

### CM-050 — VPC has no egress deny-all firewall rule (unrestricted outbound traffic)

**Severity:** HIGH
**Vector:** Crypto Mining
**Collectors required:** `network`
**CIS Reference:** [CIS GCP 3.10](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)

**What it detects:**
Projects that have no active EGRESS firewall rule that denies all traffic to `0.0.0.0/0` with a priority ≥ 65000, meaning there is no catch-all egress deny rule to block outbound connections.

**Why it matters:**
Without a deny-all egress baseline, any VM in the project can freely initiate outbound connections to crypto mining pools, C2 servers, or data exfiltration endpoints on the internet. This is the network-level complement to CM-003 (permissive egress rules).

**Remediation:**
1. Inventory all legitimate outbound destinations for workloads in this project.
2. Create explicit ALLOW egress rules for those destinations with a priority lower than 65000 (e.g., 1000).
3. Create a catch-all DENY egress rule targeting `0.0.0.0/0` with priority 65534.
4. Monitor VPC Flow Logs for unexpected egress traffic.
5. Consider Cloud Armor or Cloud IDS for additional egress inspection.

```bash
gcloud compute firewall-rules create deny-all-egress \
  --project=PROJECT_ID \
  --direction=EGRESS \
  --action=DENY \
  --rules=all \
  --destination-ranges=0.0.0.0/0 \
  --priority=65534 \
  --network=default
```

**References:**
- [Egress firewall rules](https://cloud.google.com/vpc/docs/firewalls#egress_rules_applicable_to_traffic_leaving_the_network)
- [Using firewall rules](https://cloud.google.com/vpc/docs/using-firewalls)

---

### CM-060 — Project or billing account has no budget or budget alert configured

**Severity:** HIGH
**Vector:** Crypto Mining
**Collectors required:** `billing`
**CIS Reference:** —

**What it detects:**
Billing accounts with no budgets configured at all, or projects whose billing accounts have no associated budgets. Without budget alerts, crypto mining attacks can go completely undetected until the monthly invoice arrives.

**Why it matters:**
Crypto mining attacks can generate thousands of dollars in compute costs within hours. Without budget alerts, there is no automated mechanism to detect or respond to cost anomalies. Budget alerts are the last line of defense when all other controls fail.

**Remediation:**
1. Go to Cloud Console → Billing → Budgets & alerts.
2. Create a budget for the billing account.
3. Set threshold alerts at 50%, 90%, and 100% of budget.
4. Configure email notifications and/or Pub/Sub for automation.
5. Consider separate budgets per project for granular visibility.

```bash
# Use Cloud Console or Terraform — gcloud CLI has limited budget support.
# Terraform: google_billing_budget resource.
```

**References:**
- [Cloud Billing budgets](https://cloud.google.com/billing/docs/how-to/budgets)
- [Terraform: google_billing_budget](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/billing_budget)
