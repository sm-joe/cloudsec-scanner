# Native rule catalog

| Rule ID | Detection | Severity |
|---|---|---|
| `AWS-TF-001` | Public S3 bucket ACL in Terraform | High |
| `AWS-TF-002` | Terraform security-group ingress from `0.0.0.0/0` | High |
| `AWS-TF-003` | Explicitly unencrypted EBS volume | High |
| `AWS-TF-004` | Explicitly unencrypted RDS storage | High |
| `AWS-TF-005` | S3 bucket `force_destroy = true` | Low |
| `IAM-TF-001` | Wildcard IAM actions and resources in Terraform | High |
| `K8S-SEC-001` | Privileged container | High |
| `K8S-SEC-002` | `hostNetwork: true` | Medium |
| `K8S-SEC-003` | `runAsUser: 0` | High |
| `K8S-SEC-004` | Automatic service-account token mount | Medium |
| `K8S-SEC-005` | Privilege escalation allowed | Medium |
| `K8S-SEC-006` | Writable container root filesystem | Low |
| `DOCKER-001` | Unpinned/`latest` base image | Medium |
| `DOCKER-002` | Remote URL used with Docker `ADD` | Medium |
| `DOCKER-003` | Potential literal secret in Dockerfile | High |
| `DOCKER-004` | Missing runtime user or explicit root user | Medium |
| `SEC-SECRET-001..004` | Selected AWS/GitHub credential and private-key patterns | High |

The legacy `AWS-CF-001` predicate matches an explicit PublicReadAccess: true property; it is not a general detector for S3 AccessControl: PublicRead. Additional Stage 2 rules are listed below. Rule locations are best-effort in this release; line numbers are estimated from matching text, not a full source-span parser. Helm files are discovered and parsed as YAML where possible, but Helm template expressions are not rendered in this release.

## Additional provider-specific rules

| Rule ID | Detection | Severity |
|---|---|---|
| `AWS-CF-002` | S3 bucket missing one or more explicit Block Public Access controls | High |
| `AWS-CF-003` | S3 bucket lacks explicit default encryption configuration | High |
| `AWS-CF-004` | RDS instance configured as publicly accessible | High |
| `AWS-CF-005` | RDS storage encryption explicitly disabled | High |
| `AWS-CF-006` | CloudFormation security group exposes SSH/RDP to all public addresses | High |
| `AWS-IAM-001` | IAM statement allows wildcard actions on wildcard resources | High |
| `AZ-STORAGE-001` | Azure Storage permits HTTP | High |
| `AZ-STORAGE-002` | Azure Storage allows public blob access | High |
| `AZ-STORAGE-003` | Azure Storage minimum TLS is weaker than TLS 1.2 | Medium |
| `AZ-SQL-001` | Azure SQL firewall rule spans the full IPv4 range | High |
| `AZ-TF-001` | Terraform Azure Storage HTTPS-only setting disabled | High |
| `AZ-TF-002` | Terraform Azure Storage allows public nested items | High |
| `GCP-FW-001` | GCP firewall configuration exposes SSH/RDP to all IPv4 addresses | High |
| `GCP-STORAGE-001` | GCP bucket public access prevention is inherited, not enforced | High |
| `GCP-STORAGE-002` | GCP bucket uniform-level access explicitly disabled | Medium |
| `GCP-TF-001` | Terraform GCP bucket IAM grants access to `allUsers` | High |
| `GCP-TF-002` | Terraform GCP firewall exposes SSH/RDP to all IPv4 addresses | High |
| `K8S-SEC-007` | Pod shares host PID namespace | High |
| `K8S-SEC-008` | Pod shares host IPC namespace | Medium |
| `K8S-SEC-009` | Kubernetes workload uses `hostPath` | High |
| `K8S-SEC-010` | Container adds all Linux capabilities | High |
| `K8S-RBAC-001` | Kubernetes Role/ClusterRole grants wildcard verbs or resources | High |

These are targeted starter checks, not exhaustive provider coverage or a certification of compliance. Some rules intentionally flag only explicit insecure values; absence of a property is not always proof of a secure or insecure effective configuration.


## Expanded Terraform predicates

| Rule ID | Detection | Severity |
| --- | --- | --- |
| AWS-TF-006 | Public RDS instance | High |
| AWS-TF-007 | Explicitly disabled S3 public access block flag | High |
| AWS-TF-008 | Mutable ECR tags | Medium |
| AWS-TF-009 | EKS API endpoint permits public addresses | High |
| AZ-TF-003 | Azure Storage weak minimum TLS | Medium |
| GCP-TF-003 | Bucket public access prevention inherited | High |
| GCP-TF-004 | Uniform bucket access disabled | Medium |
| GCP-TF-005 | Cloud SQL public network access | High |

## Optional scanner result identifiers

| Rule ID | Detection |
| --- | --- |
| SCA-OSV-001 | Resolved package matches OSV vulnerability advisory |
| AWS-LIVE-EBS-001 | Unencrypted EBS volume |
| AWS-LIVE-SG-001 | Public administrative ingress |
| AWS-LIVE-RDS-001 | Unencrypted RDS storage |
| AWS-LIVE-RDS-002 | Publicly accessible RDS instance |
| AWS-LIVE-ECR-001 | Mutable repository tags |
| AWS-LIVE-EKS-001 | Public API endpoint open to all addresses |

External Trivy result IDs incorporate upstream vulnerability or misconfiguration identifiers. Default severity may be overridden by configuration for scan/image commands. See the implementation in [rules](../src/cloudsec_scanner/rules) and [scanner.py](../src/cloudsec_scanner/scanner.py) for exact predicates.

[Back to README](../README.md)
