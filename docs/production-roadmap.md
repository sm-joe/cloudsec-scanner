# Production roadmap acceptance tracker

Merged increments do not imply full milestone certification. Each remaining item must be covered before a stable release.

| Milestone | Implemented | Outstanding |
|---|---|---|
| M01 | Fail-closed parsing, comparison, scanner coverage | Further security review and runtime acceptance |
| M02 | Structured HCL, resolved lockfiles, SCA, CycloneDX inventory | Helm, plan evaluation, Checkov/Gitleaks adapters, remaining ecosystems, full SBOM acceptance |
| M03 | AWS EC2/EBS/SG/RDS/ECR/EKS initial inventory | S3/IAM/VPC/CloudTrail/KMS, Azure/GCP/Kubernetes, authorized live acceptance |
| M04 | API/storage/worker foundation in progress | PostgreSQL integration tests, migrations, retries/leases/DLQ, running cancellation, OIDC/RBAC, audit, remaining resources |
| M05 | Pending | Web UI and end-to-end tests |
| M06 | Pending | Compliance evidence, policies, exceptions |
| M07 | Pending | Production hardening and operational acceptance |
| M08 | Pending | Signed stable release, deployment and recovery acceptance |
