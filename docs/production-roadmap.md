# Product Roadmap

CloudSec Scanner v0.1.0 is a standalone stable CLI with targeted IaC, secrets and dependency checks, JSON/SARIF reporting, optional Trivy/AWS integrations, local history, baseline policies and GitHub release distribution.

## Future Development

| Area | Opportunities |
| --- | --- |
| IaC accuracy | Expand structured provider predicates, resource applicability, unknown-value handling and safe/unsafe regression fixtures. |
| Kubernetes | Broader workload and RBAC coverage; rendered chart validation. |
| Supply chain | Additional resolved lockfile formats and build-graph fidelity. |
| Cloud inventory | More read-only provider and service coverage after verified integration tests. |
| Performance | Large-repository benchmarks and bounded resource consumption. |
| Distribution | Additional publishing channels only after integrity and installation acceptance. |
| User experience | Terminal reporting refinements and practical CI examples. |

The roadmap is not a commitment to dates, full CIS certification or comprehensive provider coverage. No dashboard, backend API, authentication service, database server or persistent worker is planned for the standalone CLI.

Release changes must preserve exact-head passing CI, fail-closed behavior, schema compatibility and signed artifact verification. See [release acceptance](release-acceptance.md) and [current release notes](releases/v0.1.0.md). Historical development milestones are available in Git history.
