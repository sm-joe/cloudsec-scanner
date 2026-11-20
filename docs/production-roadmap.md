# CloudSec Scanner CLI production roadmap

CloudSec is a standalone IaC and supply-chain security CLI. No web dashboard, API backend, authentication service, database server or persistent workers. Optional local scan history and optional read-only cloud inventory remain CLI features.

| Milestone | Scope | Acceptance remaining |
|---|---|---|
| M01 | Scanner integrity | Regression and adversarial input review |
| M02 | Detection engine initial increment | Additional ecosystems, external adapters and full SBOM acceptance |
| M03 | Optional AWS inventory increment | Document verified scope; further providers secondary to CLI |
| M04 | Comprehensive IaC | Initial Terraform plan/CloudFormation/List increment merged; deeper Kubernetes/Helm, ARM, GCP, Docker and input bounds remain |
| M05 | Supply chain | OSV advisory details, CVSS and Composer/Gradle/Bundler increment; external tool adapters and full SBOM schema acceptance remain |
| M06 | CLI policy/reporting | Rule metadata/versioning, expiring exceptions, stable identity, SARIF validation, coverage |
| M07 | Hardening | Multi-platform CI, performance, dependency security, package and artifact integrity |
| M08 | Stable distribution | License, docs, wheel/container, signed release and fresh installation acceptance |

Partial increments do not certify a whole milestone. Merge only exact-head passing CI with retained security gates. Live cloud credentials are not required for ordinary offline IaC scans.
