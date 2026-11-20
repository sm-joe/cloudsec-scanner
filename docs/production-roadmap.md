# CloudSec Scanner CLI production roadmap

CloudSec is a standalone IaC and supply-chain security CLI. No web dashboard, API backend, authentication service, database server or persistent workers. Optional local scan history and optional read-only cloud inventory remain CLI features.

| Milestone | Scope | Acceptance remaining |
|---|---|---|
| M01 | Scanner integrity | Regression and adversarial input review |
| M02 | Detection engine initial increment | Additional ecosystems, external adapters and full SBOM acceptance |
| M03 | Optional AWS inventory increment | Document verified scope; further providers secondary to CLI |
| M04 | Comprehensive IaC | Initial Terraform plan/CloudFormation/List increment merged; deeper Kubernetes/Helm, ARM, GCP, Docker and input bounds remain |
| M05 | Supply chain | OSV advisory details, CVSS and Composer/Gradle/Bundler increment merged; external tool adapters and full SBOM schema acceptance remain |
| M06 | CLI policy/reporting | Exact expiring exceptions and emitted fingerprints merged in initial increment; rule catalog/versioning, SARIF schema validation and complete coverage remain |
| M07 | Hardening | Merged input hardening, atomic reports, portability matrix and wheel acceptance; performance, dependency security, signed artifacts remain |
| M08 | Stable distribution | Release-candidate packaging/checksums/SBOM workflow and acceptance checklist in progress; license, signed provenance, remaining scanner and distribution acceptance before stable tag |

Partial increments do not certify a whole milestone. Merge only exact-head passing CI with retained security gates. Live cloud credentials are not required for ordinary offline IaC scans.

## Final acceptance hardening

P0 alias deduplication and external scanner integrity plus initial P1 image provenance are implemented in the release-hardening increment, pending CI. Remaining P0 coverage and licensing/artifact verification, P1 schema validation, AWS metrics, full native resource identity, report privacy and rule depth must be completed before stable release.

PR #10 merged: alias deduplication, bounded Trivy and image provenance. Next increment adds native resource assessment records, full identifiers, AWS asset metrics and added IaC predicates. Remaining coverage gaps include complete field/type validation and manifest formats. Fingerprint migration, privacy, schema validation, licensing and artifact attestation remain separate release gates.

PR #11 merged after all three workflows passed (240 tests). License and artifact checks are the next increment; signed candidate provenance is subject to main-branch execution and verification. Full schema validation, dependency audit, privacy, identity migration and remaining scanner acceptance are still open.

PRs #12 and #13 merged: licensing, candidate artifact checks, main provenance verified for #12, offline report schemas and fingerprint v2. Final integrity increment addresses remaining cloud privacy, pagination and exception escalation. Stable release remains gated on verification and documented support scope.
