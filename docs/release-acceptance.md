# CLI release acceptance

The initial release is a standalone CLI for selected IaC, secrets and dependency checks. No server or UI is shipped. Live AWS inventory and external Trivy are optional.

Before a stable tag:

- All exact-head security regression, portability and release-candidate jobs succeed.
- Audit actual installed runtime dependencies and distinguish vulnerability database/network failure from clean results.
- Validate JSON/SARIF and CycloneDX against pinned schemas; check report privacy and incomplete scan behavior.
- Complete and document outstanding M02–M07 acceptance in production-roadmap.md, or explicitly scope unsupported capabilities out of the initial release.
- Review rule accuracy; document supported formats, unsupported expressions and provider scope. No claim of full CIS certification.
- Review licensing and copyright notices; include license in wheel and source distribution.
- Verify SHA-256 checksums, signed provenance, and installation from the distribution on all supported systems.
- Validate optional external tool adapters and container distribution if advertised.
- Publish only after acceptance; never publish from an unreviewed pull request.

The release-candidate workflow produces artifacts for inspection only. Package name availability and trusted publishing configuration are not yet verified.

Candidate integrity gate: `scripts/verify_release_artifacts.py` checks both archive licenses, SPDX metadata and the complete checksum manifest. Main-only attestation runs after successful packaging, never on a pull request. Verify the actual attestation before certifying signed provenance.

Schema/privacy increment: validate native JSON, SARIF and CycloneDX exports offline using vendored schema snapshots; introduce fingerprint version 2 and opt-in relative paths. Re-review older baselines and exceptions. Cloud identity pseudonymization and upstream schema licensing review remain pending.
