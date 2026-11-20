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

Final integrity increment: per-query OSV pagination with bounded continuation, severity-aware v2 exceptions including revoked baseline approvals, and opt-in AWS identifier pseudonymization. Pending CI. Remaining publication requirements include installed runtime dependency audit, upstream schema notices and final artifact distribution verification.

PR #14 merged after 265 tests and nine portability jobs; pagination, severity-bound exceptions and cloud pseudonyms verified in CI. Candidate audit now inspects exact installed core and AWS dependency versions, including bootstrap packages, using pip-audit strict mode. Network failures and vulnerabilities block release. Upstream schema terms and attribution recorded. Scope of first stable distribution: Python wheel and source archive on GitHub Releases; PyPI and container distribution are not certified or promised by this gate. Full CIS, arbitrary Terraform expression evaluation, Helm rendering and additional adapters are outside initial supported scope. Final publication must use the exact successful main candidate, not an unverified rebuild.
