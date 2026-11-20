# Security Policy

CloudSec Scanner is a standalone security CLI. We welcome responsible reports of vulnerabilities in the scanner, its distribution and its supported integrations.

## Supported Versions

| Version | Security maintenance |
| --- | --- |
| 0.1.0 (current stable) | Supported |
| Development snapshots | Not separately supported |
| Earlier or unpublished candidates | Not supported |

Use the current distribution from [GitHub Releases](https://github.com/sm-joe/cloudsec-scanner/releases/latest). The owner-authorized same-version refresh of v0.1.0 changes the artifact checksums; verify the current checksums and provenance before installing. Support does not imply a guaranteed response or remediation SLA.

## Reporting a Vulnerability

1. Open the repository's [Security Advisories page](https://github.com/sm-joe/cloudsec-scanner/security/advisories) and use **Report a vulnerability** if private vulnerability reporting is available.
2. If private reporting is unavailable, request a private contact channel via a [GitHub issue](https://github.com/sm-joe/cloudsec-scanner/issues). Do not include sensitive details in the public issue.
3. Allow the maintainers an opportunity to investigate and coordinate disclosure before publishing exploit details.

Include the affected version and commit, OS and Python version, scanner command and options, a minimal synthetic reproduction, expected and observed behavior, security impact, and relevant sanitized diagnostics. Never submit real credentials, private keys, customer data, unredacted scan history or sensitive Terraform plans.

## Scope

Reports are particularly useful for security gate bypasses, incorrect clean assessments, unsafe input parsing, credential or report disclosure, command injection in adapters, artifact tampering and dependency vulnerabilities. Detection gaps in supported rules are also welcome. Ordinary feature requests and non-security bugs may be filed as public issues with sanitized inputs.

CloudSec evaluates selected native predicates and supported formats. A complete scan is not full CIS certification. Unsupported or unresolved assessments may withhold coverage. See the [rule catalog](docs/rules.md) and [reporting guide](docs/reporting.md) for the supported scope.

## Secure Operation

- Install only trusted release artifacts; use SHA256SUMS and GitHub build provenance for verification.
- Keep reports, local SQLite history, lockfiles and Terraform plans in appropriately protected storage.
- Use `--no-history` and `--relative-paths` for shareable scans, then manually review remaining identifiers.
- OSV vulnerability enrichment transmits package names, versions and ecosystems to the OSV service; static IaC scanning does not require a cloud account.
- Use least-privilege, short-lived AWS credentials for optional live inventory. Follow the [AWS permission guide](docs/aws-inventory-permissions.md).
- Treat exit code 3 as incomplete, not clean; never use `--no-fail` as proof of compliance.
- Use reviewed, severity-bound and expiring finding exceptions rather than hiding unresolved risk.

## Security Fixes and Distribution

Security fixes are reviewed in pull requests. Required checks include regression tests, fail-closed scan gates, cross-platform wheel validation and installed-runtime dependency audits. Release artifacts include SHA-256 checksums, a runtime SBOM and signed build provenance. Verified fixes and their affected versions will be documented through release notes or security advisories as appropriate.

See [release acceptance](docs/release-acceptance.md) and [third-party notices](THIRD-PARTY-NOTICES.md) for supply-chain and licensing details.
