# Cloud Security Scanner

A Python 3 CLI for early detection of cloud infrastructure and configuration security issues. The current MVP includes a modular provider-specific rule package for selected AWS CloudFormation, Azure ARM, GCP configuration, Terraform, Kubernetes, Dockerfile, and secret patterns, with normalized text/JSON/SARIF reporting and a GitHub Actions example.

> **Scope and accuracy:** A clean scan means only that the enabled rules did not detect a known pattern. It is not proof that a system is secure. The current native rules are intentionally a small first ruleset; do not treat this release as equivalent to Checkov, Trivy, Gitleaks, or a full CIS benchmark audit.

## Requirements and installation

- Python 3.11+
- PyYAML (installed automatically)

From the repository root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
pytest -q
cloudsec --version
```

Linux/macOS:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
pytest -q
cloudsec --version
```

## Usage

```bash
# Scan a project directory
cloudsec scan .

# Scan one Terraform file
cloudsec scan infrastructure/main.tf

# JSON report for automation
cloudsec scan . --format json --output reports/cloudsec.json

# SARIF report for GitHub code scanning
cloudsec scan . --format sarif --output reports/cloudsec.sarif

# Override the configured failure threshold
cloudsec scan . --severity CRITICAL

# Select scanners (repeat --scanner to enable multiple)
cloudsec scan . --scanner iac --scanner secrets

# Report findings without failing for findings
cloudsec scan . --no-fail

# Generate a starter configuration (does not overwrite existing files)
cloudsec config-init --output .cloudsec.yml
```

The command prints findings and returns:

| Exit code | Meaning |
|---:|---|
| `0` | Scan succeeded; no finding met the configured failure threshold, or `--no-fail` was used |
| `1` | One or more findings met the failure threshold |
| `2` | Invalid arguments, target, or configuration |
| `3` | A file scan failed; the scan is not considered clean |

## Configuration

Copy `examples/.cloudsec.yml` to `.cloudsec.yml` and customize it:

```yaml
exclude:
  - ".git/**"
  - ".venv/**"
  - "node_modules/**"
exclude_rules: []
severity_threshold: HIGH
fail_on_findings: true
max_file_bytes: 2097152
scanners: [iac, secrets]
```

`exclude` uses glob patterns relative to the scan root. `exclude_rules` lists rule IDs to suppress. Suppression should be reviewed and tracked like code; do not use exclusions to conceal accepted risk without documentation.

## Initial native rules

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
| `DOCKER-004` | No explicit `USER` instruction | Medium |
| `SEC-SECRET-001..004` | Selected AWS/GitHub credential and private-key patterns | High |

The original CloudFormation public-read starter rule is `AWS-CF-001`. Additional Stage 2 rules are listed below. Rule locations are best-effort in this MVP; line numbers are estimated from matching text, not a full source-span parser. Helm files are discovered and parsed as YAML where possible, but Helm template expressions are not rendered in this release.

### Stage 2 provider-specific rules

| Rule ID | Detection | Severity |
|---|---|---|
| `AWS-CF-002` | S3 bucket missing one or more explicit Block Public Access controls | High |
| `AWS-CF-003` | S3 bucket lacks explicit default encryption configuration | High |
| `AWS-CF-004` | RDS instance configured as publicly accessible | High |
| `AWS-CF-005` | RDS storage encryption explicitly disabled | High |
| `AWS-CF-006` | CloudFormation security group exposes SSH/RDP to all IPv4 addresses | High |
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

## GitHub Actions — Stage 8

`.github/workflows/cloudsec.yml` runs on pull requests, pushes to `main`/`master`, and manual dispatch. It installs the package with development dependencies, runs Ruff and the test suite, and generates JSON and SARIF reports.

For pull requests and commits with a usable parent revision, the workflow also:

1. Checks out the target/base revision into `baseline-repo`.
2. Scans that revision to create `reports/baseline.json`.
3. Scans the current revision to create `reports/current.json` and `reports/current.sarif`.
4. Runs `cloudsec compare` and applies `scripts/ci_gate.py` to the comparison report.
5. Fails the regression gate for new HIGH/CRITICAL findings or an existing finding whose severity escalates to HIGH/CRITICAL. Existing findings and severity downgrades do not fail this regression gate.
6. Uploads JSON/SARIF/comparison reports as a workflow artifact. SARIF is also submitted to GitHub Code Scanning when repository permissions and code-scanning availability permit it.

The baseline scan uses the scanner version from the current revision, so the comparison focuses on target findings rather than differences between scanner versions. A first commit without a parent cannot be compared; that run still tests and scans the current revision, but has no baseline regression gate. Scanner execution errors, failed tests/lint, baseline checkout/scan errors, comparison errors, and gate violations fail the workflow. SARIF publication itself is best-effort; the report artifact remains available if publishing is unavailable.

The workflow requires `contents: read`, `pull-requests: read`, and `security-events: write`. No cloud credentials are needed for local file scanning. After the first successful run, configure the repository's branch protection/ruleset to require the **Test and scan** status check; workflow files do not enable branch protection by themselves.

The regression threshold defaults to `HIGH`. To include MEDIUM findings, change the gate step to `python scripts/ci_gate.py reports/comparison.json --severity MEDIUM`.

### Reproduce the regression gate locally

```powershell
python -m pip install -e ".[dev]"
python -m pytest -q
ruff check src tests scripts
New-Item -ItemType Directory -Force reports | Out-Null
cloudsec scan . --format json --output reports/current.json --no-fail
cloudsec scan <baseline-directory> --format json --output reports/baseline.json --no-fail
cloudsec compare reports/baseline.json reports/current.json --format json --output reports/comparison.json
python scripts/ci_gate.py reports/comparison.json --severity HIGH
```

Replace `<baseline-directory>` with a checkout or working tree of the target/base revision. The CI helper consumes the JSON output of `cloudsec compare`; it does not accept SARIF as comparison input.

## Architecture

```text
src/cloudsec_scanner/
  cli.py          CLI, exit policy
  config.py       YAML config defaults and validation
  discovery.py    supported-file discovery, exclusions, size limits
  scanner.py      scan orchestration and initial native checks
  models.py       normalized finding and scan-result schema
  report.py       terminal, JSON, SARIF output
  rules/          provider-specific rule implementations
scripts/ci_gate.py comparison-based CI regression gate
    common.py     shared rule helpers and finding construction
    aws.py        AWS CloudFormation and IAM checks
    azure.py      Azure ARM checks
    gcp.py        GCP configuration checks
    kubernetes.py Kubernetes pod and RBAC checks
    terraform.py  additional Azure/GCP Terraform checks
```

### Finding schema

Each finding includes a stable rule ID, title, severity, message, path, best-effort line number, resource where available, category, provider, remediation, compliance mapping where available, and redacted evidence. JSON includes a summary and warnings/errors separately from findings.

## Implemented vs planned

**Implemented in this MVP:** Python package and CLI; file/directory discovery; Terraform pattern-based rules; YAML/JSON parsing; initial AWS CloudFormation, Azure ARM, GCP configuration, Kubernetes pod/RBAC, and Dockerfile rules; secret-pattern checks with redacted evidence; exclusions and max-file-size guard; text/JSON/SARIF output; severity threshold and exit codes; stable JSON report comparison; comparison-based CI gate for new findings and severity escalations; GitHub Actions test, scan, report artifact, and SARIF publication workflow.

**Not yet implemented:** comprehensive Azure/GCP rule coverage; full CIS benchmark coverage; robust HCL/Helm template parsing; complete CloudFormation resource/property coverage; broad secret entropy/context analysis; dependency manifest and lockfile SCA; OSV database update command; container image scanning; external scanner adapters; policy exceptions with expiry; loadable third-party rule packs; full SARIF schema validation and extensive integration/regression coverage.

## Development checks

```bash
python -m pytest -q
python -m compileall -q src
ruff check src tests scripts
```

## Adding rules

Add a stable rule ID, severity, clear risk statement, remediation, relevant provider/category, and a fixture that proves both the vulnerable case and an appropriate safe case. Add a regression test before changing an existing rule. Prefer structured parsers and resource-context-aware evaluation over broad text matching as coverage expands.

## Security notes

- Never test with real credentials. Use synthetic fixtures.
- Secret detection is heuristic; rotate a credential if a real secret may have been committed.
- Scan errors are returned separately and produce exit code `3`; they must not be interpreted as a successful clean scan.
- Native Terraform checks in this MVP use conservative text patterns, not a complete HCL parser. Validate important infrastructure with a mature IaC scanner before deployment.
