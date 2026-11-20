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

# Inspect local scan history
cloudsec history list --limit 20
cloudsec history show 1
cloudsec history trends --days 30

# Use an explicit SQLite database for repeatable automation
cloudsec scan . --history-db .cloudsec/history.db
cloudsec history list --database .cloudsec/history.db
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

## Stage 9 — Scan history and security trends

Every `cloudsec scan` and `cloudsec image` run is recorded locally in a SQLite database by default. The history stores scan metadata, severity counts, warnings/errors, the normalized findings from the report, and lifecycle changes compared with the most recent **complete** scan of the same target and scan type.

The default database is outside the repository:
- Windows: `%LOCALAPPDATA%\CloudSecScanner\history.db`
- macOS: `~/Library/Application Support/CloudSecScanner/history.db`
- Linux: `$XDG_STATE_HOME/cloudsec-scanner/history.db`, or `~/.local/state/cloudsec-scanner/history.db` when `XDG_STATE_HOME` is unset.

Set `CLOUDSEC_HISTORY_DB` to override the default for a shell/session, or use `--history-db` on `scan`/`image`. Use `--no-history` to run a scan without recording it. History database paths can also be passed to the history subcommands using `--database`.

```powershell
# Scan and record the run in the default database
cloudsec scan .

# Choose a repository-local or dedicated database explicitly
cloudsec scan . --history-db .cloudsec/history.db

# List the most recent runs; filter by exact target if needed
cloudsec history list --limit 20
cloudsec history list --target . --format json --database .cloudsec/history.db

# Inspect a run by the ID shown in history list
cloudsec history show 3

# Review scans from the last 30 days
cloudsec history trends --days 30
cloudsec history trends --days 90 --target . --format json

# Scan without storing the result
cloudsec scan . --no-history
```

History commands:
- `cloudsec history list` shows recent runs, severity counts, and lifecycle totals.
- `cloudsec history show RUN_ID` shows the stored scan metadata and findings.
- `cloudsec history trends --days N` returns time-ordered scan summaries for the selected time window. JSON output is suitable for downstream charts or reporting.
- `--target` filters by the exact target string used by the scan command; use the same target spelling consistently for useful lifecycle comparisons.
- An incomplete scan (one that reports scan errors) is retained for auditability but is not used as the baseline for the next lifecycle comparison, avoiding false “resolved” counts caused by an incomplete scan.
- Lifecycle identity reuses Stage 6's stable `finding_identity`; changes to severity, title, message, remediation, or resource are tracked as changed findings. Severity increases are counted separately.
- History is local to the machine/database and is not automatically uploaded to CI artifacts. In ephemeral CI runners, the database is ephemeral unless the workflow explicitly persists it.

The database contains scan findings and may contain file paths or redacted evidence from the report. Keep it in an appropriately protected location. The scanner's secret-detection evidence is redacted, but findings should still be treated as security-sensitive metadata.

## Architecture

```text
src/cloudsec_scanner/
  cli.py          CLI, exit policy
  config.py       YAML config defaults and validation
  discovery.py    supported-file discovery, exclusions, size limits
  scanner.py      scan orchestration and initial native checks
  models.py       normalized finding and scan-result schema
  report.py       terminal, JSON, SARIF output
  history.py      SQLite scan history, lifecycle summaries, trend queries
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

**Implemented in this MVP:** Python package and CLI; file/directory discovery; structured Terraform HCL rules; YAML/JSON parsing; initial AWS CloudFormation, Azure ARM, GCP configuration, Kubernetes pod/RBAC, and Dockerfile rules; secret-pattern checks with redacted evidence; exclusions and max-file-size guard; text/JSON/SARIF output; severity threshold and exit codes; stable JSON report comparison; comparison-based CI gate for new findings and severity escalations; GitHub Actions test, scan, report artifact, and SARIF publication workflow; local SQLite scan history and lifecycle/trend commands.

**Not yet implemented:** comprehensive Azure/GCP rule coverage; full CIS benchmark coverage; Terraform plan/expression evaluation and Helm template rendering; complete CloudFormation resource/property coverage; broad secret entropy/context analysis; additional dependency ecosystem coverage and offline OSV database updates; external scanner adapters; policy exceptions with expiry; loadable third-party rule packs; full SARIF schema validation and extensive integration/regression coverage.

## Development checks

```bash
python -m pytest -q
python -m compileall -q src scripts tests
ruff check src tests scripts
```

## Adding rules

Add a stable rule ID, severity, clear risk statement, remediation, relevant provider/category, and a fixture that proves both the vulnerable case and an appropriate safe case. Add a regression test before changing an existing rule. Prefer structured parsers and resource-context-aware evaluation over broad text matching as coverage expands.

## Security notes

- Never test with real credentials. Use synthetic fixtures.
- Secret detection is heuristic; rotate a credential if a real secret may have been committed.
- Scan errors are returned separately and produce exit code `3`; they must not be interpreted as a successful clean scan.
- Native Terraform checks use parsed HCL and do not evaluate arbitrary Terraform expressions. Validate important infrastructure with a mature IaC scanner before deployment.


### Detection engine: resolved dependencies and SBOM

The dependency scanner supports pinned requirements.txt, npm package-lock v2/v3 and npm-shrinkwrap, Poetry, uv, pnpm v6/v9, Go go.sum and Cargo.lock. Unresolved requirements fail closed during vulnerability scans. Go checksums describe downloaded modules, not necessarily the currently selected build graph. OSV queries transmit package names, versions and ecosystems to the public OSV service; missing severity remains conservatively HIGH.

Generate a local CycloneDX 1.6 JSON inventory without querying OSV:

```bash
cloudsec sbom . --output reports/sbom.json
```

This is a resolved dependency inventory, not a complete build-attested or transitive relationship graph. Unsupported ecosystem formats are not certified.


### Live AWS inventory (initial coverage)

```bash
pip install '.[aws]'
cloudsec cloud aws --region us-east-1 --output reports/aws-inventory.json
```

Uses the normal AWS SDK credential chain (prefer short-lived role credentials). No write operations are performed. The initial adapter inventories EC2 instances, EBS volumes, security groups, RDS instances, ECR repositories and EKS clusters. It checks encryption, administrative ingress, public RDS and EKS exposure, and ECR tag mutability. Coverage is explicitly limited to the requested regions and listed services; it is not a full account compliance assessment. Each failed service collection marks the output incomplete and returns exit code 3, including under --no-fail. A successful collection with HIGH/CRITICAL findings returns 1 unless --no-fail is provided. Live AWS validation requires an authorized account and read-only role. Other providers and services remain future increments.


### Offline Terraform plan and rendered manifests

```bash
terraform show -json tfplan > plan.json
cloudsec scan plan.json --scanner iac --no-history
helm template example ./chart > rendered.yaml
cloudsec scan rendered.yaml --scanner iac --no-history
```

CloudSec reads Terraform plan format 1.x without invoking Terraform, evaluates supported managed resources in nested modules, and withholds complete coverage for known unresolved security-relevant values. It does not resolve arbitrary expressions or certify unsupported resource types. Plan files may contain sensitive data; store them securely and avoid uploading them. CloudFormation intrinsic tags are parsed as inert data, not evaluated, and Kubernetes List objects are scanned item by item. Helm rendering is currently caller-managed; use trusted local charts and do not execute plugins or fetch dependencies from untrusted sources.


### Supply-chain vulnerability enrichment

OSV batch matches are resolved to individual advisory documents before severity evaluation. CVSS v3/v4 vectors and recognized database severity labels are supported; conflicting labels select the higher severity, and missing or invalid severity never implies a clean result. Transient network failures are retried within a bounded budget; failed enrichment makes the scan incomplete. Withdrawn advisories are omitted. Composer, Gradle and registry-based Bundler lockfiles are additionally supported. Non-registry Bundler sources fail closed; the SBOM is a package inventory, not a complete dependency graph.


### Expiring finding exceptions

Use a separately reviewed YAML exception file with exact finding fingerprints from a JSON scan report. Exceptions never remove the original findings or change their severity. They only affect CLI failure gating; SARIF reports retain accepted suppressions. Unmatched, ambiguous and expired exceptions remain visible and do not waive any finding. Expiration is inclusive through the stated UTC date. Reviewer identity is operator-supplied metadata, not cryptographically authenticated. Keep the policy file outside the scanned source or explicitly exclude its exact path to avoid treating policy text as application input.

```bash
cloudsec scan infrastructure/ --format json --output report.json --no-history
cloudsec scan infrastructure/ --exceptions reviewed-exceptions.yaml --no-history
```

The exception document uses version: 1 and an exceptions list. Every record requires finding_id (64 lowercase hex characters), expires (ISO date), reason and approved_by. Review exceptions in source control and protect policy changes through repository controls. The repository regression gate intentionally evaluates raw findings independently of CLI exceptions.
