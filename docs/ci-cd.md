# CI/CD integration

## Repository security workflow

`../.github/workflows/cloudsec.yml` runs on pull requests, pushes to `main`, and manual dispatch. It installs the package with development dependencies, runs Ruff and the test suite, and generates JSON and SARIF reports.

For pull requests and commits with a usable parent revision, the workflow also:

1. Checks out the target/base revision into `baseline-repo`.
2. Scans that revision to create `reports/baseline.json`.
3. Scans the current revision to create `reports/current.json` and `reports/current.sarif`.
4. Runs `cloudsec compare` and applies `scripts/ci_gate.py` to the comparison report.
5. Fails the regression gate for new HIGH/CRITICAL findings or an existing finding whose severity escalates to HIGH/CRITICAL. Existing findings and severity downgrades do not fail this regression gate.
6. Uploads JSON/SARIF/comparison reports as a workflow artifact. SARIF is also submitted to GitHub Code Scanning when repository permissions and code-scanning availability permit it.

The baseline scan uses the scanner version from the current revision, so the comparison focuses on target findings rather than differences between scanner versions. A first commit without a parent cannot be compared; that run still tests and scans the current revision, but has no baseline regression gate. Scanner execution errors, failed tests/lint, baseline checkout/scan errors, comparison errors, and gate violations fail the workflow. SARIF publication itself is best-effort; the report artifact remains available if publishing is unavailable.

The workflow requires `contents: read`, `pull-requests: read`, and `security-events: write`. No cloud credentials are needed for local file scanning. After the first successful run, configure the repository's branch protection/ruleset to require the **Test and Scan** status check; workflow files do not enable branch protection by themselves.

The regression threshold defaults to `HIGH`. To include MEDIUM findings, change the gate step to `python scripts/ci_gate.py reports/comparison.json --severity MEDIUM`.

### Reproduce the regression gate locally

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
ruff check src tests scripts
mkdir -p reports
cloudsec scan . --config .cloudsec-ci.yml --format json --output reports/current.json --no-fail --no-history
cloudsec scan ../baseline-checkout --config .cloudsec-ci.yml --format json --output reports/baseline.json --no-fail --no-history
cloudsec compare reports/baseline.json reports/current.json --format json --output reports/comparison.json
python scripts/ci_gate.py reports/comparison.json --severity HIGH
```

Replace `../baseline-checkout` with a checkout or working tree of the target/base revision. The CI helper consumes the JSON output of `cloudsec compare`; it does not accept SARIF as comparison input.


[Back to README](../README.md)
