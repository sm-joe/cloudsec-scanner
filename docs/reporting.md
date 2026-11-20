# Reporting and privacy

## Scan history and security trends

Every `cloudsec scan` and `cloudsec image` run is recorded locally in a SQLite database by default. The history stores scan metadata, severity counts, warnings/errors, the normalized findings from the report, and lifecycle changes compared with the most recent **complete** scan of the same target and scan type.

The default database is outside the repository:
- Windows: `%LOCALAPPDATA%\CloudSecScanner\history.db`
- macOS: `~/Library/Application Support/CloudSecScanner/history.db`
- Linux: `$XDG_STATE_HOME/cloudsec-scanner/history.db`, or `~/.local/state/cloudsec-scanner/history.db` when `XDG_STATE_HOME` is unset.

Set `CLOUDSEC_HISTORY_DB` to override the default for a shell/session, or use `--history-db` on `scan`/`image`. Use `--no-history` to run a scan without recording it. History database paths can also be passed to the history subcommands using `--database`.

```bash
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


### Finding schema

Each finding includes a stable rule ID, title, severity, message, path, best-effort line number, resource where available, category, provider, remediation, compliance mapping where available, and redacted evidence. JSON includes a summary and warnings/errors separately from findings.


### Resource assessment coverage

Native IaC reports now distinguish EVALUATED (implemented predicates ran), UNSUPPORTED, UNRESOLVED, and NOT_APPLICABLE resources. Unsupported or unresolved resources make the scan incomplete even with --no-fail. These statuses describe the selected native rules, not complete provider or CIS compliance. Terraform findings include resource_id (full type/name or plan address); Kubernetes findings include API version, kind, namespace and name. Legacy resource remains available for compatibility. AWS inventory reports use assets_scanned instead of files_scanned. Expanded native predicates include public RDS and EKS endpoints, S3 public access blocking, ECR tag mutability, GCP bucket/SQL controls and weak Azure storage TLS.


### Report compatibility and privacy

Reports carry fingerprint_version: 2 and include full native resource IDs in fingerprint calculations. Regenerate pre-v2 baselines and re-review exception IDs; older fingerprint versions are rejected rather than silently matched. Use cloudsec scan TARGET --relative-paths --no-history to minimize local filesystem path disclosure in exported JSON, SARIF or text. This option does not anonymize cloud identifiers, resource names, advisory metadata or arbitrary diagnostic content. Do not publish sensitive reports without review. CI validates native reports against repository-pinned JSON, SARIF 2.1.0 and CycloneDX 1.6 schemas offline.


AWS report sharing: cloudsec cloud aws --region us-east-1 --redact-identifiers --output aws-share.json. Account and asset identifiers are replaced by per-report HMAC pseudonyms; related findings remain joinable within the report. Regions, service types, posture and severities remain visible. The key is not exported; pseudonymized reports are not reproducible or suitable as cross-run baselines. OSV batch pagination follows per-package continuation tokens, rejects repetitions and enforces a finite page/advisory budget.



### Terminal scan presentation

The redesigned text report on main (not the published v0.1.0 wheel) shows numbered red FAILED findings, their actual rule IDs and full finding fingerprints, file/resource context, and green PASSED resource assessments when recorded native evaluation supports that outcome. Pass counts are resource counts, not per-rule counts, and are withheld for incomplete coverage or rule exclusions. A finding with an accepted exception remains visible. Colors are automatic on supported interactive terminals; use `--color always` or `--color never` to override auto detection. `NO_COLOR` disables colors. Text report files, JSON and SARIF remain free of terminal escape sequences. Exit codes and gating semantics are unchanged.

[Back to README](../README.md)
