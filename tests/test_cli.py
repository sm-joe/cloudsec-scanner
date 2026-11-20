import json
from pathlib import Path

from cloudsec_scanner.cli import EXIT_FINDINGS, EXIT_INPUT, EXIT_OK, main

ROOT = Path(__file__).parent


def test_json_report_and_finding_exit_code(tmp_path):
    output = tmp_path / "report.json"
    target = ROOT / "fixtures/terraform/insecure.tf"
    code = main(["scan", str(target), "--format", "json", "--output", str(output)])
    assert code == EXIT_FINDINGS
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["summary"]["finding_count"] >= 1


def test_no_fail_overrides_findings(tmp_path):
    target = ROOT / "fixtures/terraform/insecure.tf"
    assert main(["scan", str(target), "--no-fail"]) == EXIT_OK


def test_missing_target_returns_input_error(tmp_path):
    assert main(["scan", str(tmp_path / "missing")]) == EXIT_INPUT


def test_config_init_refuses_overwrite(tmp_path):
    target = tmp_path / ".cloudsec.yml"
    target.write_text("existing", encoding="utf-8")
    assert main(["config-init", "--output", str(target)]) == EXIT_INPUT



def test_baseline_gate_allows_persistent_findings(tmp_path):
    target = ROOT / "fixtures/terraform/insecure.tf"
    baseline = tmp_path / "baseline.json"
    first_output = tmp_path / "baseline-scan.json"

    assert main(
        ["scan", str(target), "--format", "json", "--output", str(first_output)]
    ) == EXIT_FINDINGS
    baseline.write_text(first_output.read_text(encoding="utf-8"), encoding="utf-8")

    assert main(
        [
            "scan",
            str(target),
            "--baseline",
            str(baseline),
            "--fail-on-new",
            "--format",
            "json",
        ]
    ) == EXIT_OK


def test_baseline_gate_fails_for_new_blocking_findings(tmp_path):
    target = ROOT / "fixtures/terraform/insecure.tf"
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"target": str(target), "fingerprint_version": 2, "findings": []}), encoding="utf-8")

    assert main(
        [
            "scan",
            str(target),
            "--baseline",
            str(baseline),
            "--fail-on-new",
            "--format",
            "json",
        ]
    ) == EXIT_FINDINGS


def test_severity_override_changes_report_and_gate(tmp_path):
    target = ROOT / "fixtures/terraform/insecure.tf"
    config = tmp_path / ".cloudsec.yml"
    output = tmp_path / "report.json"
    config.write_text(
        "severity_threshold: HIGH\n"
        "severity_overrides:\n"
        "  AWS-TF-001: LOW\n",
        encoding="utf-8",
    )

    code = main(
        [
            "scan",
            str(target),
            "--config",
            str(config),
            "--format",
            "json",
            "--output",
            str(output),
        ]
    )

    report = json.loads(output.read_text(encoding="utf-8"))
    overridden = [item for item in report["findings"] if item["rule_id"] == "AWS-TF-001"]
    assert overridden
    assert all(item["severity"] == "LOW" for item in overridden)
    assert code == EXIT_FINDINGS  # Other HIGH findings still block.


def test_fail_on_new_requires_baseline(tmp_path):
    target = ROOT / "fixtures/terraform/insecure.tf"
    assert main(["scan", str(target), "--fail-on-new"]) == EXIT_INPUT
