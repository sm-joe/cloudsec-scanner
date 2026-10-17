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
