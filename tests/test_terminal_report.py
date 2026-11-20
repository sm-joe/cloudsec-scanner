import json

from cloudsec_scanner.cli import main
from cloudsec_scanner.models import Finding, ScanResult
from cloudsec_scanner.coverage import assessment
from cloudsec_scanner.report import render_text, render_json, render_sarif, terminal_color


def sample():
    return ScanResult("iac", [Finding("AWS-TF-003", "EBS encryption disabled", "HIGH", "Risk", "iac/main.tf", resource_id="aws_ebs_volume.bad")], assessments=[
        assessment("iac/main.tf", "aws_ebs_volume.bad", "aws_ebs_volume", "EVALUATED"),
        assessment("iac/main.tf", "aws_ebs_volume.good", "aws_ebs_volume", "EVALUATED"),
    ], files_scanned=1)


def test_color_and_fingerprint():
    result = sample()
    text = render_text(result, color=True)
    assert "\x1b[1;31mFAILED\x1b[0m" in text
    assert "\x1b[1;32mPASSED\x1b[0m" in text
    assert "Passed resources: 1" in text
    assert "AWS-TF-003" in text
    assert result.to_dict()["findings"][0]["finding_id"] in text
    assert "\x1b" not in render_text(result)
    assert "\x1b" not in render_json(result)
    assert "\x1b" not in render_sarif(result)


def test_pass_withheld_for_incomplete_excluded_or_unlinked_findings():
    result = sample()
    assert "Passed resources: 0" in render_text(result, exclusions=True)
    result.coverage_complete = False
    assert "Passed resources: 0" in render_text(result)
    result.coverage_complete = True
    result.findings.append(Finding("OTHER", "Risk", "HIGH", "Risk", "iac/main.tf"))
    assert "Passed resources: 0" in render_text(result)


def test_terminal_escape_in_untrusted_text():
    result = ScanResult("path\x1b[2J")
    assert "\x1b" not in render_text(result)
    assert "\\u001b" in render_text(result)


def test_no_color_environment(monkeypatch):
    import io
    monkeypatch.setenv("NO_COLOR", "")
    assert not terminal_color("always", io.StringIO())


def test_cli_color_plain_export_and_json(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    path = tmp_path / "main.tf"
    path.write_text('resource "aws_ebs_volume" "bad" { encrypted = false }', encoding="utf-8")
    report = tmp_path / "out.txt"
    args = ["scan", str(path), "--scanner", "iac", "--no-history", "--color", "always"]
    assert main(args + ["--output", str(report)]) == 1
    assert "\x1b[1;31mFAILED" in capsys.readouterr().out
    assert "\x1b" not in report.read_text(encoding="utf-8")
    assert main(args + ["--format", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["findings"][0]["rule_id"] == "AWS-TF-003"
