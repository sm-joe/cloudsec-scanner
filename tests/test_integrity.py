import json
from dataclasses import replace

import pytest

from cloudsec_scanner.cli import main, EXIT_ERROR
from cloudsec_scanner.comparison import compare_report_documents, ComparisonError
from cloudsec_scanner.config import load_config
from cloudsec_scanner.image_scan import scan_image, ImageScanError
from cloudsec_scanner.models import Finding, ScanResult
from cloudsec_scanner.scanner import scan_target
from cloudsec_scanner.history import record_scan


def test_secret_discovery(tmp_path):
    (tmp_path / ".env").write_text("API_KEY=fixture-credential-value")
    result = scan_target(str(tmp_path), load_config(None))
    assert result.coverage_complete
    assert any(f.rule_id == "SEC-SECRET-002" for f in result.findings)


def test_empty_target_fails(tmp_path):
    assert main(["scan", str(tmp_path), "--no-fail", "--no-history"]) == EXIT_ERROR


def test_oversize_target_fails(tmp_path):
    (tmp_path / "a.tf").write_text("x" * 100)
    config = load_config(None)
    config["max_file_bytes"] = 10
    assert not scan_target(str(tmp_path), config).coverage_complete


def test_recursive_yaml(tmp_path):
    (tmp_path / "a.yaml").write_text("a: &a {b: *a}")
    result = scan_target(str(tmp_path), load_config(None))
    assert result.errors
    assert not result.coverage_complete


def test_duplicate_config(tmp_path):
    path = tmp_path / "config.yml"
    path.write_text("scanners: [iac]\nscanners: [secrets]")
    with pytest.raises(ValueError):
        load_config(str(path))


def test_moved_checkout_identity():
    finding = Finding("TEST", "test", "HIGH", "test", "/old/a.tf", resource="a")
    before = ScanResult("/old", [finding]).to_dict()
    after = ScanResult("/new", [replace(finding, path="/new/a.tf")]).to_dict()
    assert compare_report_documents(before, after)["comparison"]["persistent_count"] == 1


def test_invalid_report_rejected():
    with pytest.raises(ComparisonError):
        compare_report_documents({"findings": [42]}, {"findings": []})


def test_incomplete_comparison_rejected():
    with pytest.raises(ComparisonError):
        compare_report_documents({"findings": [], "coverage_complete": False}, {"findings": []})


def test_image_argument_rejected():
    with pytest.raises(ImageScanError, match="invalid image"):
        scan_image("--help")


def test_image_missing_results(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr("cloudsec_scanner.image_scan.subprocess.run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout=json.dumps({}), stderr=""))
    with pytest.raises(ImageScanError, match="Results"):
        scan_image("alpine:3", trivy_path="trivy")


@pytest.mark.parametrize("dockerfile", ["FROM alpine\nUSER root\n", "FROM alpine:3 AS build\nUSER 1000\nFROM alpine:3\n"])
def test_root_runtime_stage(tmp_path, dockerfile):
    path = tmp_path / "Dockerfile"
    path.write_text(dockerfile)
    assert "DOCKER-004" in {f.rule_id for f in scan_target(str(path), load_config(None)).findings}


def test_project_history_isolation(tmp_path):
    db = tmp_path / "history.db"
    a = ScanResult(".", project_key="/project-a", scan_profile="iac")
    b = ScanResult(".", project_key="/project-b", scan_profile="iac")
    record_scan(db, a)
    assert record_scan(db, b)["lifecycle"]["status"] == "initial"
