import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from cloudsec_scanner.config import load_config
from cloudsec_scanner.scanner import scan_target
from cloudsec_scanner.report import render_json, render_sarif
from cloudsec_scanner.sbom import build_sbom
from cloudsec_scanner.models import Finding, ScanResult
from cloudsec_scanner.comparison import finding_identity, compare_report_documents, ComparisonError
from cloudsec_scanner.privacy import relative_report

SCHEMAS = Path(__file__).resolve().parents[1] / "schemas"


def validate(name, document):
    schema = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
    registry = Registry()
    for file in SCHEMAS.glob("*.json"):
        item = json.loads(file.read_text(encoding="utf-8"))
        if "$id" in item:
            registry = registry.with_resource(item["$id"], Resource.from_contents(item))
    Draft7Validator(schema, registry=registry).validate(document)


def test_native_reports_validate():
    result = scan_target(str(Path(__file__).parent / "fixtures"), load_config(None))
    validate("cloudsec-report-1.0.json", json.loads(render_json(result)))
    validate("sarif-2.1.0.json", json.loads(render_sarif(result)))


def test_sbom_validate(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("requests==2.31.0")
    validate("bom-1.6.schema.json", build_sbom(str(path)))


def test_full_identity_distinguishes_namespaces():
    a = {"rule_id": "K8S-SEC-001", "path": "pod.yaml", "resource": "same", "resource_id": "v1/Pod/ns1/same"}
    assert finding_identity(a) != finding_identity({**a, "resource_id": "v1/Pod/ns2/same"})


def test_old_baseline_rejected():
    with pytest.raises(ComparisonError, match="fingerprint versions differ"):
        compare_report_documents({"findings": []}, ScanResult(".").to_dict())


def test_path_minimization_preserves_identity(tmp_path):
    path = tmp_path / "main.tf"
    result = ScanResult(str(tmp_path), [Finding("EXAMPLE", "Example", "HIGH", "Example", str(path), resource_id="aws_ebs_volume.demo")], project_key=str(tmp_path), warnings=[str(path) + ": warning"])
    sanitized = relative_report(result)
    doc = sanitized.to_dict()
    assert doc["target"] == "."
    assert doc["project_key"] == ""
    assert doc["findings"][0]["path"] == "main.tf"
    assert doc["findings"][0]["finding_id"] == result.to_dict()["findings"][0]["finding_id"]
    assert str(tmp_path) not in render_json(sanitized)


def test_cli_rejects_legacy_baseline(tmp_path):
    from cloudsec_scanner.cli import main, EXIT_ERROR
    source = tmp_path / "main.tf"
    source.write_text('resource "aws_ebs_volume" "demo" { encrypted = false }', encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"target": str(source), "findings": []}), encoding="utf-8")
    assert main(["scan", str(source), "--baseline", str(baseline), "--fail-on-new", "--scanner", "iac", "--no-history"]) == EXIT_ERROR


def test_cli_relative_export(tmp_path):
    from cloudsec_scanner.cli import main, EXIT_FINDINGS
    source = tmp_path / "main.tf"
    source.write_text('resource "aws_ebs_volume" "demo" { encrypted = false }', encoding="utf-8")
    output = tmp_path / "result.json"
    assert main(["scan", str(source), "--relative-paths", "--scanner", "iac", "--no-history", "--format", "json", "--output", str(output)]) == EXIT_FINDINGS
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["fingerprint_version"] == 2
    assert document["target"] == "."
    assert document["findings"][0]["path"] == "main.tf"
    assert str(tmp_path) not in json.dumps(document)
