import json
from dataclasses import replace

import pytest
import yaml

from cloudsec_scanner import dependency_scan as osv
from cloudsec_scanner.cli import main
from cloudsec_scanner.policy import apply_exceptions, load_exceptions
from cloudsec_scanner.models import Finding, ScanResult
from cloudsec_scanner.providers.aws import scan_aws, redact_inventory
from test_aws_inventory import Session


def test_osv_pagination_preserves_positions(monkeypatch):
    calls = []
    def request(req, **kwargs):
        queries = json.loads(req.data)["queries"]
        calls.append(queries)
        if len(calls) == 1:
            return {"results": [{"vulns": [{"id": "FIRST"}], "next_page_token": "a"}, {"vulns": [{"id": "SECOND"}]}]}
        assert queries == [{"package": {"name": "first"}, "page_token": "a"}]
        return {"results": [{"vulns": [{"id": "THIRD"}]}]}
    monkeypatch.setattr(osv, "_request_json", request)
    monkeypatch.setattr(osv, "_fetch_advisory", lambda identifier: {"id": identifier})
    result = osv._query_osv_batch([{"package": {"name": "first"}}, {"package": {"name": "second"}}])
    assert [[entry["id"] for entry in row["vulns"]] for row in result] == [["FIRST", "THIRD"], ["SECOND"]]


def test_osv_repeated_page_fails_closed(monkeypatch):
    monkeypatch.setattr(osv, "_request_json", lambda *a, **kw: {"results": [{"next_page_token": "loop"}]})
    with pytest.raises(osv.DependencyScanError, match="repeated"):
        osv._query_osv_batch([{}])


def test_escalated_exception_not_accepted():
    result = ScanResult(".", [Finding("RULE", "Risk", "HIGH", "Risk", "a.tf", resource="a")])
    entry = {"finding_id": result.to_dict()["findings"][0]["finding_id"], "expires": "2099-01-01", "approved_severity": "HIGH", "reason": "Review", "approved_by": "reviewer"}
    result.findings[0] = replace(result.findings[0], severity="CRITICAL")
    assert not apply_exceptions(result, [entry])
    assert result.exceptions[0]["status"] == "SEVERITY_ESCALATED"


def test_legacy_exception_file_rejected(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\nexceptions: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="schema"):
        load_exceptions(path)


def test_revoked_baseline_exception_blocks(tmp_path):
    source = tmp_path / "main.tf"
    source.write_text('resource "aws_ebs_volume" "demo" { encrypted = false }', encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    policy = tmp_path / "exceptions.yaml"
    args = ["scan", str(source), "--scanner", "iac", "--no-history", "--format", "json"]
    assert main(args + ["--output", str(baseline)]) == 1
    entry = {"finding_id": json.loads(baseline.read_text())["findings"][0]["finding_id"], "expires": "2099-01-01", "reason": "Review", "approved_by": "reviewer", "approved_severity": "HIGH"}
    policy.write_text(yaml.safe_dump({"version": 2, "exceptions": [entry]}), encoding="utf-8")
    assert main(args + ["--output", str(baseline), "--exceptions", str(policy)]) == 0
    assert main(args + ["--baseline", str(baseline), "--fail-on-new"]) == 1


def test_aws_pseudonyms_and_join_consistency(monkeypatch, tmp_path):
    inventory = scan_aws(["us-east-1"], session=Session())
    document = redact_inventory(inventory).to_dict()
    serialized = json.dumps(document)
    for raw in ("123456789012", "vol-a", "sg-a", "db-a", "cluster-a", "repo-a"):
        assert raw not in serialized
    assert document["summary"]["assets_scanned"] == 7
    assert document["summary"]["files_scanned"] == 0
    assert {f["resource"] for f in document["findings"]} <= {a["id"] for a in document["assets"]}
    assert document["target"] != redact_inventory(inventory).to_dict()["target"]
    monkeypatch.setattr("cloudsec_scanner.providers.aws.scan_aws", lambda regions: inventory)
    path = tmp_path / "aws.json"
    assert main(["cloud", "aws", "--region", "us-east-1", "--redact-identifiers", "--no-fail", "--output", str(path)]) == 0
    assert "123456789012" not in path.read_text()
