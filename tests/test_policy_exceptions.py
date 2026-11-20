import json
from datetime import date

import pytest
import yaml

from cloudsec_scanner.cli import main
from cloudsec_scanner.models import Finding, ScanResult
from cloudsec_scanner.policy import apply_exceptions, load_exceptions
from cloudsec_scanner.report import render_sarif


def fixture():
    return ScanResult("root", [Finding("RULE-1", "Risk", "HIGH", "Risk", "root/a.tf", resource="example")])


def entry(result, expires="2030-01-01"):
    return {"finding_id": result.to_dict()["findings"][0]["finding_id"], "expires": expires, "reason": "Approved temporary risk", "approved_by": "reviewer", "approved_severity": "HIGH"}


def test_accepted_exception_keeps_finding():
    result = fixture()
    record = entry(result)
    assert apply_exceptions(result, [record], today=date(2026, 1, 1)) == {record["finding_id"]}
    assert len(result.to_dict()["findings"]) == 1
    assert result.exceptions[0]["status"] == "ACCEPTED"
    sarif = json.loads(render_sarif(result))["runs"][0]["results"][0]
    assert sarif["partialFingerprints"]["cloudsecFindingId/v2"] == record["finding_id"]
    assert sarif["suppressions"][0]["status"] == "accepted"


def test_expired_exception_is_not_accepted():
    result = fixture()
    assert not apply_exceptions(result, [entry(result, "2020-01-01")], today=date(2026, 1, 1))
    assert result.exceptions[0]["status"] == "EXPIRED"


def test_ambiguous_identity_not_accepted():
    result = fixture()
    record = entry(result)
    result.findings.append(result.findings[0])
    assert not apply_exceptions(result, [record])
    assert result.exceptions[0]["status"] == "AMBIGUOUS"


def test_unmatched_exception_visible():
    result = fixture()
    assert not apply_exceptions(result, [{**entry(result), "finding_id": "a" * 64}])
    assert result.exceptions[0]["status"] == "UNMATCHED"


@pytest.mark.parametrize("modify", ["duplicate", "missing", "wildcard", "bad_date"])
def test_invalid_exception_documents(tmp_path, modify):
    record = entry(fixture())
    entries = [record]
    if modify == "duplicate":
        entries.append(record.copy())
    elif modify == "missing":
        del record["reason"]
    elif modify == "wildcard":
        record["finding_id"] = "*"
    else:
        record["expires"] = "forever"
    path = tmp_path / "exceptions.yaml"
    path.write_text(yaml.safe_dump({"version": 2, "exceptions": entries}))
    with pytest.raises(ValueError):
        load_exceptions(path)


def test_cli_exception_controls_exit_not_evidence(tmp_path):
    source = tmp_path / "main.tf"
    source.write_text('resource "aws_ebs_volume" "example" { encrypted = false }')
    output = tmp_path / "report.json"
    arguments = ["scan", str(source), "--scanner", "iac", "--no-history", "--format", "json", "--output", str(output)]
    assert main(arguments) == 1
    before = json.loads(output.read_text())
    record = {"finding_id": before["findings"][0]["finding_id"], "expires": "2099-01-01", "reason": "Temporary risk", "approved_by": "reviewer", "approved_severity": "HIGH"}
    policy = tmp_path / "exceptions.yaml"
    policy.write_text(yaml.safe_dump({"version": 2, "exceptions": [record]}))
    assert main(arguments + ["--exceptions", str(policy)]) == 0
    after = json.loads(output.read_text())
    assert after["findings"] == before["findings"]
    assert after["exceptions"][0]["status"] == "ACCEPTED"
