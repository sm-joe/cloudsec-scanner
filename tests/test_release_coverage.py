import json
from cloudsec_scanner.config import load_config
from cloudsec_scanner.scanner import scan_target
from cloudsec_scanner.cli import main


def scan(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    config = load_config(None)
    config["scanners"] = ["iac"]
    return scan_target(str(path), config)


def test_unknown_tf_withholds_coverage(tmp_path):
    result = scan(tmp_path, "a.tf", 'resource "aws_ebs_volume" "demo" { encrypted = var.flag }')
    assert not result.coverage_complete
    assert result.assessments[0]["status"] == "UNRESOLVED"
    assert main(["scan", result.target, "--scanner", "iac", "--no-history", "--no-fail"]) == 3


def test_unsupported_tf_withholds_coverage(tmp_path):
    result = scan(tmp_path, "a.tf", 'resource "example_unknown" "demo" {}')
    assert not result.coverage_complete
    assert result.assessments[0]["status"] == "UNSUPPORTED"


def test_full_tf_resource_and_new_rules(tmp_path):
    result = scan(tmp_path, "a.tf", '''
resource "aws_ebs_volume" "demo" { encrypted = false }
resource "aws_db_instance" "demo" {
  storage_encrypted = false
  publicly_accessible = true
}
resource "aws_s3_bucket_public_access_block" "demo" { block_public_acls = false }
''')
    assert result.coverage_complete
    assert {f.rule_id for f in result.findings} >= {"AWS-TF-003", "AWS-TF-004", "AWS-TF-006", "AWS-TF-007"}
    assert {f.resource_id for f in result.findings} == {"aws_ebs_volume.demo", "aws_db_instance.demo", "aws_s3_bucket_public_access_block.demo"}


def test_kube_namespace_identity(tmp_path):
    result = scan(tmp_path, "a.yaml", '''
apiVersion: v1
kind: Pod
metadata: {name: demo, namespace: a}
spec: {hostPID: true}
---
apiVersion: v1
kind: Pod
metadata: {name: demo, namespace: b}
spec: {hostPID: true}
''')
    assert {f.resource_id for f in result.findings} == {"v1/Pod/a/demo", "v1/Pod/b/demo"}


def test_unsupported_plan(tmp_path):
    result = scan(tmp_path, "plan.json", json.dumps({"format_version": "1.2", "planned_values": {"root_module": {"resources": [{"address": "example_unknown.a", "type": "example_unknown", "values": {}}]}}}))
    assert not result.coverage_complete
    assert result.assessments[0]["status"] == "UNSUPPORTED"


def test_cloudformation_unresolved(tmp_path):
    result = scan(tmp_path, "a.yaml", '''
Resources:
  Database:
    Type: AWS::RDS::DBInstance
    Properties:
      StorageEncrypted: !Ref Flag
''')
    assert not result.coverage_complete
    assert result.assessments[0]["status"] == "UNRESOLVED"
