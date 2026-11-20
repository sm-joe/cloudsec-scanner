import json

import pytest

from cloudsec_scanner.config import load_config
from cloudsec_scanner.scanner import scan_target
from cloudsec_scanner.safe_input import safe_yaml_documents


def scan(tmp_path, filename, contents):
    path = tmp_path / filename
    path.write_text(contents, encoding="utf-8")
    return scan_target(str(path), load_config(None))


def plan(values, unknown=None):
    address = 'module.child.aws_ebs_volume.example[0]'
    return {"format_version": "1.2", "terraform_version": "1.9.0",
            "planned_values": {"root_module": {"child_modules": [{"address": "module.child", "resources": [
                {"address": address, "type": "aws_ebs_volume", "mode": "managed", "values": values}]}]}},
            "resource_changes": [{"address": address, "mode": "managed", "change": {"actions": ["create"], "after_unknown": unknown or {}}}]}


def test_nested_plan_address(tmp_path):
    result = scan(tmp_path, "plan.json", json.dumps(plan({"encrypted": False})))
    assert result.coverage_complete
    assert any(f.rule_id == "AWS-TF-003" and f.resource == "module.child.aws_ebs_volume.example[0]" for f in result.findings)


def test_unknown_plan_security_fields(tmp_path):
    result = scan(tmp_path, "plan.json", json.dumps(plan({}, {"encrypted": True})))
    assert not result.coverage_complete
    assert result.warnings


def test_known_safe_plan(tmp_path):
    result = scan(tmp_path, "plan.json", json.dumps(plan({"encrypted": True}, {"id": True})))
    assert result.coverage_complete
    assert not result.findings


def test_bad_plan_fails(tmp_path):
    result = scan(tmp_path, "plan.json", json.dumps({"format_version": "2.0", "planned_values": {}}))
    assert result.errors
    assert not result.coverage_complete


def test_cloudformation_intrinsics(tmp_path):
    result = scan(tmp_path, "template.yaml", """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Disk:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      GroupId: !Ref Group
      IpProtocol: tcp
      FromPort: 20
      ToPort: 30
      CidrIpv6: '::/0'
""")
    assert not result.errors
    assert "AWS-CF-006" in {f.rule_id for f in result.findings}


def test_unknown_yaml_tag_rejected():
    with pytest.raises(ValueError):
        safe_yaml_documents("x: !Unexpected data", cloudformation=True)


def test_config_parser_remains_strict():
    with pytest.raises(ValueError):
        safe_yaml_documents("x: !Ref Value")


def test_kubernetes_list(tmp_path):
    result = scan(tmp_path, "list.yaml", """
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Pod
    metadata:
      name: example
    spec:
      hostPID: true
""")
    assert not result.errors
    assert any(f.rule_id == "K8S-SEC-007" and f.resource == "example" for f in result.findings)
