import json

import pytest

from cloudsec_scanner.providers.aws import scan_aws
from cloudsec_scanner.cli import main


class Pager:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self):
        yield from self.pages


class Client:
    pages = {
        "describe_volumes": [{"Volumes": [{"VolumeId": "vol-a", "Encrypted": False}]}, {"Volumes": [{"VolumeId": "vol-b", "Encrypted": True}]}],
        "describe_security_groups": [{"SecurityGroups": [{"GroupId": "sg-a", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]}]}],
        "describe_instances": [{"Reservations": [{"Instances": [{"InstanceId": "i-a"}]}]}],
        "describe_db_instances": [{"DBInstances": [{"DBInstanceIdentifier": "db-a", "StorageEncrypted": True, "PubliclyAccessible": True}]}],
        "describe_repositories": [{"repositories": [{"repositoryName": "repo-a", "imageTagMutability": "IMMUTABLE"}]}],
        "list_clusters": [{"clusters": ["cluster-a"]}],
    }

    def get_paginator(self, operation):
        return Pager(self.pages[operation])

    def get_caller_identity(self):
        return {"Account": "123456789012"}

    def describe_cluster(self, name):
        return {"cluster": {"resourcesVpcConfig": {"endpointPublicAccess": True, "publicAccessCidrs": ["0.0.0.0/0"]}}}


class Session:
    def __init__(self, fail=None):
        self.fail = fail

    def client(self, service, region_name):
        if service == self.fail:
            raise PermissionError("sensitive diagnostic should never appear")
        return Client()


def test_pagination_and_posture():
    result = scan_aws(["us-east-1"], session=Session())
    assert result.result.coverage_complete
    assert len(result.assets) == 7
    assert len(result.coverage) == 4
    assert {f.rule_id for f in result.result.findings} == {"AWS-LIVE-EBS-001", "AWS-LIVE-SG-001", "AWS-LIVE-RDS-002", "AWS-LIVE-EKS-001"}


def test_partial_permissions_fail_closed():
    inventory = scan_aws(["us-east-1"], session=Session("rds"))
    assert not inventory.result.coverage_complete
    assert inventory.result.errors
    assert "sensitive diagnostic" not in json.dumps(inventory.to_dict())
    assert any(a["service"] == "ebs" for a in inventory.assets)


def test_account_identity_failure():
    with pytest.raises(ValueError, match="identity unavailable"):
        scan_aws(["us-east-1"], session=Session("sts"))


def test_regions_explicit():
    with pytest.raises(ValueError, match="region"):
        scan_aws([], session=Session())


def test_cli_partial_even_no_fail(monkeypatch, tmp_path):
    inventory = scan_aws(["us-east-1"], session=Session("rds"))
    monkeypatch.setattr("cloudsec_scanner.providers.aws.scan_aws", lambda regions: inventory)
    output = tmp_path / "cloud.json"
    assert main(["cloud", "aws", "--region", "us-east-1", "--no-fail", "--output", str(output)]) == 3
    assert json.loads(output.read_text())["coverage_complete"] is False
