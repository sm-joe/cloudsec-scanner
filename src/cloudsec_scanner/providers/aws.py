"""Bounded read-only AWS inventory and posture checks."""
from dataclasses import dataclass, field
from typing import Any

from cloudsec_scanner.models import Finding, ScanResult


@dataclass
class AWSInventory:
    result: ScanResult
    assets: list[dict[str, Any]] = field(default_factory=list)
    coverage: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self):
        return {**self.result.to_dict(), "assets": self.assets, "coverage": self.coverage}


def _pages(client, operation, key, *, limit=1000):
    count = 0
    for page in client.get_paginator(operation).paginate():
        count += 1
        if count > limit:
            raise ValueError("pagination budget exceeded")
        if not isinstance(page, dict) or not isinstance(page.get(key), list):
            raise ValueError("invalid inventory page")
        yield from page[key]


def _collect(inventory, service, region, callback):
    try:
        callback()
    except Exception as exc:
        # Never include SDK request parameters, credentials, or raw diagnostics.
        inventory.result.errors.append(f"{service}/{region}: collection failed ({type(exc).__name__})")
        inventory.result.coverage_complete = False
        inventory.coverage.append({"service": service, "region": region, "status": "INCOMPLETE"})
    else:
        inventory.coverage.append({"service": service, "region": region, "status": "COMPLETE"})


def scan_aws(regions, *, session=None):
    if not regions or any(not isinstance(r, str) or not r.strip() for r in regions):
        raise ValueError("at least one explicit AWS region is required")
    regions = sorted(set(regions))
    if session is None:
        try:
            import boto3
        except ImportError as exc:
            raise ValueError("install cloudsec-scanner[aws] for AWS inventory") from exc
        session = boto3.Session()
    try:
        account = session.client("sts", region_name=regions[0]).get_caller_identity()["Account"]
        if not isinstance(account, str) or len(account) != 12 or not account.isdigit():
            raise ValueError("invalid AWS account identity")
    except Exception as exc:
        raise ValueError("AWS identity unavailable; verify the configured credential chain") from exc
    target = f"aws://{account}"
    result = ScanResult(target, project_key=target, scan_profile="aws-inventory-v1:" + ",".join(regions))
    inventory = AWSInventory(result)

    def asset(service, region, identifier, **properties):
        if not isinstance(identifier, str) or not identifier:
            raise ValueError("missing asset identifier")
        if len(inventory.assets) >= 100000:
            raise ValueError("inventory asset budget exceeded")
        uri = f"{target}/{region}/{service}/{identifier}"
        inventory.assets.append({"id": uri, "provider": "AWS", "account": account, "region": region, "service": service, "resource": identifier, "properties": properties})
        result.files_scanned += 1
        return uri

    def finding(rule, title, uri, fix, severity="HIGH"):
        result.findings.append(Finding(rule, title, severity, title, uri, resource=uri, provider="AWS", remediation=fix))

    def ec2(region):
        client = session.client("ec2", region_name=region)
        for volume in _pages(client, "describe_volumes", "Volumes"):
            encrypted = volume["Encrypted"]
            if not isinstance(encrypted, bool):
                raise ValueError("missing volume encryption state")
            uri = asset("ebs", region, volume["VolumeId"], encrypted=encrypted)
            if not encrypted:
                finding("AWS-LIVE-EBS-001", "EBS volume is unencrypted", uri, "Migrate data to an encrypted EBS volume.")
        for group in _pages(client, "describe_security_groups", "SecurityGroups"):
            permissions = group["IpPermissions"]
            if not isinstance(permissions, list):
                raise ValueError("invalid security group ingress state")
            uri = asset("security-group", region, group["GroupId"])
            for rule in permissions:
                public = any(x.get("CidrIp") == "0.0.0.0/0" for x in rule.get("IpRanges", [])) or any(x.get("CidrIpv6") == "::/0" for x in rule.get("Ipv6Ranges", []))
                protocol = rule["IpProtocol"]
                admin = protocol == "-1" or (protocol in {"tcp", "6"} and any(rule.get("FromPort", 65536) <= port <= rule.get("ToPort", -1) for port in (22, 3389)))
                if public and admin:
                    finding("AWS-LIVE-SG-001", "Security group exposes administrative ports publicly", uri, "Restrict SSH and RDP to approved private networks.")
                    break
        for reservation in _pages(client, "describe_instances", "Reservations"):
            for instance in reservation["Instances"]:
                asset("ec2", region, instance["InstanceId"], public_ip_present=bool(instance.get("PublicIpAddress")))

    def rds(region):
        client = session.client("rds", region_name=region)
        for database in _pages(client, "describe_db_instances", "DBInstances"):
            encrypted = database["StorageEncrypted"]
            public = database["PubliclyAccessible"]
            if not isinstance(encrypted, bool) or not isinstance(public, bool):
                raise ValueError("invalid database posture")
            uri = asset("rds", region, database["DBInstanceIdentifier"], encrypted=encrypted, publicly_accessible=public)
            if not encrypted:
                finding("AWS-LIVE-RDS-001", "RDS storage is unencrypted", uri, "Migrate to an encrypted database.")
            if public:
                finding("AWS-LIVE-RDS-002", "RDS instance is publicly accessible", uri, "Disable public accessibility and review network access.")

    def ecr(region):
        client = session.client("ecr", region_name=region)
        for repository in _pages(client, "describe_repositories", "repositories"):
            uri = asset("ecr", region, repository["repositoryName"], tag_mutability=repository["imageTagMutability"])
            if repository["imageTagMutability"] == "MUTABLE":
                finding("AWS-LIVE-ECR-001", "ECR repository allows mutable tags", uri, "Enable immutable image tags where appropriate.", "MEDIUM")

    def eks(region):
        client = session.client("eks", region_name=region)
        for name in _pages(client, "list_clusters", "clusters"):
            cluster = client.describe_cluster(name=name)["cluster"]
            config = cluster["resourcesVpcConfig"]
            public = config["endpointPublicAccess"]
            if not isinstance(public, bool):
                raise ValueError("invalid EKS endpoint posture")
            uri = asset("eks", region, name, endpoint_public_access=public)
            if public and any(c in {"0.0.0.0/0", "::/0"} for c in config["publicAccessCidrs"]):
                finding("AWS-LIVE-EKS-001", "EKS API endpoint allows all public addresses", uri, "Restrict endpoint CIDRs or enable private endpoint access.")

    for region in regions:
        for name, callback in (("ec2", ec2), ("rds", rds), ("ecr", ecr), ("eks", eks)):
            _collect(inventory, name, region, lambda callback=callback, region=region: callback(region))
    return inventory
