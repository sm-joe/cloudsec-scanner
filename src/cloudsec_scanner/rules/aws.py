"""Initial AWS CloudFormation and IAM document rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cloudsec_scanner.models import Finding
from cloudsec_scanner.rules.common import finding, mappings

CIS_AWS = ("CIS AWS Foundations Benchmark",)


def scan_aws_document(doc: Any, path: Path, text: str) -> list[Finding]:
    if not isinstance(doc, dict):
        return []
    findings: list[Finding] = []
    resources = doc.get("Resources", {})
    if isinstance(resources, dict):
        for logical_id, resource in resources.items():
            if not isinstance(resource, dict):
                continue
            resource_type = str(resource.get("Type", ""))
            properties = resource.get("Properties", {})
            if not isinstance(properties, dict):
                properties = {}
            if resource_type == "AWS::S3::Bucket":
                public_access = properties.get("PublicAccessBlockConfiguration", {})
                if not isinstance(public_access, dict) or any(
                    public_access.get(flag) is not True
                    for flag in (
                        "BlockPublicAcls",
                        "IgnorePublicAcls",
                        "BlockPublicPolicy",
                        "RestrictPublicBuckets",
                    )
                ):
                    findings.append(
                        finding(
                            "AWS-CF-002",
                            "S3 public access block is incomplete",
                            "HIGH",
                            "The bucket does not explicitly enable all four S3 Block Public Access controls.",
                            path,
                            text,
                            rf"{logical_id}\s*:",
                            "Configure all four PublicAccessBlockConfiguration controls as true and review bucket policies.",
                            provider="AWS",
                            resource=str(logical_id),
                            compliance=CIS_AWS,
                        )
                    )
                if "BucketEncryption" not in properties:
                    findings.append(
                        finding(
                            "AWS-CF-003",
                            "S3 bucket encryption is not configured",
                            "HIGH",
                            "The CloudFormation bucket has no explicit default server-side encryption configuration.",
                            path,
                            text,
                            rf"{logical_id}\s*:",
                            "Configure BucketEncryption with SSE-S3 or the required approved encryption option.",
                            provider="AWS",
                            resource=str(logical_id),
                            compliance=CIS_AWS,
                        )
                    )
            elif resource_type == "AWS::RDS::DBInstance":
                if properties.get("PubliclyAccessible") is True:
                    findings.append(
                        finding(
                            "AWS-CF-004",
                            "RDS instance is publicly accessible",
                            "HIGH",
                            "The database instance is configured for public accessibility.",
                            path,
                            text,
                            rf"{logical_id}\s*:",
                            "Set PubliclyAccessible to false and use private subnets and controlled access paths.",
                            provider="AWS",
                            resource=str(logical_id),
                            compliance=CIS_AWS,
                        )
                    )
                if properties.get("StorageEncrypted") is False:
                    findings.append(
                        finding(
                            "AWS-CF-005",
                            "RDS storage encryption disabled",
                            "HIGH",
                            "The database explicitly disables storage encryption.",
                            path,
                            text,
                            rf"{logical_id}\s*:",
                            "Enable StorageEncrypted and plan migration if the existing database cannot be encrypted in place.",
                            provider="AWS",
                            resource=str(logical_id),
                            compliance=CIS_AWS,
                        )
                    )
            elif resource_type == "AWS::EC2::SecurityGroup":
                for ingress in mappings(properties.get("SecurityGroupIngress")):
                    cidrs = ingress.get("CidrIp")
                    port = ingress.get("FromPort")
                    if cidrs == "0.0.0.0/0" and port in (22, 3389):
                        findings.append(
                            finding(
                                "AWS-CF-006",
                                "Administrative port exposed to the internet",
                                "HIGH",
                                f"Security group {logical_id} exposes TCP port {port} to 0.0.0.0/0.",
                                path,
                                text,
                                rf"{logical_id}\s*:",
                                "Restrict administrative access to approved source ranges or use a managed access service.",
                                provider="AWS",
                                resource=str(logical_id),
                                compliance=CIS_AWS,
                            )
                        )
    # Inspect inline IAM policy statements when they are represented as ordinary JSON/YAML.
    for policy in _walk_dicts(doc):
        statements = policy.get("Statement")
        for statement in mappings(statements):
            effect = str(statement.get("Effect", "")).lower()
            actions = statement.get("Action")
            resources_value = statement.get("Resource")
            if effect == "allow" and _has_wildcard(actions) and _has_wildcard(resources_value):
                findings.append(
                    finding(
                        "AWS-IAM-001",
                        "Wildcard IAM permissions",
                        "HIGH",
                        "An IAM statement allows wildcard actions on wildcard resources.",
                        path,
                        text,
                        r"Action\s*:\s*['\"]?\*|\"Action\"\s*:\s*\"\*\"",
                        "Replace wildcard actions and resources with the minimum permissions required.",
                        provider="AWS",
                        category="iam",
                        compliance=CIS_AWS,
                    )
                )
                break
    return findings


def _walk_dicts(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_dicts(child)


def _has_wildcard(value: Any) -> bool:
    if value == "*":
        return True
    return isinstance(value, list) and "*" in value
