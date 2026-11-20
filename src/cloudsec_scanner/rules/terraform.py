"""Structured Terraform checks; no evaluation or execution of Terraform code."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import hcl2

from cloudsec_scanner.models import Finding
from cloudsec_scanner.safe_input import validate_document
from cloudsec_scanner.coverage import assessment, tf_status


def _list(value: Any) -> list:
    return value if isinstance(value, list) else [value] if value is not None else []


def _public(values: Any) -> bool:
    return any(value in ("0.0.0.0/0", "::/0") for value in _list(values))


def _wild(value: Any) -> bool:
    return "*" in _list(value)


def _admin(ports: Any) -> bool:
    for port in _list(ports):
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", str(port))
        if match:
            low, high = int(match[1]), int(match[2] or match[1])
            if any(low <= target <= high for target in (22, 3389)):
                return True
    return False


def _policy(value: Any) -> Any:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None
    try:
        return json.loads(value)
    except ValueError:
        # python-hcl2 represents a jsonencode expression as interpolation.
        # Parse the argument as HCL data, never evaluate the expression.
        match = re.fullmatch(r"\$\{jsonencode\((.*)\)\}", value, re.S)
        if match:
            try:
                return hcl2.loads("policy = " + match[1]).get("policy")
            except Exception:
                return None
        return None


def scan_terraform_document(path: Path, text: str, assessments=None) -> list[Finding]:
    # Normalize Windows CRLF before handing text to the HCL grammar.
    text = text.replace("\r\n", "\n")
    try:
        document = hcl2.loads(text)
        validate_document(document)
    except Exception as exc:
        raise ValueError("invalid or excessively complex Terraform HCL") from exc

    return evaluate_terraform_resources(path, document, text, assessments=assessments)


def evaluate_terraform_resources(path: Path, document: dict, text: str = "", *, assessments=None, plan=False) -> list[Finding]:
    findings: list[Finding] = []
    aws = "CIS AWS Foundations Benchmark"
    azure = "Microsoft Cloud Security Benchmark"
    gcp = "Google Cloud security best practices"

    for entry in _list(document.get("resource")):
        if not isinstance(entry, dict):
            raise ValueError("invalid Terraform resource")
        for kind, names in entry.items():
            for name, body in names.items():
                if not isinstance(body, dict):
                    raise ValueError("invalid Terraform resource body")
                resource_id = name if plan else f"{kind}.{name}"
                if assessments is not None:
                    status, reason = tf_status(kind, body)
                    assessments.append(assessment(path, resource_id, kind, status, reason))
                location = re.search(r'resource\s+"' + re.escape(kind) + r'"\s+"' + re.escape(name) + r'"', text)
                line = text.count("\n", 0, location.start()) + 1 if location else 1

                def add(rule, title, severity, message, fix, provider="AWS", benchmark=aws, category="misconfiguration"):
                    findings.append(Finding(rule, title, severity, message, str(path), line, name, category, provider, fix, compliance=(benchmark,), resource_id=resource_id))

                if kind in {"aws_s3_bucket_acl", "aws_s3_bucket"} and body.get("acl") in ("public-read", "public-read-write"):
                    add("AWS-TF-001", "Public S3 bucket ACL", "HIGH", "An S3 ACL grants public access.", "Remove public ACLs and configure S3 Block Public Access.")
                if kind == "aws_security_group_rule" and body.get("type") == "ingress" and (_public(body.get("cidr_blocks")) or _public(body.get("ipv6_cidr_blocks"))):
                    add("AWS-TF-002", "Security group ingress open to the internet", "HIGH", "An ingress rule permits a public CIDR.", "Restrict ingress CIDRs and ports.")
                if kind == "aws_vpc_security_group_ingress_rule" and (_public(body.get("cidr_ipv4")) or _public(body.get("cidr_ipv6"))):
                    add("AWS-TF-002", "Security group ingress open to the internet", "HIGH", "An ingress rule permits a public CIDR.", "Restrict ingress CIDRs and ports.")
                if kind == "aws_security_group" and any(isinstance(rule, dict) and (_public(rule.get("cidr_blocks")) or _public(rule.get("ipv6_cidr_blocks"))) for rule in _list(body.get("ingress"))):
                    add("AWS-TF-002", "Security group ingress open to the internet", "HIGH", "An ingress rule permits a public CIDR.", "Restrict ingress CIDRs and ports.")
                if kind == "aws_ebs_volume" and body.get("encrypted") is False:
                    add("AWS-TF-003", "EBS volume encryption disabled", "HIGH", "EBS encryption is explicitly disabled.", "Enable EBS encryption.")
                if kind == "aws_db_instance" and body.get("storage_encrypted") is False:
                    add("AWS-TF-004", "RDS storage encryption disabled", "HIGH", "RDS encryption is explicitly disabled.", "Enable storage encryption and plan migration.")
                if kind == "aws_db_instance" and body.get("publicly_accessible") is True:
                    add("AWS-TF-006", "RDS is publicly accessible", "HIGH", "Public accessibility is enabled.", "Disable public accessibility and review network access.")
                if kind == "aws_s3_bucket_public_access_block" and any(body.get(k) is False for k in ("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets")):
                    add("AWS-TF-007", "S3 public access blocking disabled", "HIGH", "A public access block flag is explicitly disabled.", "Enable all four public access block flags.")
                if kind == "aws_ecr_repository" and body.get("image_tag_mutability") == "MUTABLE":
                    add("AWS-TF-008", "ECR image tags mutable", "MEDIUM", "Image tags can be overwritten.", "Set image tag mutability to IMMUTABLE.")
                if kind == "aws_eks_cluster" and any(isinstance(config, dict) and config.get("endpoint_public_access") is True and _public(config.get("public_access_cidrs")) for config in _list(body.get("vpc_config"))):
                    add("AWS-TF-009", "EKS endpoint open publicly", "HIGH", "The cluster API allows all public addresses.", "Use a private endpoint or limit public access CIDRs.")
                if kind == "google_storage_bucket":
                    if body.get("public_access_prevention") == "inherited":
                        add("GCP-TF-003", "Bucket public access prevention inherited", "HIGH", "Public access prevention is not enforced at the bucket.", "Set public_access_prevention to enforced.", "GCP", gcp)
                    if body.get("uniform_bucket_level_access") is False:
                        add("GCP-TF-004", "Uniform bucket access disabled", "MEDIUM", "Object ACLs may be used.", "Enable uniform bucket-level access.", "GCP", gcp)
                if kind == "google_sql_database_instance" and any(isinstance(settings, dict) and any(isinstance(ip, dict) and ip.get("ipv4_enabled") is True and any(isinstance(net, dict) and net.get("value") == "0.0.0.0/0" for net in _list(ip.get("authorized_networks"))) for ip in _list(settings.get("ip_configuration"))) for settings in _list(body.get("settings"))):
                    add("GCP-TF-005", "Cloud SQL public network access", "HIGH", "All IPv4 addresses are authorized.", "Use private connectivity and restricted networks.", "GCP", gcp)
                if kind == "aws_s3_bucket" and body.get("force_destroy") is True:
                    add("AWS-TF-005", "S3 bucket force destroy enabled", "LOW", "Terraform can destroy a non-empty bucket.", "Disable force_destroy for production buckets.")
                if kind in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}:
                    policy = _policy(body.get("policy"))
                    if isinstance(policy, dict) and any(isinstance(statement, dict) and str(statement.get("Effect", "")).lower() == "allow" and _wild(statement.get("Action")) and _wild(statement.get("Resource")) for statement in _list(policy.get("Statement"))):
                        add("IAM-TF-001", "Wildcard IAM policy permissions", "HIGH", "An Allow statement grants all actions on all resources.", "Scope actions and resources to least privilege.", category="iam")
                if kind == "azurerm_storage_account":
                    if body.get("min_tls_version") in {"TLS1_0", "TLS1_1"}:
                        add("AZ-TF-003", "Storage permits weak TLS", "MEDIUM", "Minimum TLS version is below TLS 1.2.", "Set minimum TLS to TLS1_2.", "Azure", azure)
                    if body.get("enable_https_traffic_only") is False or body.get("https_traffic_only_enabled") is False:
                        add("AZ-TF-001", "Azure storage account permits HTTP", "HIGH", "HTTPS-only traffic is disabled.", "Require HTTPS-only traffic.", "Azure", azure)
                    if body.get("allow_nested_items_to_be_public") is True:
                        add("AZ-TF-002", "Azure storage allows public nested items", "HIGH", "Nested items may be public.", "Disable anonymous access unless explicitly approved.", "Azure", azure)
                if kind in {"google_storage_bucket_iam_member", "google_storage_bucket_iam_binding", "google_storage_bucket_iam_policy"} and any(member in ("allUsers", "allAuthenticatedUsers") for member in _list(body.get("member")) + _list(body.get("members"))):
                    add("GCP-TF-001", "GCP storage bucket grants public access", "HIGH", "Bucket IAM grants public access.", "Remove public IAM principals.", "GCP", gcp)
                if kind == "google_compute_firewall" and _public(body.get("source_ranges")) and any(isinstance(rule, dict) and (_admin(rule.get("ports")) or not rule.get("ports")) for rule in _list(body.get("allow")) + _list(body.get("allowed"))):
                    add("GCP-TF-002", "GCP firewall exposes administrative port", "HIGH", "Public firewall permits administrative traffic.", "Restrict source ranges and administrative ports.", "GCP", gcp)
    return findings
