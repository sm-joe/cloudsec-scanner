"""Initial native IaC and secret scanners."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

from cloudsec_scanner.dependency_scan import scan_dependencies
from cloudsec_scanner.discovery import discover
from cloudsec_scanner.models import Finding, ScanResult
from cloudsec_scanner.rules import (
    scan_aws_document,
    scan_azure_document,
    scan_gcp_document,
    scan_kubernetes_document,
    scan_terraform_document,
)
from cloudsec_scanner.secret_detection import scan_secrets

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("SEC-SECRET-001", re.compile(r"(?i)\bAKIA[0-9A-Z]{16}\b")),
    (
        "SEC-SECRET-002",
        re.compile(
            r"(?i)(?:aws_secret_access_key|client_secret|password|api[_-]?key|access[_-]?token)\s*[:=]\s*[\"']?([^\s\"']{8,})"
        ),
    ),
    ("SEC-SECRET-003", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("SEC-SECRET-004", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
)


def _line_for(text: str, pattern: str, default: int = 1) -> int:
    match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    return text.count("\n", 0, match.start()) + 1 if match else default


def _walk(value: Any, path: str = "") -> Iterator[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield child_path, child
            yield from _walk(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, f"{path}[{index}]")


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    message: str,
    path: Path,
    line: int,
    remediation: str,
    provider: str | None = None,
    resource: str | None = None,
    compliance: tuple[str, ...] = (),
    category: str = "misconfiguration",
    evidence: str | None = None,
) -> Finding:
    return Finding(
        rule_id,
        title,
        severity,
        message,
        str(path),
        line,
        resource,
        category,
        provider,
        remediation,
        (),
        compliance,
        evidence,
    )


def _scan_yaml_json(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        if path.suffix.lower() == ".json":
            docs = [json.loads(text)]
        else:
            docs = list(yaml.safe_load_all(text))
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"malformed YAML/JSON: {exc}") from exc

    for doc in docs:
        if doc is None:
            continue
        if not isinstance(doc, (dict, list)):
            continue
        flattened = list(_walk(doc))
        is_k8s = isinstance(doc, dict) and ("apiVersion" in doc or "kind" in doc)
        is_cf = isinstance(doc, dict) and ("Resources" in doc or "AWSTemplateFormatVersion" in doc)

        for key_path, value in flattened:
            key_lower = key_path.lower()
            if is_k8s:
                if key_lower.endswith(".securitycontext.privileged") and value is True:
                    line = _line_for(text, r"privileged\s*:\s*true")
                    findings.append(
                        _finding(
                            "K8S-SEC-001",
                            "Privileged container enabled",
                            "HIGH",
                            "A Kubernetes container is configured with privileged access to the host.",
                            path,
                            line,
                            "Set securityContext.privileged to false or remove it; use narrowly scoped capabilities.",
                            "Kubernetes",
                            str(doc.get("metadata", {}).get("name", "unknown")),
                            ("CIS Kubernetes Benchmark",),
                        )
                    )
                if key_lower.endswith(".hostnetwork") and value is True:
                    findings.append(
                        _finding(
                            "K8S-SEC-002",
                            "Pod uses host network",
                            "MEDIUM",
                            "The pod shares the node network namespace, increasing exposure and reducing isolation.",
                            path,
                            _line_for(text, r"hostNetwork\s*:\s*true"),
                            "Disable hostNetwork unless the workload has a documented requirement.",
                            "Kubernetes",
                            str(doc.get("metadata", {}).get("name", "unknown")),
                            ("CIS Kubernetes Benchmark",),
                        )
                    )
                if key_lower.endswith(".runasuser") and value == 0:
                    findings.append(
                        _finding(
                            "K8S-SEC-003",
                            "Container runs as root",
                            "HIGH",
                            "runAsUser is explicitly set to UID 0.",
                            path,
                            _line_for(text, r"runAsUser\s*:\s*0"),
                            "Run the workload as a non-root UID and set runAsNonRoot: true.",
                            "Kubernetes",
                            str(doc.get("metadata", {}).get("name", "unknown")),
                            ("CIS Kubernetes Benchmark",),
                        )
                    )
                if key_lower.endswith(".automountserviceaccounttoken") and value is True:
                    findings.append(
                        _finding(
                            "K8S-SEC-004",
                            "Service-account token auto-mounted",
                            "MEDIUM",
                            "A pod automatically receives a service-account token that may not be needed.",
                            path,
                            _line_for(text, r"automountServiceAccountToken\s*:\s*true"),
                            "Set automountServiceAccountToken: false unless the application requires Kubernetes API access.",
                            "Kubernetes",
                            str(doc.get("metadata", {}).get("name", "unknown")),
                            ("CIS Kubernetes Benchmark",),
                        )
                    )
                if key_lower.endswith(".allowprivilegeescalation") and value is True:
                    findings.append(
                        _finding(
                            "K8S-SEC-005",
                            "Privilege escalation allowed",
                            "MEDIUM",
                            "A container may gain additional privileges through setuid/setgid binaries.",
                            path,
                            _line_for(text, r"allowPrivilegeEscalation\s*:\s*true"),
                            "Set allowPrivilegeEscalation: false unless explicitly required.",
                            "Kubernetes",
                            str(doc.get("metadata", {}).get("name", "unknown")),
                            ("CIS Kubernetes Benchmark",),
                        )
                    )
                if key_lower.endswith(".readonlyrootfilesystem") and value is False:
                    findings.append(
                        _finding(
                            "K8S-SEC-006",
                            "Writable container root filesystem",
                            "LOW",
                            "The container root filesystem is explicitly writable.",
                            path,
                            _line_for(text, r"readOnlyRootFilesystem\s*:\s*false"),
                            "Set readOnlyRootFilesystem: true and mount writable paths explicitly.",
                            "Kubernetes",
                            str(doc.get("metadata", {}).get("name", "unknown")),
                            ("CIS Kubernetes Benchmark",),
                        )
                    )
            if is_cf and key_path.endswith(".Properties.PublicReadAccess") and value is True:
                findings.append(
                    _finding(
                        "AWS-CF-001",
                        "CloudFormation resource allows public read",
                        "HIGH",
                        "A CloudFormation resource has a PublicReadAccess property enabled.",
                        path,
                        _line_for(text, r"PublicReadAccess\s*:\s*true"),
                        "Disable public read access and grant access through least-privilege identity policies.",
                        "AWS",
                        key_path.split(".")[1] if "." in key_path else None,
                        ("CIS AWS Foundations Benchmark",),
                    )
                )
        findings.extend(scan_aws_document(doc, path, text))
        findings.extend(scan_azure_document(doc, path, text))
        findings.extend(scan_gcp_document(doc, path, text))
        findings.extend(scan_kubernetes_document(doc, path, text))
    return findings


def _scan_terraform(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    checks = [
        (
            r"(?s)resource\s+\"aws_s3_bucket_acl\"\s+\"([^\"]+)\"\s*\{[^}]*acl\s*=\s*\"public-read(?:-write)?\"",
            "AWS-TF-001",
            "Public S3 bucket ACL",
            "HIGH",
            "An S3 bucket ACL grants public read or write access.",
            "Remove public ACLs and use S3 Block Public Access with least-privilege bucket policies.",
        ),
        (
            r"(?s)resource\s+\"aws_security_group_rule\"\s+\"([^\"]+)\"\s*\{[^}]*type\s*=\s*\"ingress\"[^}]*cidr_blocks\s*=\s*\[[^]]*\"0\.0\.0\.0/0\"",
            "AWS-TF-002",
            "Security group ingress open to the internet",
            "HIGH",
            "An ingress rule allows traffic from every IPv4 address.",
            "Restrict source CIDRs to trusted networks and limit exposed ports.",
        ),
        (
            r"(?s)resource\s+\"aws_ebs_volume\"\s+\"([^\"]+)\"\s*\{[^}]*encrypted\s*=\s*false",
            "AWS-TF-003",
            "EBS volume encryption disabled",
            "HIGH",
            "The EBS volume explicitly disables encryption.",
            "Enable EBS encryption; prefer the AWS-managed EBS KMS key when a customer-managed key is not required.",
        ),
        (
            r"(?s)resource\s+\"aws_db_instance\"\s+\"([^\"]+)\"\s*\{[^}]*storage_encrypted\s*=\s*false",
            "AWS-TF-004",
            "RDS storage encryption disabled",
            "HIGH",
            "The database explicitly disables storage encryption.",
            "Set storage_encrypted = true and verify encryption requirements for existing databases.",
        ),
        (
            r"(?s)resource\s+\"aws_s3_bucket\"\s+\"([^\"]+)\"\s*\{[^}]*force_destroy\s*=\s*true",
            "AWS-TF-005",
            "S3 bucket force destroy enabled",
            "LOW",
            "Terraform can destroy a non-empty bucket without an additional safeguard.",
            "Disable force_destroy for production buckets unless lifecycle automation explicitly requires it.",
        ),
    ]
    for pattern, rule_id, title, severity, message, remediation in checks:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(
                _finding(
                    rule_id,
                    title,
                    severity,
                    message,
                    path,
                    line,
                    remediation,
                    "AWS",
                    match.group(1),
                    ("CIS AWS Foundations Benchmark",),
                )
            )
    if re.search(
        r"(?s)resource\s+\"aws_iam_policy\".*?\bAction\s*=\s*\[?\s*\"\*\".*?\bResource\s*=\s*\[?\s*\"\*\"",
        text,
    ):
        match = re.search(r"resource\s+\"aws_iam_policy\"", text)
        line = text.count("\n", 0, match.start()) + 1 if match else 1
        findings.append(
            _finding(
                "IAM-TF-001",
                "Wildcard IAM policy permissions",
                "HIGH",
                "An IAM policy appears to allow all actions on all resources.",
                path,
                line,
                "Scope actions and resources to the minimum permissions required.",
                "AWS",
                compliance=("CIS AWS Foundations Benchmark",),
                category="iam",
            )
        )
    findings.extend(scan_terraform_document(path, text))
    return findings


def _scan_dockerfile(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    user_seen = False
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if re.match(r"(?i)^USER\s+", stripped):
            user_seen = True
        if re.match(r"(?i)^FROM\s+[^\s]+:(?:latest)?\s*(?:#.*)?$", stripped):
            findings.append(
                _finding(
                    "DOCKER-001",
                    "Unpinned container base image",
                    "MEDIUM",
                    "The Dockerfile uses latest or an untagged base image, making builds non-reproducible.",
                    path,
                    number,
                    "Pin a maintained base image to an explicit version or digest.",
                )
            )
        if re.match(r"(?i)^ADD\s+https?://", stripped):
            findings.append(
                _finding(
                    "DOCKER-002",
                    "Remote URL used with ADD",
                    "MEDIUM",
                    "Docker ADD downloads remote content without an explicit integrity check.",
                    path,
                    number,
                    "Download with a verified checksum in a controlled build step, or copy a vendored artifact.",
                )
            )
        if re.search(r"(?i)\b(password|secret|token|api[_-]?key)\s*=\s*[^$\s]+", stripped):
            findings.append(
                _finding(
                    "DOCKER-003",
                    "Possible hardcoded secret in Dockerfile",
                    "HIGH",
                    "A Dockerfile instruction appears to assign a literal secret value.",
                    path,
                    number,
                    "Use build secrets or runtime secret injection; do not bake credentials into image layers.",
                    category="secrets",
                )
            )
    if not user_seen:
        findings.append(
            _finding(
                "DOCKER-004",
                "No non-root USER instruction",
                "MEDIUM",
                "The Dockerfile does not declare a runtime user, so the image may run as root.",
                path,
                1,
                "Create/use a dedicated unprivileged user and add a USER instruction after setup.",
            )
        )
    return findings


def _scan_secrets(path: Path, text: str) -> list[Finding]:
    """Run hardened secret detection for a supported file."""
    return scan_secrets(path, text)


def scan_target(target: str, config: dict[str, Any]) -> ScanResult:
    files, skipped, warnings = discover(target, config["exclude"], config["max_file_bytes"])
    result = ScanResult(target=str(Path(target)), files_skipped=skipped, warnings=warnings)
    enabled = set(config.get("scanners", ["iac", "secrets"]))
    excluded_rules = set(config.get("exclude_rules", []))
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            current: list[Finding] = []
            if "secrets" in enabled:
                current.extend(_scan_secrets(path, text))
            if "iac" in enabled:
                if path.suffix.lower() == ".tf":
                    current.extend(_scan_terraform(path, text))
                elif (
                    path.name in {"Dockerfile", "Containerfile"}
                    or path.suffix.lower() == ".dockerfile"
                ):
                    current.extend(_scan_dockerfile(path, text))
                elif path.suffix.lower() in {".yaml", ".yml", ".json"}:
                    current.extend(_scan_yaml_json(path, text))
            if "dependencies" in enabled and path.name in {
                "requirements.txt",
                "package-lock.json",
            }:
                current.extend(scan_dependencies(path, text))
            # Prefer the Dockerfile-specific rule over the generic assignment rule
            # when both identify the same literal secret on the same source line.
            # Other secret rules (for example access-key IDs or private-key markers)
            # remain reportable because they may represent independent indicators.
            docker_secret_locations = {
                (finding.path, finding.line)
                for finding in current
                if finding.rule_id == "DOCKER-003"
            }
            filtered = [
                finding
                for finding in current
                if finding.rule_id not in excluded_rules
                and not (
                    finding.rule_id == "SEC-SECRET-002"
                    and (finding.path, finding.line) in docker_secret_locations
                )
            ]
            result.findings.extend(filtered)
            result.files_scanned += 1
        except (OSError, ValueError) as exc:
            result.errors.append(f"{path}: {exc}")
    return result
