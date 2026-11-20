"""Initial native IaC and secret scanners."""

from __future__ import annotations

import json
import re
from dataclasses import replace
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

from cloudsec_scanner.dependency_scan import scan_dependencies
from cloudsec_scanner.lockfiles import LOCK_NAMES
from cloudsec_scanner.discovery import discover
from cloudsec_scanner.models import Finding, ScanResult
from cloudsec_scanner.safe_input import validate_document, safe_yaml_documents, safe_json_document
from cloudsec_scanner.rules import (
    scan_aws_document,
    scan_azure_document,
    scan_gcp_document,
    scan_kubernetes_document,
    scan_terraform_document,
)
from cloudsec_scanner.secret_detection import scan_secrets
from cloudsec_scanner.terraform_plan import is_plan, scan_plan
from cloudsec_scanner.coverage import structured_coverage, assessment, kube_id

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


def _metadata_name(doc: dict) -> str:
    metadata = doc.get("metadata")
    return str(metadata.get("name", "unknown")) if isinstance(metadata, dict) else "unknown"


def _scan_yaml_json(path: Path, text: str, warnings: list[str] | None = None, assessments=None) -> list[Finding]:
    findings: list[Finding] = []
    try:
        if path.suffix.lower() == ".json":
            docs = [safe_json_document(text)]
        else:
            docs = safe_yaml_documents(text, cloudformation=True)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"malformed YAML/JSON: {exc}") from exc

    # Kubernetes List objects contain independently identified resources.
    pending = list(reversed(docs))
    while pending:
        doc = pending.pop()
        if isinstance(doc, dict) and doc.get("kind") == "List" and "apiVersion" in doc:
            items = doc.get("items")
            if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                raise ValueError("invalid Kubernetes List items")
            validate_document(doc)
            pending.extend(reversed(items))
            continue
        if is_plan(doc):
            plan_findings, plan_warnings = scan_plan(path, doc, assessments)
            findings.extend(plan_findings)
            if warnings is not None:
                warnings.extend(f"{path}: {warning}" for warning in sorted(set(plan_warnings)))
            continue
        if doc is None:
            continue
        if not isinstance(doc, (dict, list)):
            continue
        validate_document(doc)
        coverage = structured_coverage(path, doc)
        if assessments is not None:
            assessments.extend(coverage)
        first_finding = len(findings)
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
                            _metadata_name(doc),
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
                            _metadata_name(doc),
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
                            _metadata_name(doc),
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
                            _metadata_name(doc),
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
                            _metadata_name(doc),
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
                            _metadata_name(doc),
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
        for index in range(first_finding, len(findings)):
            item = findings[index]
            if item.provider == "Kubernetes" and isinstance(doc, dict):
                findings[index] = replace(item, resource_id=kube_id(doc))
            else:
                matches = [entry["resource_id"] for entry in coverage if item.resource and entry["resource_id"].endswith("." + item.resource)]
                if len(matches) == 1:
                    findings[index] = replace(item, resource_id=matches[0])
    return findings


def _scan_terraform(path: Path, text: str, assessments=None) -> list[Finding]:
    return scan_terraform_document(path, text, assessments)


def _scan_dockerfile(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    user_seen = False
    aliases: dict[str, bool] = {}
    stage_alias = None
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if re.match(r"(?i)^FROM\s+", stripped):
            tokens = stripped.split()
            tokens = [token for token in tokens[1:] if not token.startswith("--")]
            image = tokens[0] if tokens else ""
            inherited_stage = image.lower() in aliases
            user_seen = aliases.get(image.lower(), False)
            if len(tokens) >= 3 and tokens[1].lower() == "as":
                aliases[tokens[2].lower()] = user_seen
            stage_alias = tokens[2].lower() if len(tokens) >= 3 and tokens[1].lower() == "as" else None
        if re.match(r"(?i)^USER\s+", stripped):
            user = stripped.split()[1].split(":")[0]
            user_seen = bool(user) and user.lower() not in {"root", "0"} and not user.startswith("$")
            if stage_alias:
                aliases[stage_alias] = user_seen
        if re.match(r"(?i)^FROM\s+", stripped) and not inherited_stage and image != "scratch" and "@" not in image and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")):
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
    enabled = set(config.get("scanners", ["iac", "secrets"]))
    files, skipped, warnings = discover(target, config["exclude"], config["max_file_bytes"], include_secrets="secrets" in enabled)
    result = ScanResult(target=str(Path(target)), files_skipped=skipped, warnings=warnings)
    result.coverage_complete = bool(files) and bool(enabled) and not warnings
    # Security-policy changes make lifecycle comparisons non-equivalent.
    import hashlib
    profile = {
        "scanners": sorted(enabled),
        "exclude": sorted(config["exclude"]),
        "exclude_rules": sorted(config.get("exclude_rules", [])),
        "max_file_bytes": config["max_file_bytes"],
        "severity_overrides": config.get("severity_overrides", {}),
    }
    result.scan_profile = hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest()
    result.project_key = str(Path(target).resolve())
    excluded_rules = set(config.get("exclude_rules", []))
    for path in files:
        try:
            with path.open("rb") as stream:
                raw = stream.read(config["max_file_bytes"] + 1)
            if len(raw) > config["max_file_bytes"]:
                raise ValueError("file exceeded scan size limit")
            text = raw.decode("utf-8")
            current: list[Finding] = []
            if "secrets" in enabled:
                current.extend(_scan_secrets(path, text))
            # Policy-only YAML is not an infrastructure template. The active
            # configuration is independently validated by load_config.
            is_policy = False
            if path.name in {".cloudsec.yml", ".cloudsec.yaml", ".cloudsec-ci.yml"}:
                from cloudsec_scanner.config import DEFAULT_CONFIG
                try:
                    from cloudsec_scanner.safe_input import _preflight_yaml
                    policy_docs = []
                    loader = yaml.SafeLoader(text)
                    try:
                        while loader.check_node():
                            if policy_docs:
                                raise ValueError("multiple policy documents")
                            node = loader.get_node()
                            _preflight_yaml(node)
                            policy_docs.append(loader.construct_document(node))
                    finally:
                        loader.dispose()
                    is_policy = len(policy_docs) == 1 and isinstance(policy_docs[0], dict) and set(policy_docs[0]) <= set(DEFAULT_CONFIG)
                except (yaml.YAMLError, RecursionError, TypeError, ValueError):
                    pass
            if "iac" in enabled and path.name not in LOCK_NAMES and not is_policy:
                if path.suffix.lower() == ".tf":
                    current.extend(_scan_terraform(path, text, result.assessments))
                elif (
                    path.name in {"Dockerfile", "Containerfile"}
                    or path.suffix.lower() == ".dockerfile"
                ):
                    current.extend(_scan_dockerfile(path, text))
                    result.assessments.append(assessment(path, path.name, "Dockerfile", "EVALUATED"))
                elif path.suffix.lower() in {".yaml", ".yml", ".json"}:
                    current.extend(_scan_yaml_json(path, text, result.warnings, result.assessments))
            if "dependencies" in enabled and path.name in LOCK_NAMES:
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
        except (OSError, ValueError, RecursionError, TypeError, AttributeError) as exc:
            result.errors.append(f"{path}: scan failed ({type(exc).__name__}); check file syntax and scanner configuration")
            result.coverage_complete = False
    if any(a["status"] in {"UNSUPPORTED", "UNRESOLVED"} for a in result.assessments):
        result.coverage_complete = False
        result.warnings.append("Native IaC assessment includes unsupported or unresolved resources")
    if result.warnings:
        result.coverage_complete = False
    return result
