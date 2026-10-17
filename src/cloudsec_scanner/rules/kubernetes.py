"""Additional Kubernetes pod and RBAC security rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cloudsec_scanner.models import Finding
from cloudsec_scanner.rules.common import finding, mappings

K8S_BASELINE = ("CIS Kubernetes Benchmark",)


def _walk(value: Any, path: str = ""):
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield child_path, child
            yield from _walk(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, f"{path}[{index}]")


def scan_kubernetes_document(doc: Any, path: Path, text: str) -> list[Finding]:
    if not isinstance(doc, dict) or not ("apiVersion" in doc and "kind" in doc):
        return []
    kind = str(doc.get("kind", ""))
    metadata = doc.get("metadata", {})
    name = str(metadata.get("name", "unknown")) if isinstance(metadata, dict) else "unknown"
    findings: list[Finding] = []
    flattened = list(_walk(doc))
    for key_path, value in flattened:
        lowered = key_path.lower()
        if lowered.endswith(".hostpid") and value is True:
            findings.append(
                finding(
                    "K8S-SEC-007",
                    "Pod shares host PID namespace",
                    "HIGH",
                    "The pod can inspect host processes, weakening workload isolation.",
                    path,
                    text,
                    r"hostPID\s*:\s*true",
                    "Disable hostPID unless a documented privileged workload requires it.",
                    provider="Kubernetes",
                    resource=name,
                    compliance=K8S_BASELINE,
                )
            )
        if lowered.endswith(".hostipc") and value is True:
            findings.append(
                finding(
                    "K8S-SEC-008",
                    "Pod shares host IPC namespace",
                    "MEDIUM",
                    "The pod shares the node IPC namespace with potential cross-workload exposure.",
                    path,
                    text,
                    r"hostIPC\s*:\s*true",
                    "Disable hostIPC unless explicitly required.",
                    provider="Kubernetes",
                    resource=name,
                    compliance=K8S_BASELINE,
                )
            )
        if lowered.endswith(".hostpath") and isinstance(value, (dict, str)):
            findings.append(
                finding(
                    "K8S-SEC-009",
                    "Host filesystem path mounted",
                    "HIGH",
                    "A hostPath volume can expose node files or permit host compromise if writable.",
                    path,
                    text,
                    r"hostPath\s*:",
                    "Avoid hostPath; use a dedicated volume type and restrict mounts to read-only when unavoidable.",
                    provider="Kubernetes",
                    resource=name,
                    compliance=K8S_BASELINE,
                )
            )
        if (
            lowered.endswith(".capabilities.add")
            and isinstance(value, list)
            and any(str(cap).upper() == "ALL" for cap in value)
        ):
            findings.append(
                finding(
                    "K8S-SEC-010",
                    "All Linux capabilities added",
                    "HIGH",
                    "The container requests every Linux capability, substantially increasing privilege.",
                    path,
                    text,
                    r"capabilities\s*:\s*",
                    "Drop all capabilities by default and add only specifically required capabilities.",
                    provider="Kubernetes",
                    resource=name,
                    compliance=K8S_BASELINE,
                )
            )
    if kind in {"ClusterRole", "Role"}:
        for rule in mappings(doc.get("rules")):
            if "*" in rule.get("verbs", []) or "*" in rule.get("resources", []):
                findings.append(
                    finding(
                        "K8S-RBAC-001",
                        "Wildcard Kubernetes RBAC permission",
                        "HIGH",
                        f"{kind} {name} grants wildcard verbs or resources.",
                        path,
                        text,
                        r"verbs\s*:\s*|resources\s*:\s*",
                        "Replace wildcard verbs/resources with the minimum permissions needed by the subject.",
                        provider="Kubernetes",
                        resource=name,
                        category="iam",
                        compliance=K8S_BASELINE,
                    )
                )
                break
    return findings
