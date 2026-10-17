"""Initial Google Cloud deployment/configuration security rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cloudsec_scanner.models import Finding
from cloudsec_scanner.rules.common import finding

GCP_BASELINE = ("Google Cloud security best practices",)


def scan_gcp_document(doc: Any, path: Path, text: str) -> list[Finding]:
    if not isinstance(doc, dict):
        return []
    findings: list[Finding] = []
    # Google Cloud Deployment Manager and Terraform-export-like YAML/JSON shapes.
    resources = doc.get("resources", [])
    if isinstance(resources, list):
        for index, resource in enumerate(resources):
            if not isinstance(resource, dict):
                continue
            resource_type = str(resource.get("type", "")).lower()
            name = str(resource.get("name", f"resources[{index}]"))
            properties = resource.get("properties", {})
            if not isinstance(properties, dict):
                properties = {}
            if "storage" in resource_type and "bucket" in resource_type:
                if properties.get("iamConfiguration", {}).get("publicAccessPrevention") == "inherited":
                    findings.append(finding(
                        "GCP-STORAGE-001", "Bucket public access prevention not enforced", "HIGH",
                        "The bucket inherits public-access settings instead of enforcing prevention.", path, text,
                        r"publicAccessPrevention\s*:\s*['\"]?inherited",
                        "Set publicAccessPrevention to enforced and review bucket IAM bindings.",
                        provider="GCP", resource=name, compliance=GCP_BASELINE,
                    ))
                if properties.get("uniformBucketLevelAccess") is False:
                    findings.append(finding(
                        "GCP-STORAGE-002", "Uniform bucket-level access disabled", "MEDIUM",
                        "Object ACLs may be used alongside IAM, complicating access control review.", path, text,
                        r"uniformBucketLevelAccess\s*:\s*false",
                        "Enable uniform bucket-level access and manage permissions through IAM.",
                        provider="GCP", resource=name, compliance=GCP_BASELINE,
                    ))
    # Kubernetes-style GCP firewall resources are not reliably represented by one schema;
    # only flag explicit broad source ranges paired with administrative ports.
    source_ranges = doc.get("sourceRanges")
    allowed = doc.get("allowed")
    if isinstance(source_ranges, list) and "0.0.0.0/0" in source_ranges:
        ports: set[str] = set()
        for item in allowed if isinstance(allowed, list) else []:
            if isinstance(item, dict):
                values = item.get("ports", [])
                if isinstance(values, list):
                    ports.update(str(port) for port in values)
        if ports.intersection({"22", "3389"}):
            findings.append(finding(
                "GCP-FW-001", "GCP firewall exposes administrative port", "HIGH",
                "A firewall rule allows SSH or RDP from all IPv4 addresses.", path, text,
                r"sourceRanges\s*:\s*\[[^]]*0\.0\.0\.0/0",
                "Restrict source ranges to approved networks and use controlled administrative access.",
                provider="GCP", compliance=GCP_BASELINE,
            ))
    return findings
