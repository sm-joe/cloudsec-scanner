"""Initial Azure Resource Manager template security rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cloudsec_scanner.models import Finding
from cloudsec_scanner.rules.common import finding

AZURE_BASELINE = ("Microsoft Cloud Security Benchmark",)


def scan_azure_document(doc: Any, path: Path, text: str) -> list[Finding]:
    if not isinstance(doc, dict):
        return []
    resources = doc.get("resources", [])
    if not isinstance(resources, list):
        return []
    findings: list[Finding] = []
    for index, resource in enumerate(resources):
        if not isinstance(resource, dict):
            continue
        resource_type = str(resource.get("type", "")).lower()
        name = str(resource.get("name", f"resources[{index}]"))
        properties = resource.get("properties", {})
        if not isinstance(properties, dict):
            properties = {}
        if resource_type == "microsoft.storage/storageaccounts":
            if properties.get("supportsHttpsTrafficOnly") is False:
                findings.append(
                    finding(
                        "AZ-STORAGE-001",
                        "Storage account permits HTTP",
                        "HIGH",
                        "The storage account explicitly allows non-HTTPS traffic.",
                        path,
                        text,
                        r"supportsHttpsTrafficOnly\s*['\"]?\s*:\s*false",
                        "Set supportsHttpsTrafficOnly to true and require TLS for storage access.",
                        provider="Azure",
                        resource=name,
                        compliance=AZURE_BASELINE,
                    )
                )
            if properties.get("allowBlobPublicAccess") is True:
                findings.append(
                    finding(
                        "AZ-STORAGE-002",
                        "Anonymous blob access enabled",
                        "HIGH",
                        "The storage account allows blob-level public access.",
                        path,
                        text,
                        r"allowBlobPublicAccess\s*['\"]?\s*:\s*true",
                        "Set allowBlobPublicAccess to false unless a reviewed public-content use case requires it.",
                        provider="Azure",
                        resource=name,
                        compliance=AZURE_BASELINE,
                    )
                )
            minimum_tls = str(properties.get("minimumTlsVersion", ""))
            if minimum_tls and minimum_tls not in {"TLS1_2", "TLS1_3"}:
                findings.append(
                    finding(
                        "AZ-STORAGE-003",
                        "Storage account uses weak TLS minimum",
                        "MEDIUM",
                        f"The storage account minimumTlsVersion is {minimum_tls}.",
                        path,
                        text,
                        r"minimumTlsVersion\s*['\"]?\s*:",
                        "Set minimumTlsVersion to TLS1_2 or a stronger supported version.",
                        provider="Azure",
                        resource=name,
                        compliance=AZURE_BASELINE,
                    )
                )
        elif resource_type == "microsoft.sql/servers/firewallrules":
            start_ip = properties.get("startIpAddress")
            end_ip = properties.get("endIpAddress")
            if start_ip == "0.0.0.0" and end_ip == "255.255.255.255":
                findings.append(
                    finding(
                        "AZ-SQL-001",
                        "SQL firewall allows all Azure services and IPs",
                        "HIGH",
                        "The SQL firewall rule spans the full IPv4 address range.",
                        path,
                        text,
                        r"startIpAddress\s*['\"]?\s*:\s*['\"]?0\.0\.0\.0",
                        "Replace the broad range with approved source IP ranges and private connectivity where possible.",
                        provider="Azure",
                        resource=name,
                        compliance=AZURE_BASELINE,
                    )
                )
    return findings
