"""Additional provider-aware Terraform security checks (initial pattern-based coverage)."""

from __future__ import annotations

import re
from pathlib import Path

from cloudsec_scanner.models import Finding
from cloudsec_scanner.rules.common import finding


def scan_terraform_document(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    checks = [
        (
            r'(?s)resource\s+"azurerm_storage_account"\s+"([^\"]+)"\s*\{[^}]*enable_https_traffic_only\s*=\s*false',
            "AZ-TF-001",
            "Azure storage account permits HTTP",
            "HIGH",
            "The storage account explicitly disables HTTPS-only traffic.",
            "Set enable_https_traffic_only = true and require encrypted transport.",
            "Azure",
            "Microsoft Cloud Security Benchmark",
        ),
        (
            r'(?s)resource\s+"azurerm_storage_account"\s+"([^\"]+)"\s*\{[^}]*allow_nested_items_to_be_public\s*=\s*true',
            "AZ-TF-002",
            "Azure storage allows public nested items",
            "HIGH",
            "The storage account allows containers or blobs to be configured for public access.",
            "Set allow_nested_items_to_be_public = false unless a reviewed public-content use case requires it.",
            "Azure",
            "Microsoft Cloud Security Benchmark",
        ),
        (
            r'(?s)resource\s+"google_storage_bucket_iam_(?:member|binding|policy)"\s+"([^\"]+)"\s*\{[^}]*(?:member|members)\s*=\s*(?:\[\s*)?"allUsers"',
            "GCP-TF-001",
            "GCP storage bucket grants public access",
            "HIGH",
            "A bucket IAM policy grants access to allUsers.",
            "Remove allUsers/allAuthenticatedUsers bindings and grant access to named principals only.",
            "GCP",
            "Google Cloud security best practices",
        ),
        (
            r'(?s)resource\s+"google_compute_firewall"\s+"([^\"]+)"\s*\{[^}]*source_ranges\s*=\s*\[[^]]*"0\.0\.0\.0/0"[^}]*allowed\s*\{[^}]*ports\s*=\s*\[[^]]*"(?:22|3389)"',
            "GCP-TF-002",
            "GCP firewall exposes administrative port",
            "HIGH",
            "A firewall rule exposes SSH or RDP to all IPv4 addresses.",
            "Restrict source_ranges and expose administrative ports only to approved networks.",
            "GCP",
            "Google Cloud security best practices",
        ),
    ]
    for pattern, rule_id, title, severity, message, remediation, provider, compliance in checks:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            findings.append(
                finding(
                    rule_id,
                    title,
                    severity,
                    message,
                    path,
                    text,
                    re.escape(match.group(1)),
                    remediation,
                    provider=provider,
                    resource=match.group(1),
                    compliance=(compliance,),
                )
            )
    return findings
