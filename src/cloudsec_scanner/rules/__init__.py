"""Provider- and platform-specific native security rules."""

from cloudsec_scanner.rules.aws import scan_aws_document
from cloudsec_scanner.rules.azure import scan_azure_document
from cloudsec_scanner.rules.gcp import scan_gcp_document
from cloudsec_scanner.rules.kubernetes import scan_kubernetes_document
from cloudsec_scanner.rules.terraform import scan_terraform_document

__all__ = [
    "scan_aws_document",
    "scan_azure_document",
    "scan_gcp_document",
    "scan_kubernetes_document",
    "scan_terraform_document",
]
