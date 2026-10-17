"""Regression tests for the Stage 2 provider-specific rules library."""

import json
from pathlib import Path

from cloudsec_scanner.config import DEFAULT_CONFIG
from cloudsec_scanner.scanner import scan_target


def _scan(tmp_path: Path, filename: str, document: object) -> set[str]:
    target = tmp_path / filename
    if filename.endswith(".json"):
        target.write_text(json.dumps(document, indent=2), encoding="utf-8")
    else:
        import yaml

        target.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    config = dict(DEFAULT_CONFIG)
    config["exclude"] = []
    result = scan_target(str(target), config)
    assert not result.errors
    return {item.rule_id for item in result.findings}


def test_aws_cloudformation_bucket_requires_public_access_block_and_encryption(tmp_path):
    rules = _scan(tmp_path, "template.json", {
        "Resources": {
            "DataBucket": {"Type": "AWS::S3::Bucket", "Properties": {}},
        },
    })
    assert {"AWS-CF-002", "AWS-CF-003"} <= rules


def test_azure_storage_rules_detect_http_and_public_blob_access(tmp_path):
    rules = _scan(tmp_path, "azure.json", {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "resources": [{
            "type": "Microsoft.Storage/storageAccounts",
            "name": "unsafeStorage",
            "properties": {
                "supportsHttpsTrafficOnly": False,
                "allowBlobPublicAccess": True,
                "minimumTlsVersion": "TLS1_0",
            },
        }],
    })
    assert {"AZ-STORAGE-001", "AZ-STORAGE-002", "AZ-STORAGE-003"} <= rules


def test_gcp_firewall_detects_public_ssh(tmp_path):
    rules = _scan(tmp_path, "firewall.yaml", {
        "sourceRanges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
    })
    assert "GCP-FW-001" in rules


def test_kubernetes_host_namespaces_hostpath_and_wildcard_rbac(tmp_path):
    target = tmp_path / "unsafe.yaml"
    target.write_text("""apiVersion: v1
kind: Pod
metadata:
  name: unsafe
spec:
  hostPID: true
  hostIPC: true
  volumes:
    - name: host
      hostPath:
        path: /etc
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: unsafe-admin
rules:
  - apiGroups: [\"*\"]
    resources: [\"*\"]
    verbs: [\"*\"]
""", encoding="utf-8")
    config = dict(DEFAULT_CONFIG)
    config["exclude"] = []
    result = scan_target(str(target), config)
    rules = {item.rule_id for item in result.findings}
    assert not result.errors
    assert {"K8S-SEC-007", "K8S-SEC-008", "K8S-SEC-009", "K8S-RBAC-001"} <= rules


def test_terraform_azure_and_gcp_rules(tmp_path):
    target = tmp_path / "main.tf"
    target.write_text('''resource "azurerm_storage_account" "bad" {
  enable_https_traffic_only = false
  allow_nested_items_to_be_public = true
}
resource "google_storage_bucket_iam_member" "public" {
  bucket = "example"
  role = "roles/storage.objectViewer"
  member = "allUsers"
}
''', encoding="utf-8")
    config = dict(DEFAULT_CONFIG)
    config["exclude"] = []
    result = scan_target(str(target), config)
    rules = {item.rule_id for item in result.findings}
    assert not result.errors
    assert {"AZ-TF-001", "AZ-TF-002", "GCP-TF-001"} <= rules
