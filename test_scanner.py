from pathlib import Path

from cloudsec_scanner.config import DEFAULT_CONFIG
from cloudsec_scanner.scanner import scan_target

ROOT = Path(__file__).parent


def config_for(target: Path) -> dict:
    config = dict(DEFAULT_CONFIG)
    config["exclude"] = []
    config["max_file_bytes"] = 2 * 1024 * 1024
    return config


def test_terraform_rules_find_public_acl_and_unencrypted_volume():
    target = ROOT / "fixtures/terraform/insecure.tf"
    result = scan_target(str(target), config_for(target))
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "AWS-TF-001" in rule_ids
    assert "AWS-TF-003" in rule_ids
    assert result.files_scanned == 1


def test_kubernetes_security_context_rules():
    target = ROOT / "fixtures/kubernetes/insecure.yaml"
    result = scan_target(str(target), config_for(target))
    rule_ids = {finding.rule_id for finding in result.findings}
    assert {"K8S-SEC-001", "K8S-SEC-002", "K8S-SEC-003", "K8S-SEC-004", "K8S-SEC-005", "K8S-SEC-006"} <= rule_ids


def test_dockerfile_detects_root_default_and_literal_secret_without_leaking_value():
    target = ROOT / "fixtures/docker/Dockerfile"
    result = scan_target(str(target), config_for(target))
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "DOCKER-001" in rule_ids
    assert "DOCKER-003" in rule_ids
    assert "DOCKER-004" in rule_ids
    assert all("plaintext-secret-value" not in str(f.to_dict()) for f in result.findings)


def test_cloudformation_json_is_parsed():
    target = ROOT / "fixtures/cloudformation/insecure.json"
    result = scan_target(str(target), config_for(target))
    assert any(f.rule_id == "AWS-CF-001" for f in result.findings)


def test_malformed_yaml_is_scan_error(tmp_path):
    target = tmp_path / "broken.yaml"
    target.write_text("kind: Pod\nmetadata: [unterminated\n", encoding="utf-8")
    result = scan_target(str(target), config_for(target))
    assert result.errors
    assert result.files_scanned == 0


def test_dockerfile_secret_assignment_is_not_reported_twice():
    target = ROOT / "fixtures/docker/Dockerfile"
    result = scan_target(str(target), config_for(target))
    secret_findings = [
        finding for finding in result.findings
        if finding.path == str(target)
        and finding.line == 2
        and finding.category == "secrets"
    ]
    assert [finding.rule_id for finding in secret_findings] == ["DOCKER-003"]


def test_all_supported_fixture_files_are_scanned():
    target = ROOT / "fixtures"
    result = scan_target(str(target), config_for(target))
    assert result.files_scanned == 4
    assert result.files_skipped == 0
    assert result.errors == []
    scanned_paths = {finding.path for finding in result.findings}
    assert str(target / "cloudformation/insecure.json") in scanned_paths
    assert str(target / "docker/Dockerfile") in scanned_paths
    assert str(target / "kubernetes/insecure.yaml") in scanned_paths
    assert str(target / "terraform/insecure.tf") in scanned_paths

