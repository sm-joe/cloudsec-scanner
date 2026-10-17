from pathlib import Path

from cloudsec_scanner.config import DEFAULT_CONFIG
from cloudsec_scanner.scanner import scan_target

FIXTURES = Path(__file__).parent / "fixtures"


def make_config(**overrides):
    config = {
        **DEFAULT_CONFIG,
        "exclude": [],
        "exclude_rules": [],
        "scanners": ["iac", "secrets"],
        "max_file_bytes": 2 * 1024 * 1024,
    }
    config.update(overrides)
    return config


def test_excluded_directory_is_not_scanned(tmp_path):
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "insecure.tf").write_text(
        'resource "aws_s3_bucket" "example" {\n  acl = "public-read"\n}\n',
        encoding="utf-8",
    )
    (tmp_path / "safe.tf").write_text(
        'resource "aws_s3_bucket" "example" {\n  acl = "private"\n}\n',
        encoding="utf-8",
    )

    result = scan_target(
        str(tmp_path),
        make_config(exclude=["vendor/"]),
    )

    assert result.files_scanned == 1
    assert result.errors == []
    assert all("vendor" not in finding.path for finding in result.findings)
    assert all(finding.rule_id != "AWS-TF-001" for finding in result.findings)


def test_disabling_iac_scanner_preserves_secret_scanning(tmp_path):
    target = tmp_path / "Dockerfile"
    target.write_text(
        "FROM nginx:latest\nENV API_KEY=example-secret-value\n",
        encoding="utf-8",
    )

    result = scan_target(
        str(target),
        make_config(scanners=["secrets"]),
    )

    rule_ids = {finding.rule_id for finding in result.findings}
    assert result.files_scanned == 1
    assert result.errors == []
    assert "DOCKER-001" not in rule_ids
    assert "DOCKER-003" not in rule_ids
    assert "SEC-SECRET-002" in rule_ids
    assert "example-secret-value" not in str([finding.to_dict() for finding in result.findings])


def test_empty_scanner_selection_scans_file_without_findings(tmp_path):
    target = tmp_path / "insecure.tf"
    target.write_text(
        'resource "aws_s3_bucket" "example" {\n  acl = "public-read"\n}\n',
        encoding="utf-8",
    )

    result = scan_target(str(target), make_config(scanners=[]))

    assert result.files_scanned == 1
    assert result.findings == []
    assert result.errors == []


def test_rule_exclusion_does_not_suppress_other_rules():
    target = FIXTURES / "terraform" / "insecure.tf"

    result = scan_target(
        str(target),
        make_config(exclude_rules=["AWS-TF-003"]),
    )

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "AWS-TF-003" not in rule_ids
    assert "AWS-TF-001" in rule_ids
    assert "AWS-TF-005" in rule_ids


def test_malformed_file_does_not_block_valid_file(tmp_path):
    (tmp_path / "broken.yaml").write_text(
        "kind: Pod\nmetadata: [unterminated\n",
        encoding="utf-8",
    )
    (tmp_path / "valid.yaml").write_text(
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata:\n"
        "  name: test-pod\n"
        "spec:\n"
        "  containers:\n"
        "    - name: app\n"
        "      image: nginx:1.27\n"
        "      securityContext:\n"
        "        privileged: true\n",
        encoding="utf-8",
    )

    result = scan_target(str(tmp_path), make_config())

    assert result.files_scanned == 1
    assert len(result.errors) == 1
    assert "broken.yaml" in result.errors[0]
    assert "K8S-SEC-001" in {finding.rule_id for finding in result.findings}
