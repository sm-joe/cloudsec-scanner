from pathlib import Path

from cloudsec_scanner.config import DEFAULT_CONFIG
from cloudsec_scanner.scanner import scan_target

ROOT = Path(__file__).parent
FIXTURES = ROOT / "fixtures"


def make_config(**overrides) -> dict:
    """Return an isolated scanner configuration for each test."""
    config = {
        **DEFAULT_CONFIG,
        "exclude": [],
        "exclude_rules": [],
        "scanners": ["iac", "secrets"],
        "max_file_bytes": 2 * 1024 * 1024,
    }
    config.update(overrides)
    return config


def test_fixture_rule_ids_are_regression_covered():
    cases = {
        "terraform/insecure.tf": {
            "AWS-TF-001",
            "AWS-TF-003",
            "AWS-TF-005",
        },
        "kubernetes/insecure.yaml": {
            "K8S-SEC-001",
            "K8S-SEC-002",
            "K8S-SEC-003",
            "K8S-SEC-004",
            "K8S-SEC-005",
            "K8S-SEC-006",
        },
        "cloudformation/insecure.json": {
            "AWS-CF-001",
            "AWS-CF-002",
            "AWS-CF-003",
        },
        "docker/Dockerfile": {
            "DOCKER-001",
            "DOCKER-003",
            "DOCKER-004",
        },
    }

    for relative_path, expected_rule_ids in cases.items():
        result = scan_target(str(FIXTURES / relative_path), make_config())
        actual_rule_ids = {finding.rule_id for finding in result.findings}

        assert not result.errors, f"{relative_path}: {result.errors}"
        assert expected_rule_ids <= actual_rule_ids, (
            f"{relative_path}: missing rules {sorted(expected_rule_ids - actual_rule_ids)}"
        )


def test_findings_have_valid_core_metadata():
    result = scan_target(str(FIXTURES), make_config())

    assert not result.errors
    assert result.findings

    for finding in result.findings:
        assert finding.rule_id
        assert finding.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert finding.path
        assert finding.line >= 1
        assert finding.remediation


def test_excluded_rule_is_removed_without_suppressing_other_findings():
    target = FIXTURES / "terraform" / "insecure.tf"
    result = scan_target(
        str(target),
        make_config(exclude_rules=["AWS-TF-003"]),
    )
    rule_ids = {finding.rule_id for finding in result.findings}

    assert "AWS-TF-003" not in rule_ids
    assert "AWS-TF-001" in rule_ids
    assert "AWS-TF-005" in rule_ids


def test_empty_scanner_list_produces_no_findings():
    target = FIXTURES / "terraform" / "insecure.tf"
    result = scan_target(str(target), make_config(scanners=[]))

    assert result.files_scanned == 1
    assert result.findings == []
    assert result.errors == []


def test_malformed_file_does_not_prevent_scanning_valid_file(tmp_path):
    (tmp_path / "broken.yaml").write_text(
        "kind: Pod\nmetadata: [unterminated\n",
        encoding="utf-8",
    )
    (tmp_path / "valid.yaml").write_text(
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata:\n"
        "  name: regression-pod\n"
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


def test_docker_secret_is_redacted_and_not_reported_twice():
    target = FIXTURES / "docker" / "Dockerfile"
    result = scan_target(str(target), make_config())
    serialized_findings = str([finding.to_dict() for finding in result.findings])
    secret_related = [
        finding
        for finding in result.findings
        if finding.rule_id in {"DOCKER-003", "SEC-SECRET-002"}
    ]

    assert "plaintext-secret-value" not in serialized_findings
    assert len(secret_related) == 1
    assert secret_related[0].rule_id == "DOCKER-003"
