import pytest

from cloudsec_scanner.secret_detection import scan_secrets


@pytest.mark.parametrize(
    "text,expected_rule",
    [
        ("AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF", "SEC-SECRET-001"),
        ("password = 'super-secret-password-123'", "SEC-SECRET-002"),
        ("client_secret: 'client-secret-value-123'", "SEC-SECRET-002"),
        ("api_key = api-key-value-123456", "SEC-SECRET-002"),
        ("aws_secret_access_key=aws-secret-value-123", "SEC-SECRET-002"),
        ("-----BEGIN RSA PRIVATE KEY-----", "SEC-SECRET-003"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "SEC-SECRET-003"),
        ("ghp_abcdefghijklmnopqrstuvwxyz1234567890", "SEC-SECRET-004"),
    ],
)
def test_detects_credential_patterns_without_leaking_values(tmp_path, text, expected_rule):
    path = tmp_path / "source.tf"
    findings = scan_secrets(path, text)

    assert expected_rule in {finding.rule_id for finding in findings}
    assert text not in str([finding.to_dict() for finding in findings])

    for finding in findings:
        assert finding.evidence
        assert "[REDACTED]" in finding.evidence or "PRIVATE KEY MARKER" in finding.evidence


@pytest.mark.parametrize(
    "text",
    [
        'password = "changeme"',
        "token: placeholder",
        "api_key=${API_KEY}",
        "client_secret: '{{ secret_value }}'",
        "password = example",
        "token = your-token",
    ],
)
def test_ignores_common_placeholder_values(tmp_path, text):
    findings = scan_secrets(tmp_path / "config.yaml", text)

    assert findings == []


def test_detects_multiple_secrets_on_different_lines(tmp_path):
    text = 'password = "first-secret-value-123"\napi_key = "second-secret-value-456"\n'

    findings = scan_secrets(tmp_path / "config.yaml", text)

    assert len(findings) == 2
    assert {finding.line for finding in findings} == {1, 2}
    assert all("[REDACTED]" in finding.evidence for finding in findings)


def test_secret_detection_is_case_insensitive_for_assignment_names(tmp_path):
    findings = scan_secrets(
        tmp_path / "config.yaml",
        'CLIENT_SECRET="a-long-client-secret-value"',
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-SECRET-002"
    assert "a-long-client-secret-value" not in findings[0].evidence


def test_empty_input_returns_no_findings(tmp_path):
    assert scan_secrets(tmp_path / "empty.tf", "") == []


def test_findings_include_path_line_and_remediation(tmp_path):
    path = tmp_path / "main.tf"
    findings = scan_secrets(
        path,
        "# sample\npassword = 'realistic-secret-value-123'\n",
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.path == str(path)
    assert finding.line == 2
    assert finding.remediation
    assert finding.severity == "HIGH"
