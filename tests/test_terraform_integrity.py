"""Regression coverage for resource-scoped HCL parsing."""
import pytest

from cloudsec_scanner.config import load_config
from cloudsec_scanner.scanner import scan_target


def scan(tmp_path, source):
    path = tmp_path / "main.tf"
    path.write_text(source, encoding="utf-8")
    return scan_target(str(path), load_config(None))


def test_reordered_properties_and_nested_blocks(tmp_path):
    result = scan(tmp_path, '''
resource "aws_security_group_rule" "public" {
  cidr_blocks = ["0.0.0.0/0"]
  type = "ingress"
}
resource "aws_ebs_volume" "unencrypted" {
  tags = { Name = "test" }
  encrypted = false
}
''')
    assert not result.errors
    assert {"AWS-TF-002", "AWS-TF-003"} <= {f.rule_id for f in result.findings}


def test_comments_and_string_literals_do_not_trigger_rules(tmp_path):
    result = scan(tmp_path, '''
# resource "aws_ebs_volume" "commented" { encrypted = false }
resource "aws_ebs_volume" "safe" {
  encrypted = true
  tags = { Description = "encrypted = false" }
}
''')
    assert not result.errors
    assert not result.findings


def test_malformed_hcl_fails_closed(tmp_path):
    result = scan(tmp_path, 'resource "aws_ebs_volume" "invalid" {')
    assert result.errors
    assert not result.coverage_complete


@pytest.mark.parametrize("effect, expected", [("Allow", True), ("Deny", False)])
def test_iam_json_policy(tmp_path, effect, expected):
    result = scan(tmp_path, '''
resource "aws_iam_policy" "example" {
  policy = <<EOF
{"Statement":[{"Effect":"%s","Action":"*","Resource":"*"}]}
EOF
}
''' % effect)
    assert not result.errors
    assert ("IAM-TF-001" in {f.rule_id for f in result.findings}) == expected


def test_ipv6_and_port_range(tmp_path):
    result = scan(tmp_path, '''
resource "google_compute_firewall" "public" {
  allow { protocol = "tcp"\n ports = ["20-30"] }
  source_ranges = ["::/0"]
}
''')
    assert not result.errors
    assert "GCP-TF-002" in {f.rule_id for f in result.findings}
