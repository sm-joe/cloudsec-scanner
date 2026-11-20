from cloudsec_scanner.scanner import scan_target
from cloudsec_scanner.config import load_config


def test_windows_crlf_terraform(tmp_path):
    path = tmp_path / "main.tf"
    path.write_bytes(b'resource "aws_ebs_volume" "example" {\r\n  encrypted = false\r\n}\r\n')
    result = scan_target(str(path), load_config(None))
    assert not result.errors
    assert any(f.rule_id == "AWS-TF-003" for f in result.findings)
