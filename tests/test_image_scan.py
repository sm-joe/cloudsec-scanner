import json
from subprocess import CompletedProcess

import pytest

from cloudsec_scanner.image_scan import ImageScanError, scan_image


def test_maps_trivy_vulnerability_and_misconfiguration(monkeypatch):
    payload = {
        "Results": [
            {
                "Target": "alpine:3.20 (alpine 3.20.2)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-1234",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.0",
                        "FixedVersion": "3.0.1",
                        "Severity": "CRITICAL",
                        "Title": "Example vulnerability",
                        "PrimaryURL": "https://example.test/CVE-2026-1234",
                    }
                ],
                "Misconfigurations": [
                    {
                        "ID": "AVD-DS-0001",
                        "Title": "Container runs as root",
                        "Severity": "HIGH",
                        "Message": "The image may run as root.",
                        "Resolution": "Configure a non-root user.",
                    }
                ],
            }
        ]
    }
    monkeypatch.setattr("cloudsec_scanner.image_scan.shutil.which", lambda _: "trivy")
    monkeypatch.setattr(
        "cloudsec_scanner.image_scan.subprocess.run",
        lambda *args, **kwargs: CompletedProcess(args[0], 0, json.dumps(payload), ""),
    )

    result = scan_image("alpine:3.20")

    assert result.files_scanned == 1
    assert result.target == "image://alpine:3.20"
    assert {finding.rule_id for finding in result.findings} == {
        "IMG-VULN-CVE-2026-1234",
        "IMG-CONFIG-AVD-DS-0001",
    }
    assert next(f for f in result.findings if f.category == "vulnerability").severity == "CRITICAL"


def test_requires_trivy(monkeypatch):
    monkeypatch.setattr("cloudsec_scanner.image_scan.shutil.which", lambda _: None)
    with pytest.raises(ImageScanError, match="Trivy was not found"):
        scan_image("alpine:3.20")


def test_rejects_malformed_trivy_json(monkeypatch):
    monkeypatch.setattr("cloudsec_scanner.image_scan.shutil.which", lambda _: "trivy")
    monkeypatch.setattr(
        "cloudsec_scanner.image_scan.subprocess.run",
        lambda *args, **kwargs: CompletedProcess(args[0], 0, "{broken", ""),
    )
    with pytest.raises(ImageScanError, match="malformed JSON"):
        scan_image("alpine:3.20")


def test_rejects_failed_trivy_execution(monkeypatch):
    monkeypatch.setattr("cloudsec_scanner.image_scan.shutil.which", lambda _: "trivy")
    monkeypatch.setattr(
        "cloudsec_scanner.image_scan.subprocess.run",
        lambda *args, **kwargs: CompletedProcess(args[0], 1, "", "image not found"),
    )
    with pytest.raises(ImageScanError, match="Trivy image scan failed"):
        scan_image("missing:tag")
