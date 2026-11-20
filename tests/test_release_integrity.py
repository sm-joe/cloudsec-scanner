import sys
from pathlib import Path

import pytest

from cloudsec_scanner.dependency_scan import scan_dependencies
from cloudsec_scanner.image_scan import scan_image, _run_json, ImageScanError


def test_connected_aliases_keep_highest_severity_and_all_ids():
    advisories = [
        {"id": "PYSEC-1", "aliases": ["GHSA-1"], "database_specific": {"severity": "LOW"}},
        {"id": "GHSA-1", "aliases": ["CVE-2024-1234"], "database_specific": {"severity": "CRITICAL"}},
        {"id": "CVE-2024-1234", "database_specific": {"severity": "MEDIUM"}},
        {"id": "UNRELATED", "database_specific": {"severity": "MEDIUM"}},
    ]
    for ordered in (advisories, list(reversed(advisories))):
        findings = scan_dependencies(Path("requirements.txt"), "requests==2.19.0", query_batch=lambda q: [{"vulns": ordered}])
        assert len(findings) == 2
        merged = next(f for f in findings if f.severity == "CRITICAL")
        assert merged.evidence == "OSV: CVE-2024-1234"
        assert set(merged.advisory_ids) == {"PYSEC-1", "GHSA-1", "CVE-2024-1234"}
        assert len(merged.references) == 3


@pytest.mark.parametrize("document", [
    {"Results": []},
    {"Results": [{}]},
    {"Results": [{"Target": "image", "Vulnerabilities": {}}]},
    {"Results": [{"Target": "image", "Vulnerabilities": [{}]}]},
    {"Results": [{"Target": "image"}]},
])
def test_trivy_invalid_clean_fails(monkeypatch, document):
    monkeypatch.setattr("cloudsec_scanner.image_scan._run_json", lambda *a, **kw: document)
    with pytest.raises(ImageScanError):
        scan_image("alpine:3", trivy_path="trivy")


def test_clean_trivy_and_allowlisted_provenance(monkeypatch):
    digest = "sha256:" + "a" * 64
    payload = {"Metadata": {"ImageID": digest, "RepoDigests": ["alpine@" + digest], "OS": {"Family": "alpine"}, "ImageConfig": {"Env": ["private"]}},
               "Results": [{"Target": "alpine", "Class": "os-pkgs", "Type": "alpine"}]}
    monkeypatch.setattr("cloudsec_scanner.image_scan._run_json", lambda cmd, *a, **kw: {"Version": "0.70.0", "VulnerabilityDB": {"UpdatedAt": "2026-01-01"}} if cmd[1] == "version" else payload)
    result = scan_image("alpine:3", trivy_path="trivy")
    assert result.coverage_complete
    assert not result.findings
    assert result.provenance["image_digests"] == [digest]
    assert result.provenance["version"] == "0.70.0"
    assert "private" not in str(result.to_dict())


@pytest.mark.parametrize("code, message", [
    ("print('x' * 10000)", "exceeded bounds"),
    ("print('not json')", "malformed JSON"),
    ("raise SystemExit(2)", "failed"),
    ("import time; time.sleep(10)", "timed out"),
])
def test_real_subprocess_failure(code, message):
    with pytest.raises(ImageScanError, match=message):
        _run_json([sys.executable, "-c", code], 1, limit=2048)
