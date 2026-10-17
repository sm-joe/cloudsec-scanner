import json

from cloudsec_scanner.comparison import compare_reports, finding_identity


def _finding(**overrides):
    item = {
        "rule_id": "IMG-VULN-CVE-2025-0001",
        "title": "Example vulnerability",
        "severity": "HIGH",
        "message": "Example description",
        "path": "image://example:latest",
        "line": None,
        "resource": "openssl@3.0.1",
        "category": "vulnerability",
        "provider": "Container",
        "remediation": "Upgrade openssl.",
        "evidence": "Image: example:latest; vulnerability: CVE-2025-0001",
    }
    item.update(overrides)
    return item


def _write_report(path, findings, target="image://example:latest"):
    path.write_text(json.dumps({"target": target, "findings": findings}), encoding="utf-8")


def test_identity_survives_package_version_and_severity_changes():
    original = _finding()
    updated = _finding(resource="openssl@3.0.2", severity="MEDIUM")
    assert finding_identity(original) == finding_identity(updated)


def test_identical_reports_classify_finding_as_persistent(tmp_path):
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    finding = _finding()
    _write_report(baseline, [finding])
    _write_report(current, [finding])

    result = compare_reports(baseline, current)
    assert result["comparison"] == {
        "baseline_target": "image://example:latest",
        "current_target": "image://example:latest",
        "baseline_finding_count": 1,
        "current_finding_count": 1,
        "new_count": 0,
        "resolved_count": 0,
        "persistent_count": 1,
        "changed_count": 0,
    }


def test_new_finding_is_classified_as_new(tmp_path):
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    _write_report(baseline, [_finding()])
    added = _finding(rule_id="IMG-VULN-CVE-2025-0002", resource="curl@8.0")
    _write_report(current, [_finding(), added])

    result = compare_reports(baseline, current)
    assert result["comparison"]["new_count"] == 1
    assert result["new"][0]["finding"]["rule_id"] == "IMG-VULN-CVE-2025-0002"


def test_missing_finding_is_classified_as_resolved(tmp_path):
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    removed = _finding(rule_id="IMG-VULN-CVE-2025-0002", resource="curl@8.0")
    _write_report(baseline, [_finding(), removed])
    _write_report(current, [_finding()])

    result = compare_reports(baseline, current)
    assert result["comparison"]["resolved_count"] == 1
    assert result["resolved"][0]["finding"]["rule_id"] == "IMG-VULN-CVE-2025-0002"


def test_severity_or_remediation_change_is_classified_as_changed(tmp_path):
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    _write_report(baseline, [_finding()])
    updated = _finding(severity="CRITICAL", remediation="Upgrade to a patched OpenSSL release.")
    _write_report(current, [updated])

    result = compare_reports(baseline, current)
    assert result["comparison"]["changed_count"] == 1
    changes = result["changed"][0]["changes"]
    assert changes["severity"] == {"previous": "HIGH", "current": "CRITICAL"}
    assert changes["remediation"] == {
        "previous": "Upgrade openssl.",
        "current": "Upgrade to a patched OpenSSL release.",
    }


def test_package_version_upgrade_keeps_identity_and_is_classified_as_changed(tmp_path):
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    before = _finding(resource="openssl@3.0.1")
    after = _finding(resource="openssl@3.0.2")
    assert finding_identity(before) == finding_identity(after)
    _write_report(baseline, [before])
    _write_report(current, [after])

    result = compare_reports(baseline, current)
    assert result["comparison"]["new_count"] == 0
    assert result["comparison"]["resolved_count"] == 0
    assert result["comparison"]["persistent_count"] == 0
    assert result["comparison"]["changed_count"] == 1
    assert result["changed"][0]["changes"]["resource"] == {
        "previous": "openssl@3.0.1",
        "current": "openssl@3.0.2",
    }
