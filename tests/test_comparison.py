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


def test_comparison_classifies_new_resolved_persistent_and_changed(tmp_path):
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    old = _finding()
    resolved = _finding(rule_id="IMG-VULN-CVE-2025-0002", resource="curl@8.0")
    persistent = _finding(rule_id="IMG-VULN-CVE-2025-0003", resource="zlib@1.2")
    changed_old = _finding(rule_id="IMG-VULN-CVE-2025-0004", resource="libxml2@2.9")
    changed_new = _finding(
        rule_id="IMG-VULN-CVE-2025-0004", resource="libxml2@2.10", severity="MEDIUM"
    )
    new = _finding(rule_id="IMG-VULN-CVE-2025-0005", resource="bash@5.2")
    _write_report(baseline, [old, resolved, persistent, changed_old])
    _write_report(current, [old, persistent, changed_new, new])

    result = compare_reports(baseline, current)
    summary = result["comparison"]
    assert summary["new_count"] == 1
    assert summary["resolved_count"] == 1
    assert summary["persistent_count"] == 2
    assert summary["changed_count"] == 1
