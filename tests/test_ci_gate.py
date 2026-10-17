import json

import pytest

from scripts.ci_gate import EXIT_INPUT, EXIT_OK, EXIT_POLICY, evaluate_comparison, main


def _finding(rule_id="TEST-001", severity="HIGH", title="Example finding", path="main.tf"):
    return {"rule_id": rule_id, "severity": severity, "title": title, "path": path}


def _comparison(new=None, changed=None):
    new = new or []
    changed = changed or []
    return {
        "comparison": {
            "new_count": len(new),
            "changed_count": len(changed),
        },
        "new": new,
        "changed": changed,
    }


def test_existing_findings_do_not_appear_as_gate_violations():
    assert evaluate_comparison(_comparison(), "HIGH") == []


def test_new_high_and_critical_findings_fail_high_threshold():
    comparison = _comparison(
        new=[
            {"finding": _finding("TEST-HIGH", "HIGH")},
            {"finding": _finding("TEST-CRIT", "CRITICAL")},
        ]
    )
    violations = evaluate_comparison(comparison, "HIGH")
    assert len(violations) == 2
    assert all(item.startswith("NEW ") for item in violations)


def test_new_medium_finding_passes_high_threshold():
    comparison = _comparison(new=[{"finding": _finding(severity="MEDIUM")}])
    assert evaluate_comparison(comparison, "HIGH") == []


def test_severity_escalation_to_high_fails():
    comparison = _comparison(
        changed=[
            {
                "finding": _finding(severity="HIGH"),
                "changes": {"severity": {"previous": "MEDIUM", "current": "HIGH"}},
            }
        ]
    )
    violations = evaluate_comparison(comparison, "HIGH")
    assert len(violations) == 1
    assert violations[0].startswith("SEVERITY ESCALATION [MEDIUM -> HIGH]")


def test_severity_downgrade_does_not_fail():
    comparison = _comparison(
        changed=[
            {
                "finding": _finding(severity="MEDIUM"),
                "changes": {"severity": {"previous": "HIGH", "current": "MEDIUM"}},
            }
        ]
    )
    assert evaluate_comparison(comparison, "HIGH") == []


def test_non_severity_change_does_not_fail():
    comparison = _comparison(
        changed=[
            {"finding": _finding(), "changes": {"remediation": {"previous": "a", "current": "b"}}}
        ]
    )
    assert evaluate_comparison(comparison, "HIGH") == []


def test_invalid_threshold_is_rejected():
    with pytest.raises(ValueError, match="severity threshold"):
        evaluate_comparison(_comparison(), "URGENT")


def test_cli_returns_policy_exit_for_new_high_finding(tmp_path):
    report = tmp_path / "comparison.json"
    report.write_text(
        json.dumps(_comparison(new=[{"finding": _finding()}])), encoding="utf-8"
    )
    assert main([str(report), "--severity", "HIGH"]) == EXIT_POLICY


def test_cli_returns_success_for_medium_finding_at_high_threshold(tmp_path):
    report = tmp_path / "comparison.json"
    report.write_text(
        json.dumps(_comparison(new=[{"finding": _finding(severity="MEDIUM")} ])),
        encoding="utf-8",
    )
    assert main([str(report), "--severity", "HIGH"]) == EXIT_OK


def test_cli_returns_input_error_for_missing_report(tmp_path):
    assert main([str(tmp_path / "missing.json")]) == EXIT_INPUT


def test_cli_returns_input_error_for_malformed_report(tmp_path):
    report = tmp_path / "comparison.json"
    report.write_text("{not-json", encoding="utf-8")
    assert main([str(report)]) == EXIT_INPUT


def test_cli_rejects_comparison_without_required_arrays(tmp_path):
    report = tmp_path / "comparison.json"
    report.write_text(json.dumps({"comparison": {}}), encoding="utf-8")
    assert main([str(report)]) == EXIT_INPUT
