"""Regression tests for persistent scan history."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cloudsec_scanner.cli import EXIT_OK, main
from cloudsec_scanner.history import (
    HistoryError,
    get_scan,
    get_trends,
    list_scans,
    record_scan,
)
from cloudsec_scanner.models import Finding, ScanResult


def finding(
    rule_id: str = "TEST-001",
    severity: str = "HIGH",
    title: str = "Test finding",
    path: str = "main.tf",
    resource: str = "example",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        message="A synthetic test finding.",
        path=path,
        line=1,
        resource=resource,
        category="misconfiguration",
        provider="AWS",
        remediation="Fix the synthetic issue.",
    )


def result(target: str, findings: list[Finding], errors: list[str] | None = None) -> ScanResult:
    return ScanResult(
        target=target,
        findings=findings,
        files_scanned=1,
        files_skipped=0,
        errors=errors or [],
    )


def test_history_persists_scans_and_tracks_lifecycle(tmp_path):
    database = tmp_path / "history.db"
    first = record_scan(database, result(".", [finding()]))
    second = record_scan(
        database,
        result(".", [finding(), finding(rule_id="TEST-002", title="Another finding")]),
    )

    assert first["id"] == 1
    assert first["lifecycle"]["status"] == "initial"
    assert first["lifecycle"]["new_count"] is None
    assert second["id"] == 2
    assert second["lifecycle"]["new_count"] == 1
    assert second["lifecycle"]["persistent_count"] == 1

    scans = list_scans(database)
    assert len(scans) == 2
    assert scans[0]["id"] == 2
    assert scans[1]["id"] == 1
    assert scans[0]["severity_counts"]["HIGH"] == 2

    detail = get_scan(database, 2)
    assert detail["findings"][1]["rule_id"] in {"TEST-001", "TEST-002"}
    assert detail["lifecycle"]["new_count"] == 1


def test_history_tracks_severity_escalation_as_changed(tmp_path):
    database = tmp_path / "history.db"
    record_scan(database, result(".", [finding(severity="MEDIUM")]))
    second = record_scan(database, result(".", [finding(severity="CRITICAL")]))

    assert second["lifecycle"]["changed_count"] == 1
    assert second["lifecycle"]["severity_escalation_count"] == 1


def test_incomplete_scan_is_not_used_as_lifecycle_baseline(tmp_path):
    database = tmp_path / "history.db"
    record_scan(database, result(".", [finding()]))
    incomplete = record_scan(database, result(".", [], errors=["failed to parse file"]))
    after = record_scan(database, result(".", [finding()]))

    assert incomplete["lifecycle"]["status"] == "incomplete"
    assert after["lifecycle"]["new_count"] == 0
    assert after["lifecycle"]["persistent_count"] == 1


def test_history_trends_filter_by_target_and_window(tmp_path):
    database = tmp_path / "history.db"
    record_scan(database, result(".", [finding()]))
    record_scan(database, result("other-target", []))

    trends = get_trends(database, days=30, target=".")
    assert len(trends) == 1
    assert trends[0]["target"] == "."


def test_history_rejects_invalid_limits_and_unknown_run(tmp_path):
    database = tmp_path / "history.db"
    with pytest.raises(HistoryError, match="limit"):
        list_scans(database, limit=0)
    with pytest.raises(HistoryError, match="not found"):
        get_scan(database, 999)


def test_scan_cli_records_history_and_history_commands_render_json(tmp_path, capsys):
    database = tmp_path / "history.db"
    fixture = Path(__file__).parent / "fixtures" / "terraform" / "insecure.tf"

    code = main(
        [
            "scan",
            str(fixture),
            "--history-db",
            str(database),
            "--no-fail",
            "--format",
            "json",
        ]
    )
    assert code == EXIT_OK
    assert "Scan history: run #1" in capsys.readouterr().err

    code = main(
        [
            "history",
            "list",
            "--database",
            str(database),
            "--format",
            "json",
        ]
    )
    assert code == EXIT_OK
    listed = json.loads(capsys.readouterr().out)
    assert len(listed) == 1
    assert listed[0]["id"] == 1

    code = main(
        [
            "history",
            "show",
            "1",
            "--database",
            str(database),
            "--format",
            "json",
        ]
    )
    assert code == EXIT_OK
    shown = json.loads(capsys.readouterr().out)
    assert shown["finding_count"] >= 1

    code = main(
        [
            "history",
            "trends",
            "--database",
            str(database),
            "--days",
            "30",
            "--format",
            "json",
        ]
    )
    assert code == EXIT_OK
    trends = json.loads(capsys.readouterr().out)
    assert len(trends) == 1
