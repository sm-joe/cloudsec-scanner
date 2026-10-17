"""Persistent local scan history and posture trend queries."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cloudsec_scanner.comparison import finding_identity
from cloudsec_scanner.models import SEVERITY_ORDER, ScanResult


class HistoryError(RuntimeError):
    """Raised when scan history cannot be read or written safely."""


def default_history_db_path(override: str | None = None) -> Path:
    """Return the configured history database path for the current user."""
    if override:
        return Path(override).expanduser()
    configured = os.environ.get("CLOUDSEC_HISTORY_DB")
    if configured:
        return Path(configured).expanduser()

    if sys.platform == "win32":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return root / "CloudSecScanner" / "history.db"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "CloudSecScanner" / "history.db"
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return state_home / "cloudsec-scanner" / "history.db"


def _connect(database: str | Path) -> sqlite3.Connection:
    path = Path(database).expanduser()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        _ensure_schema(connection)
        return connection
    except (OSError, sqlite3.Error) as exc:
        raise HistoryError(f"could not open scan history database {path}: {exc}") from exc


def _ensure_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT NOT NULL,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL CHECK (scan_type IN ('scan', 'image')),
            files_scanned INTEGER NOT NULL,
            files_skipped INTEGER NOT NULL,
            finding_count INTEGER NOT NULL,
            severity_counts_json TEXT NOT NULL,
            lifecycle_json TEXT NOT NULL,
            findings_json TEXT NOT NULL,
            warnings_json TEXT NOT NULL,
            errors_json TEXT NOT NULL,
            is_complete INTEGER NOT NULL CHECK (is_complete IN (0, 1))
        );
        CREATE INDEX IF NOT EXISTS idx_scan_runs_target_type_id
            ON scan_runs(target, scan_type, id DESC);
        CREATE INDEX IF NOT EXISTS idx_scan_runs_scanned_at
            ON scan_runs(scanned_at DESC);
        """
    )


def _index_findings(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        identity = finding_identity(finding)
        if identity in indexed:
            suffix = 2
            while f"{identity}:{suffix}" in indexed:
                suffix += 1
            identity = f"{identity}:{suffix}"
        indexed[identity] = finding
    return indexed


def _lifecycle(
    previous_findings: list[dict[str, Any]], current_findings: list[dict[str, Any]]
) -> dict[str, Any]:
    previous = _index_findings(previous_findings)
    current = _index_findings(current_findings)
    new = [item for key, item in current.items() if key not in previous]
    resolved = [item for key, item in previous.items() if key not in current]
    changed: list[dict[str, Any]] = []
    persistent = 0
    escalations = 0
    mutable_fields = ("title", "message", "remediation", "severity", "resource")

    for identity, finding in current.items():
        old = previous.get(identity)
        if old is None:
            continue
        changes = {
            field: {"previous": old.get(field), "current": finding.get(field)}
            for field in mutable_fields
            if old.get(field) != finding.get(field)
        }
        if changes:
            changed.append(
                {
                    "finding_id": identity.split(":", 1)[0],
                    "finding": finding,
                    "changes": changes,
                }
            )
        else:
            persistent += 1
        old_severity = str(old.get("severity", "INFO")).upper()
        new_severity = str(finding.get("severity", "INFO")).upper()
        if (
            old_severity in SEVERITY_ORDER
            and new_severity in SEVERITY_ORDER
            and SEVERITY_ORDER[new_severity] < SEVERITY_ORDER[old_severity]
        ):
            escalations += 1

    return {
        "status": "complete",
        "new_count": len(new),
        "resolved_count": len(resolved),
        "persistent_count": persistent,
        "changed_count": len(changed),
        "severity_escalation_count": escalations,
        "new": new,
        "resolved": resolved,
        "changed": changed,
    }


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        severity = str(finding.get("severity", "INFO")).upper()
        if severity in counts:
            counts[severity] += 1
    return counts


def record_scan(
    database: str | Path,
    result: ScanResult,
    scan_type: str = "scan",
) -> dict[str, Any]:
    """Persist a scan and return its run ID and finding-lifecycle summary."""
    if scan_type not in {"scan", "image"}:
        raise HistoryError(f"unsupported scan type: {scan_type}")
    document = result.to_dict()
    findings = document["findings"]
    is_complete = not bool(result.errors)
    lifecycle: dict[str, Any] = {
        "status": "incomplete",
        "new_count": None,
        "resolved_count": None,
        "persistent_count": None,
        "changed_count": None,
        "severity_escalation_count": None,
    }

    connection = _connect(database)
    try:
        if is_complete:
            previous_row = connection.execute(
                """
                SELECT findings_json FROM scan_runs
                WHERE target = ? AND scan_type = ? AND is_complete = 1
                ORDER BY id DESC LIMIT 1
                """,
                (result.target, scan_type),
            ).fetchone()
            if previous_row is None:
                lifecycle = {
                    "status": "initial",
                    "new_count": None,
                    "resolved_count": None,
                    "persistent_count": None,
                    "changed_count": None,
                    "severity_escalation_count": None,
                    "new": [],
                    "resolved": [],
                    "changed": [],
                }
            else:
                previous_findings = json.loads(previous_row["findings_json"])
                lifecycle = _lifecycle(previous_findings, findings)

        scanned_at = datetime.now(UTC).isoformat(timespec="seconds")
        cursor = connection.execute(
            """
            INSERT INTO scan_runs (
                scanned_at, target, scan_type, files_scanned, files_skipped,
                finding_count, severity_counts_json, lifecycle_json, findings_json,
                warnings_json, errors_json, is_complete
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scanned_at,
                result.target,
                scan_type,
                result.files_scanned,
                result.files_skipped,
                len(findings),
                json.dumps(_severity_counts(findings), sort_keys=True),
                json.dumps(lifecycle, sort_keys=True),
                json.dumps(findings, sort_keys=True),
                json.dumps(result.warnings),
                json.dumps(result.errors),
                int(is_complete),
            ),
        )
        connection.commit()
        return {"id": int(cursor.lastrowid), "scanned_at": scanned_at, "lifecycle": lifecycle}
    except (sqlite3.Error, OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        connection.rollback()
        raise HistoryError(f"could not record scan history: {exc}") from exc
    finally:
        connection.close()


def _decode_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "scanned_at": row["scanned_at"],
        "target": row["target"],
        "scan_type": row["scan_type"],
        "files_scanned": row["files_scanned"],
        "files_skipped": row["files_skipped"],
        "finding_count": row["finding_count"],
        "severity_counts": json.loads(row["severity_counts_json"]),
        "lifecycle": json.loads(row["lifecycle_json"]),
        "findings": json.loads(row["findings_json"]),
        "warnings": json.loads(row["warnings_json"]),
        "errors": json.loads(row["errors_json"]),
        "complete": bool(row["is_complete"]),
    }


def list_scans(
    database: str | Path,
    limit: int = 20,
    target: str | None = None,
) -> list[dict[str, Any]]:
    if isinstance(limit, bool) or limit < 1 or limit > 1000:
        raise HistoryError("history list limit must be between 1 and 1000")
    connection = _connect(database)
    try:
        if target:
            rows = connection.execute(
                "SELECT * FROM scan_runs WHERE target = ? ORDER BY id DESC LIMIT ?",
                (target, limit),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_decode_row(row) for row in rows]
    except (sqlite3.Error, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise HistoryError(f"could not read scan history: {exc}") from exc
    finally:
        connection.close()


def get_scan(database: str | Path, run_id: int) -> dict[str, Any]:
    if isinstance(run_id, bool) or run_id < 1:
        raise HistoryError("scan run ID must be a positive integer")
    connection = _connect(database)
    try:
        row = connection.execute("SELECT * FROM scan_runs WHERE id = ?", (run_id,)).fetchone()
        if row is None:
            raise HistoryError(f"scan run {run_id} was not found")
        return _decode_row(row)
    except (sqlite3.Error, ValueError, TypeError, json.JSONDecodeError) as exc:
        if isinstance(exc, HistoryError):
            raise
        raise HistoryError(f"could not read scan run {run_id}: {exc}") from exc
    finally:
        connection.close()


def get_trends(
    database: str | Path,
    days: int = 30,
    target: str | None = None,
) -> list[dict[str, Any]]:
    if isinstance(days, bool) or days < 1 or days > 3650:
        raise HistoryError("history trend window must be between 1 and 3650 days")
    cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat(timespec="seconds")
    connection = _connect(database)
    try:
        if target:
            rows = connection.execute(
                """
                SELECT * FROM scan_runs
                WHERE scanned_at >= ? AND target = ?
                ORDER BY scanned_at ASC, id ASC
                """,
                (cutoff, target),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM scan_runs WHERE scanned_at >= ? ORDER BY scanned_at ASC, id ASC",
                (cutoff,),
            ).fetchall()
        return [_decode_row(row) for row in rows]
    except (sqlite3.Error, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise HistoryError(f"could not read scan trends: {exc}") from exc
    finally:
        connection.close()
