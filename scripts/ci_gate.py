"""Enforce a severity threshold on new findings and severity escalations in a comparison report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
EXIT_OK = 0
EXIT_POLICY = 1
EXIT_INPUT = 2


def _load_comparison(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"could not read comparison report {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"comparison report {path} is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("comparison report must be a JSON object")
    summary = data.get("comparison")
    if not isinstance(summary, dict):
        raise ValueError("comparison report is missing the comparison summary")
    for key in ("new", "changed"):
        if not isinstance(data.get(key), list):
            raise ValueError(f"comparison report must contain a {key!r} array")
    return data


def _severity(value: Any) -> str:
    if not isinstance(value, str):
        return "INFO"
    normalized = value.upper()
    return normalized if normalized in SEVERITY_ORDER else "INFO"


def evaluate_comparison(comparison: dict[str, Any], threshold: str = "HIGH") -> list[str]:
    """Return policy violations for new findings and upward severity changes."""
    threshold = threshold.upper()
    if threshold not in SEVERITY_ORDER:
        raise ValueError("severity threshold must be CRITICAL, HIGH, MEDIUM, LOW, or INFO")
    threshold_rank = SEVERITY_ORDER[threshold]
    violations: list[str] = []

    for entry in comparison["new"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("finding"), dict):
            raise ValueError("comparison report contains an invalid entry in 'new'")
        finding = entry["finding"]
        severity = _severity(finding.get("severity"))
        if SEVERITY_ORDER[severity] <= threshold_rank:
            violations.append(
                f"NEW [{severity}] {finding.get('rule_id', 'UNKNOWN-RULE')} — "
                f"{finding.get('title', 'Untitled finding')} "
                f"({finding.get('resource') or finding.get('path', '')})"
            )

    for entry in comparison["changed"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("finding"), dict):
            raise ValueError("comparison report contains an invalid entry in 'changed'")
        changes = entry.get("changes", {})
        if not isinstance(changes, dict) or "severity" not in changes:
            continue
        severity_change = changes["severity"]
        if not isinstance(severity_change, dict):
            raise ValueError("comparison report contains an invalid severity change")
        previous = _severity(severity_change.get("previous"))
        current = _severity(severity_change.get("current"))
        if (
            SEVERITY_ORDER[current] <= threshold_rank
            and SEVERITY_ORDER[current] < SEVERITY_ORDER[previous]
        ):
            finding = entry["finding"]
            violations.append(
                f"SEVERITY ESCALATION [{previous} -> {current}] "
                f"{finding.get('rule_id', 'UNKNOWN-RULE')} — "
                f"{finding.get('title', 'Untitled finding')} "
                f"({finding.get('resource') or finding.get('path', '')})"
            )

    return violations


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fail CI for new findings or severity escalations in a CloudSec comparison report."
    )
    parser.add_argument("comparison", help="JSON output from 'cloudsec compare --format json'")
    parser.add_argument(
        "--severity",
        choices=tuple(SEVERITY_ORDER),
        default="HIGH",
        help="minimum severity that fails the gate (default: HIGH)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        comparison = _load_comparison(Path(args.comparison))
        violations = evaluate_comparison(comparison, args.severity)
    except ValueError as exc:
        print(f"CI gate error: {exc}", file=sys.stderr)
        return EXIT_INPUT

    summary = comparison["comparison"]
    print(
        "CloudSec regression gate: "
        f"{summary.get('new_count', len(comparison['new']))} new, "
        f"{summary.get('changed_count', len(comparison['changed']))} changed; "
        f"threshold={args.severity}"
    )
    if violations:
        print(f"FAIL: {len(violations)} policy violation(s)", file=sys.stderr)
        for violation in violations:
            print(f"  - {violation}", file=sys.stderr)
        return EXIT_POLICY

    print("PASS: no new findings or severity escalations at or above the threshold")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
