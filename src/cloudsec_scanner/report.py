"""Terminal, JSON and SARIF report writers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cloudsec_scanner.models import SEVERITY_ORDER, ScanResult


def _sarif(result: ScanResult) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    level_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }
    for finding in result.findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.message},
                "help": {"text": finding.remediation},
                "properties": {"severity": finding.severity, "category": finding.category},
            },
        )
        item: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": level_map.get(finding.severity, "warning"),
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.path.replace("\\", "/")},
                        "region": {"startLine": finding.line or 1},
                    }
                }
            ],
            "properties": {
                "severity": finding.severity,
                "remediation": finding.remediation,
                "provider": finding.provider,
                "resource": finding.resource,
                "compliance": list(finding.compliance),
            },
        }
        if finding.evidence:
            item["properties"]["redactedEvidence"] = finding.evidence
        results.append(item)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cloudsec-scanner",
                        "version": "0.1.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "target": result.target,
                    "filesScanned": result.files_scanned,
                    "filesSkipped": result.files_skipped,
                    "warnings": result.warnings,
                    "errors": result.errors,
                },
            }
        ],
    }


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=False) + "\n"


def render_sarif(result: ScanResult) -> str:
    return json.dumps(_sarif(result), indent=2) + "\n"


def render_text(result: ScanResult) -> str:
    lines = [
        f"Cloud Security Scanner — {result.target}",
        f"Files scanned: {result.files_scanned} | skipped: {result.files_skipped} | findings: {len(result.findings)}",
        "",
    ]
    if not result.findings:
        lines.append("No findings detected by the enabled rules.")
    for f in sorted(
        result.findings,
        key=lambda item: (SEVERITY_ORDER.get(item.severity, 99), item.path, item.line or 0),
    ):
        location = f"{f.path}:{f.line or 1}"
        lines.extend(
            [
                f"[{f.severity}] {f.rule_id} — {f.title}",
                f"  Location: {location}",
                f"  Risk: {f.message}",
                f"  Fix: {f.remediation}",
            ]
        )
        if f.resource:
            lines.append(f"  Resource: {f.resource}")
        if f.compliance:
            lines.append(f"  Compliance: {', '.join(f.compliance)}")
        lines.append("")
    for warning in result.warnings:
        lines.append(f"WARNING: {warning}")
    for error in result.errors:
        lines.append(f"ERROR: {error}")
    return "\n".join(lines).rstrip() + "\n"


def write_report(result: ScanResult, fmt: str, output: str | None) -> str:
    if fmt == "json":
        rendered = render_json(result)
    elif fmt == "sarif":
        rendered = render_sarif(result)
    else:
        rendered = render_text(result)
    if output:
        target = Path(output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
    return rendered
