"""Stable finding identities and comparison of JSON scan reports."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class ComparisonError(ValueError):
    """Raised when a scan report cannot be compared."""


def _normalise_resource(finding: dict[str, Any]) -> str:
    resource = finding.get("resource")
    if not isinstance(resource, str):
        return ""
    resource = resource.strip()
    # Container vulnerability resources are emitted as package@installed-version.
    # Exclude the version so an upgraded package retains the same finding identity.
    if finding.get("provider") == "Container" and finding.get("category") == "vulnerability":
        return resource.split("@", 1)[0]
    return resource


def finding_identity(finding: dict[str, Any]) -> str:
    """Return a stable SHA-256 identity, excluding mutable severity and description fields."""
    rule_id = finding.get("rule_id") or finding.get("ruleId")
    path = finding.get("path")
    if not isinstance(path, str) or not path:
        locations = finding.get("locations")
        try:
            path = locations[0]["physicalLocation"]["artifactLocation"]["uri"]
        except (TypeError, IndexError, KeyError):
            path = ""
    category = finding.get("category", "")
    provider = finding.get("provider", "")
    resource = _normalise_resource(finding)
    evidence = finding.get("evidence") or finding.get("properties", {}).get("redactedEvidence", "")
    # For findings without a resource, evidence and line provide useful disambiguation.
    line = finding.get("line")
    if line is None and not resource:
        try:
            line = finding["locations"][0]["physicalLocation"]["region"].get("startLine")
        except (TypeError, IndexError, KeyError, AttributeError):
            line = None
    payload = {
        "rule_id": str(rule_id or "UNKNOWN-RULE"),
        "path": path.replace("\\", "/"),
        "category": category,
        "provider": provider,
        "resource": resource,
        "evidence": evidence if not resource else "",
        "line": line if not resource else None,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _read_report(path: str | Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    report_path = Path(path)
    try:
        document = json.loads(report_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ComparisonError(f"could not read report {report_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ComparisonError(f"report {report_path} is not valid JSON: {exc}") from exc

    if not isinstance(document, dict):
        raise ComparisonError(f"report {report_path} must contain a JSON object")
    findings = document.get("findings")
    if not isinstance(findings, list):
        raise ComparisonError(
            f"report {report_path} must be a cloudsec JSON report with a findings array; SARIF is not supported"
        )

    indexed: dict[str, dict[str, Any]] = {}
    for item in findings:
        if not isinstance(item, dict):
            continue
        identity = finding_identity(item)
        # Preserve duplicates deterministically instead of silently overwriting one.
        if identity in indexed:
            suffix = 2
            while f"{identity}:{suffix}" in indexed:
                suffix += 1
            identity = f"{identity}:{suffix}"
        indexed[identity] = item
    return document, indexed


def compare_reports(baseline_path: str | Path, current_path: str | Path) -> dict[str, Any]:
    """Compare current scan findings against a previous JSON scan report."""
    baseline_doc, baseline = _read_report(baseline_path)
    current_doc, current = _read_report(current_path)

    new: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    persistent: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []

    for identity, finding in current.items():
        if identity not in baseline:
            new.append({"finding_id": identity.split(":", 1)[0], "finding": finding})
            continue
        previous = baseline[identity]
        previous_severity = previous.get("severity")
        current_severity = finding.get("severity")
        item = {
            "finding_id": identity.split(":", 1)[0],
            "previous_severity": previous_severity,
            "current_severity": current_severity,
            "finding": finding,
        }
        mutable_fields = ("title", "message", "remediation", "severity")
        if any(previous.get(field) != finding.get(field) for field in mutable_fields):
            changed.append(item)
        else:
            persistent.append(item)

    for identity, finding in baseline.items():
        if identity not in current:
            resolved.append({"finding_id": identity.split(":", 1)[0], "finding": finding})

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def sort_key(item: dict[str, Any]) -> tuple[int, str, str]:
        finding = item["finding"]
        return (
            severity_order.get(str(finding.get("severity", "INFO")).upper(), 99),
            str(finding.get("rule_id", "")),
            str(finding.get("resource", "")),
        )

    for group in (new, resolved, persistent, changed):
        group.sort(key=sort_key)

    return {
        "schema_version": "1.0",
        "comparison": {
            "baseline_target": baseline_doc.get("target"),
            "current_target": current_doc.get("target"),
            "baseline_finding_count": len(baseline),
            "current_finding_count": len(current),
            "new_count": len(new),
            "resolved_count": len(resolved),
            "persistent_count": len(persistent),
            "changed_count": len(changed),
        },
        "new": new,
        "resolved": resolved,
        "persistent": persistent,
        "changed": changed,
    }


def render_comparison_text(comparison: dict[str, Any]) -> str:
    summary = comparison["comparison"]
    lines = [
        "Cloud Security Scan Comparison",
        f"Baseline: {summary.get('baseline_target')}",
        f"Current:  {summary.get('current_target')}",
        f"Findings: {summary['baseline_finding_count']} -> {summary['current_finding_count']}",
        f"New: {summary['new_count']} | Resolved: {summary['resolved_count']} | "
        f"Persistent: {summary['persistent_count']} | Changed: {summary['changed_count']}",
        "",
    ]
    for group_name in ("new", "resolved", "changed", "persistent"):
        entries = comparison[group_name]
        lines.append(f"{group_name.upper()} ({len(entries)})")
        for entry in entries:
            finding = entry["finding"]
            lines.append(
                f"  [{finding.get('severity', 'INFO')}] {finding.get('rule_id', 'UNKNOWN-RULE')} — "
                f"{finding.get('title', 'Untitled finding')} ({finding.get('resource') or finding.get('path', '')})"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
