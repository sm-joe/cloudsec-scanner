"""Stable finding identities and comparison of JSON scan reports."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from cloudsec_scanner.models import SEVERITY_ORDER


class ComparisonError(ValueError):
    """Raised when a scan report cannot be compared."""


def _normalise_resource(finding: dict[str, Any]) -> str:
    resource = finding.get("resource_id") or finding.get("resource")
    if not isinstance(resource, str):
        return ""
    resource = resource.strip()
    # Container vulnerability resources are emitted as package@installed-version.
    # Exclude the version so an upgraded package retains the same finding identity.
    if finding.get("category") == "dependency" or (finding.get("provider") == "Container" and finding.get("category") == "vulnerability"):
        return resource.rsplit("@", 1)[0] if "@" in resource.lstrip("@") else resource
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
        "evidence": evidence if not resource or category == "dependency" else "",
        "line": line if not resource else None,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _relative_finding(finding: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
    path, target = finding.get("path"), document.get("target")
    if isinstance(path, str) and isinstance(target, str) and not target.startswith("image://"):
        normalized = path.replace("\\", "/")
        root = target.replace("\\", "/").rstrip("/")
        if normalized == root:
            normalized = root.rsplit("/", 1)[-1]
        elif root and root != "." and normalized.startswith(root + "/"):
            normalized = normalized[len(root) + 1:]
        return {**finding, "path": normalized.removeprefix("./")}
    return finding


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
        if not isinstance(item, dict) or item.get("severity") not in SEVERITY_ORDER:
            raise ComparisonError("invalid finding or severity")
        identity = finding_identity(_relative_finding(item, document))
        # Preserve duplicates deterministically instead of silently overwriting one.
        if identity in indexed:
            suffix = 2
            while f"{identity}:{suffix}" in indexed:
                suffix += 1
            identity = f"{identity}:{suffix}"
        indexed[identity] = item
    return document, indexed


def compare_report_documents(
    baseline_doc: dict[str, Any], current_doc: dict[str, Any]
) -> dict[str, Any]:
    """Compare two already-loaded CloudSec JSON report documents."""
    for document in (baseline_doc, current_doc):
        if document.get("coverage_complete") is False or document.get("errors"):
            raise ComparisonError("cannot compare incomplete scans")
    if baseline_doc.get("fingerprint_version", 1) != current_doc.get("fingerprint_version", 1):
        raise ComparisonError("finding fingerprint versions differ; regenerate baseline using current CLI")
    if baseline_doc.get("scan_profile") and current_doc.get("scan_profile") and baseline_doc["scan_profile"] != current_doc["scan_profile"]:
        raise ComparisonError("scan profiles differ")
    baseline, current = _index_report_findings(baseline_doc), _index_report_findings(current_doc)

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
        mutable_fields = ("title", "message", "remediation", "severity", "resource")
        changes = {
            field: {"previous": previous.get(field), "current": finding.get(field)}
            for field in mutable_fields
            if previous.get(field) != finding.get(field)
        }
        if changes:
            item["changes"] = changes
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



def _index_report_findings(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    findings = document.get("findings")
    if not isinstance(findings, list):
        raise ComparisonError("report must be a cloudsec JSON report with a findings array; SARIF is not supported")
    indexed: dict[str, dict[str, Any]] = {}
    for item in findings:
        if not isinstance(item, dict) or item.get("severity") not in SEVERITY_ORDER:
            raise ComparisonError("invalid finding or severity")
        identity = finding_identity(_relative_finding(item, document))
        if identity in indexed:
            suffix = 2
            while f"{identity}:{suffix}" in indexed:
                suffix += 1
            identity = f"{identity}:{suffix}"
        indexed[identity] = item
    return indexed


def compare_reports(baseline_path: str | Path, current_path: str | Path) -> dict[str, Any]:
    """Compare current scan findings against a previous JSON scan report."""
    baseline_doc, _ = _read_report(baseline_path)
    current_doc, _ = _read_report(current_path)
    return compare_report_documents(baseline_doc, current_doc)


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
