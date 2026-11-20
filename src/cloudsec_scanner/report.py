"""Terminal, JSON and SARIF report writers."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from cloudsec_scanner.models import SEVERITY_ORDER, ScanResult
from cloudsec_scanner.comparison import finding_identity, _relative_finding
from urllib.parse import quote
from cloudsec_scanner import __version__


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
    accepted = {entry["finding_id"]: entry for entry in result.exceptions if entry["status"] == "ACCEPTED"}
    for finding in result.findings:
        relative = _relative_finding(finding.to_dict(), {"target": result.target})
        identity = finding_identity(relative)
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
            "partialFingerprints": {"cloudsecFindingId/v2": identity},
            "level": level_map.get(finding.severity, "warning"),
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": quote(relative["path"].replace("\\", "/"), safe="/:")},
                        "region": {"startLine": finding.line or 1},
                    }
                }
            ],
            "properties": {
                "severity": finding.severity,
                "remediation": finding.remediation,
                "provider": finding.provider,
                "resource": finding.resource,
                "resourceId": finding.resource_id,
                "compliance": list(finding.compliance),
                "advisoryIds": list(finding.advisory_ids),
            },
        }
        if finding.evidence:
            item["properties"]["redactedEvidence"] = finding.evidence
        if identity in accepted:
            item["suppressions"] = [{"kind": "external", "status": "accepted", "justification": accepted[identity]["reason"]}]
        results.append(item)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cloudsec-scanner",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "target": result.target,
                    "coverageComplete": result.coverage_complete and not result.errors,
                    "filesScanned": result.files_scanned,
                    "filesSkipped": result.files_skipped,
                    "assetsScanned": result.assets_scanned,
                    "assessments": result.assessments,
                    "warnings": result.warnings,
                    "errors": result.errors,
                    "exceptions": result.exceptions,
                    "provenance": result.provenance,
                },
            }
        ],
    }


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=False) + "\n"


def render_sarif(result: ScanResult) -> str:
    return json.dumps(_sarif(result), indent=2) + "\n"


def render_text(result: ScanResult, *, color: bool = False, exclusions: bool = False) -> str:
    """Render findings and explicitly evaluated resource outcomes, not inferred rule passes."""
    import unicodedata

    def safe(value):
        # Untrusted filenames/configuration must not inject ANSI or terminal controls.
        return "".join(c if unicodedata.category(c) not in {"Cc", "Cf", "Cs"} else f"\\u{ord(c):04x}" for c in str(value))

    def paint(value, code):
        return f"\x1b[{code}m{value}\x1b[0m" if color else value

    complete = result.coverage_complete and not result.errors
    counts = result.to_dict()["summary"]["assessment_counts"]
    accepted = {entry["finding_id"] for entry in result.exceptions if entry["status"] == "ACCEPTED"}
    # Use resource-level outcomes only where the existing scanner recorded evaluation.
    # Ambiguous or unlinked findings prevent a positive outcome for that file.
    failed = {(f.path, f.resource_id) for f in result.findings if f.resource_id}
    uncertain = {f.path for f in result.findings if not f.resource_id}
    keys = {(entry["path"], entry["resource_id"]) for entry in result.assessments}
    uncertain.update(f.path for f in result.findings if f.resource_id and (f.path, f.resource_id) not in keys)
    from collections import Counter
    occurrences = Counter((entry["path"], entry["resource_id"]) for entry in result.assessments)
    seen = set()
    passed = []
    for entry in result.assessments:
        key = (entry["path"], entry["resource_id"])
        if key in seen:
            continue
        seen.add(key)
        if complete and not exclusions and occurrences[key] == 1 and entry["status"] == "EVALUATED" and key not in failed and entry["path"] not in uncertain:
            passed.append(entry)

    lines = [
        paint("CloudSec Scanner", "1;36") + f"  v{__version__}",
        "=" * 64,
        f"Target: {safe(result.target)}",
        f"Files scanned: {result.files_scanned} | skipped: {result.files_skipped} | findings: {len(result.findings)}",
        f"Evaluated resources: {counts['EVALUATED']}",
        "Coverage: " + paint("COMPLETE" if complete else "INCOMPLETE", "32" if complete else "31"),
        paint(f"Passed resources: {len(passed)}", "32" if passed else "0") + " | " + paint(f"Failed findings: {len(result.findings)}", "31" if result.findings else "0"),
        "Severity: " + " | ".join(f"{level} {count}" for level, count in result.to_dict()["summary"]["by_severity"].items()),
        "",
        paint("Scan results", "1;36"),
        "-" * 64,
    ]
    if not result.findings:
        lines.append("No findings detected by the enabled rules." if complete else "Scan incomplete; no clean assessment is available.")
    for number, f in enumerate(sorted(result.findings, key=lambda item: (SEVERITY_ORDER.get(item.severity, 99), item.path, item.line or 0, item.rule_id)), 1):
        identity = finding_identity(_relative_finding(f.to_dict(), {"target": result.target}))
        status = paint("FAILED", "1;31")
        lines.extend([
            f"{number:>3}. | {status} | [{safe(f.severity)}] {paint(safe(f.rule_id), '1;33')} — {safe(f.title)}",
            f"       FILE: {safe(f.path)}:{f.line or 1}",
            f"       FINDING ID: {identity}",
            f"       Risk: {safe(f.message)}",
            f"       Fix: {safe(f.remediation)}",
        ])
        if f.resource_id or f.resource:
            lines.append(f"       RESOURCE: {safe(f.resource_id or f.resource)}")
        if f.compliance:
            lines.append(f"       Compliance: {safe(', '.join(f.compliance))}")
        if identity in accepted:
            lines.append("       " + paint("Accepted exception (finding retained)", "33"))
        lines.append("")
    if passed:
        lines.extend([paint("Passed resource assessments", "1;32"), "-" * 64])
        for entry in passed:
            lines.append(f"  | {paint('PASSED', '1;32')} | {safe(entry['resource_id'])}")
            lines.append(f"       FILE: {safe(entry['path'])}")
        lines.append("  No findings from enabled native predicates; not full compliance.")
    if exclusions:
        lines.append("Pass counts withheld: rule exclusions are enabled.")
    if result.assessments:
        for status, count in counts.items():
            lines.append(f"{status}: {count} resource(s)")
        for entry in result.assessments:
            if entry["status"] != "EVALUATED":
                lines.append(f"  | {paint(safe(entry['status']), '33')} | {safe(entry['resource_id'])} — {safe(entry['reason'])}")
    for entry in result.exceptions:
        lines.append(f"Exception {safe(entry['status'])}: {safe(entry['finding_id'])} (expires {safe(entry['expires'])})")
    for warning in result.warnings:
        lines.append(paint("WARNING:", "33") + f" {safe(warning)}")
    for error in result.errors:
        lines.append(paint("ERROR:", "31") + f" {safe(error)}")
    lines.append("-" * 64)
    if not complete:
        lines.append(paint("INCOMPLETE — assessment coverage withheld", "1;31"))
    elif result.findings:
        lines.append(paint("COMPLETED WITH FINDINGS", "1;31"))
    elif passed:
        lines.append(paint("COMPLETED — no findings in enabled checks", "1;32"))
    else:
        lines.append("COMPLETED — no findings reported; no resource passes established")
    return "\n".join(lines).rstrip() + "\n"


def terminal_color(mode, stream):
    """Respect redirected output, NO_COLOR and terminal capabilities."""
    if mode == "never" or "NO_COLOR" in os.environ:
        return False
    if mode != "always" and (not stream.isatty() or os.environ.get("TERM") == "dumb"):
        return False
    if os.name == "nt" and stream.isatty():
        try:
            import ctypes
            kernel = ctypes.windll.kernel32
            handle = kernel.GetStdHandle(-11)
            flags = ctypes.c_uint()
            if not kernel.GetConsoleMode(handle, ctypes.byref(flags)):
                return mode == "always"
            return bool(kernel.SetConsoleMode(handle, flags.value | 4))
        except (AttributeError, OSError):
            return mode == "always"
    return True


def write_report(result: ScanResult, fmt: str, output: str | None, *, exclusions: bool = False) -> str:
    if fmt == "json":
        rendered = render_json(result)
    elif fmt == "sarif":
        rendered = render_sarif(result)
    else:
        rendered = render_text(result, exclusions=exclusions)
    if output:
        target = Path(output)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=target.parent, prefix=".cloudsec-", delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(rendered)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return rendered
