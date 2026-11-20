"""Shared finding and scan result models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from cloudsec_scanner import __version__

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    message: str
    path: str
    line: int | None = None
    resource: str | None = None
    category: str = "misconfiguration"
    provider: str | None = None
    remediation: str = (
        "Review the affected configuration and apply the relevant security best practice."
    )
    references: tuple[str, ...] = ()
    compliance: tuple[str, ...] = ()
    evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["references"] = list(self.references)
        result["compliance"] = list(self.compliance)
        return result


@dataclass(slots=True)
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    coverage_complete: bool = True
    scan_profile: str = ""
    project_key: str = ""
    exceptions: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        from cloudsec_scanner.comparison import finding_identity, _relative_finding

        return {
            "schema_version": "1.0",
            "tool": {"name": "cloudsec-scanner", "version": __version__},
            "target": self.target,
            "coverage_complete": self.coverage_complete and not self.errors,
            "scan_profile": self.scan_profile,
            "project_key": self.project_key,
            "summary": {
                "files_scanned": self.files_scanned,
                "files_skipped": self.files_skipped,
                "finding_count": len(self.findings),
                "by_severity": {
                    severity: sum(1 for f in self.findings if f.severity == severity)
                    for severity in SEVERITY_ORDER
                },
            },
            "exceptions": self.exceptions,
            "findings": [
                {**finding.to_dict(), "finding_id": finding_identity(_relative_finding(finding.to_dict(), {"target": self.target}))}
                for finding in sorted(
                    self.findings,
                    key=lambda f: (
                        SEVERITY_ORDER.get(f.severity, 99),
                        f.path,
                        f.line or 0,
                        f.rule_id,
                    ),
                )
            ],
            "warnings": self.warnings,
            "errors": self.errors,
        }
