"""Shared helpers for native security rules."""

from __future__ import annotations

import re
from pathlib import Path

from cloudsec_scanner.models import Finding


def line_for(text: str, pattern: str, default: int = 1) -> int:
    match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    return text.count("\n", 0, match.start()) + 1 if match else default


def finding(
    rule_id: str,
    title: str,
    severity: str,
    message: str,
    path: Path,
    text: str,
    line_pattern: str,
    remediation: str,
    *,
    provider: str,
    resource: str | None = None,
    category: str = "misconfiguration",
    compliance: tuple[str, ...] = (),
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        message=message,
        path=str(path),
        line=line_for(text, line_pattern),
        resource=resource,
        category=category,
        provider=provider,
        remediation=remediation,
        compliance=compliance,
    )


def mappings(value: object) -> list[dict]:
    """Return mapping objects from a mapping or list without assuming input shape."""
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []
