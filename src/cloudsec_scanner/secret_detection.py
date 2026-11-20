"""Secret detection with redacted evidence and placeholder filtering."""

from __future__ import annotations

import re
from pathlib import Path

from cloudsec_scanner.models import Finding

_PLACEHOLDER_VALUES = {
    "",
    "changeme",
    "change-me",
    "example",
    "example-value",
    "dummy",
    "fake",
    "not-a-secret",
    "placeholder",
    "replace-me",
    "replace_me",
    "sample",
    "test",
    "testing",
    "your-secret",
    "your-secret-here",
    "your-token",
    "your-api-key",
    "${SECRET}",
    "${TOKEN}",
    "${API_KEY}",
}

_ASSIGNMENT_PATTERN = re.compile(
    r"""(?ix)
    \b
    (?P<key>
        aws_secret_access_key |
        aws_session_token |
        client_secret |
        clientsecret |
        access_token |
        auth_token |
        api[_-]?key |
        secret[_-]?key |
        secret |
        password |
        passwd |
        token
    )
    \b
    \s*[:=]\s*
    (?P<quote>["']?)
    (?P<value>[^\s"'`,;}\]]+)
    """
)

_AWS_ACCESS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GITHUB_TOKEN_PATTERN = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")
_PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")

_RULE_REMEDIATION = (
    "Remove the credential from source control, rotate it if it is real, "
    "and use a secret manager or runtime credential injection."
)


def _is_placeholder(value: str) -> bool:
    """Return whether a candidate secret is a placeholder or variable reference."""
    normalized = value.strip().strip("\"'`").strip().lower()

    if not normalized:
        return True

    exact_placeholders = {
        "changeme",
        "change-me",
        "change_me",
        "placeholder",
        "example",
        "your-token",
        "your_token",
        "your-secret",
        "your_secret",
        "your-password",
        "your_password",
        "todo",
        "none",
        "null",
        "undefined",
    }

    if normalized in exact_placeholders:
        return True

    # Environment variables and shell-style variable references.
    if normalized.startswith("$"):
        return True

    # Template placeholders, including partially captured expressions.
    if normalized.startswith("{") or normalized.endswith("}"):
        return True

    return "{{" in normalized or "}}" in normalized


def _finding(
    rule_id: str,
    path: Path,
    line: int,
    evidence: str,
) -> Finding:
    return Finding(
        rule_id,
        "Possible hardcoded secret",
        "HIGH",
        "A credential-like value or private-key marker was found.",
        str(path),
        line,
        None,
        "secrets",
        None,
        _RULE_REMEDIATION,
        (),
        (),
        evidence,
    )


def scan_secrets(path: Path, text: str) -> list[Finding]:
    """Find likely credentials while ensuring evidence never exposes values."""
    findings: list[Finding] = []
    seen: set[tuple[str, int, int, int]] = set()

    def add(
        rule_id: str,
        match: re.Match[str],
        evidence: str,
    ) -> None:
        line = text.count("\n", 0, match.start()) + 1
        identity = (rule_id, line, match.start(), match.end())

        if identity in seen:
            return

        seen.add(identity)
        findings.append(_finding(rule_id, path, line, evidence))

    for match in _AWS_ACCESS_KEY_PATTERN.finditer(text):
        add("SEC-SECRET-001", match, "AWS access key: [REDACTED]")

    for match in _ASSIGNMENT_PATTERN.finditer(text):
        # GitHub Actions OIDC permissions are enum values, not credential assignments.
        # Restrict this distinction to the exact workflow key and standalone YAML line.
        line_start = text.rfind("\n", 0, match.start()) + 1
        line_end = text.find("\n", match.end())
        line_text = text[line_start:line_end if line_end != -1 else len(text)]
        if (
            path.parent.name == "workflows"
            and path.parent.parent.name == ".github"
            and path.suffix in {".yaml", ".yml"}
            and match.group("key").lower() == "token"
            and re.fullmatch(r"[ \t]*id-token:[ \t]*(?:write|none|read)[ \t]*(?:#.*)?", line_text)
        ):
            continue
        value = match.group("value").rstrip(".")
        if _is_placeholder(value):
            continue

        key = match.group("key").lower().replace("-", "_")
        if key in {"aws_secret_access_key", "aws_session_token"}:
            evidence_key = key
        elif key in {"clientsecret"}:
            evidence_key = "client_secret"
        else:
            evidence_key = key

        add(
            "SEC-SECRET-002",
            match,
            f"{evidence_key}=[REDACTED]",
        )

    for match in _PRIVATE_KEY_PATTERN.finditer(text):
        add(
            "SEC-SECRET-003",
            match,
            "[REDACTED PRIVATE KEY MARKER]",
        )

    for match in _GITHUB_TOKEN_PATTERN.finditer(text):
        add("SEC-SECRET-004", match, "GitHub token: [REDACTED]")

    return sorted(
        findings,
        key=lambda finding: (finding.path, finding.line, finding.rule_id),
    )
