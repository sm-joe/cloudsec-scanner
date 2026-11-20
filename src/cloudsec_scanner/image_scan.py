"""Container image scanning through the Trivy CLI."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any

from cloudsec_scanner.models import Finding, ScanResult

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


class ImageScanError(ValueError):
    """Raised when an image scan cannot be executed or parsed safely."""


def _severity(value: Any) -> str:
    if isinstance(value, str) and value.upper() in SEVERITIES:
        return value.upper()
    return "HIGH"


def _string(value: Any, fallback: str) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else fallback


def _finding_from_vulnerability(image: str, target: str, item: dict[str, Any]) -> Finding:
    vuln_id = _string(item.get("VulnerabilityID"), "UNKNOWN-VULNERABILITY")
    package = _string(item.get("PkgName"), "unknown-package")
    installed = _string(item.get("InstalledVersion"), "unknown")
    fixed = item.get("FixedVersion")
    fix = (
        f"Upgrade {package} from {installed} to {fixed}."
        if isinstance(fixed, str) and fixed.strip()
        else f"Review {package} and update to a version that is not affected by {vuln_id}."
    )
    references = item.get("PrimaryURL")
    refs = (
        (references,) if isinstance(references, str) and references.startswith("https://") else ()
    )
    return Finding(
        rule_id=f"IMG-VULN-{vuln_id}",
        title=_string(item.get("Title"), f"Vulnerable image package: {package}"),
        severity=_severity(item.get("Severity")),
        message=_string(
            item.get("Description"), f"{package}@{installed} is affected by {vuln_id}."
        ),
        path=target,
        resource=f"{package}@{installed}",
        category="vulnerability",
        provider="Container",
        remediation=fix,
        references=refs,
        evidence=f"Image: {image}; vulnerability: {vuln_id}",
    )


def _finding_from_misconfiguration(image: str, target: str, item: dict[str, Any]) -> Finding:
    rule_id = _string(item.get("ID"), "UNKNOWN-MISCONFIGURATION")
    references = item.get("PrimaryURL")
    refs = (
        (references,) if isinstance(references, str) and references.startswith("https://") else ()
    )
    return Finding(
        rule_id=f"IMG-CONFIG-{rule_id}",
        title=_string(item.get("Title"), "Container image misconfiguration"),
        severity=_severity(item.get("Severity")),
        message=_string(item.get("Message"), "Trivy reported a container image misconfiguration."),
        path=target,
        resource=_string(item.get("Target"), image),
        category="misconfiguration",
        provider="Container",
        remediation=_string(
            item.get("Resolution"), "Review and remediate the reported image configuration issue."
        ),
        references=refs,
        evidence=f"Image: {image}; check: {rule_id}",
    )


def scan_image(image: str, *, trivy_path: str | None = None, timeout: int = 900) -> ScanResult:
    """Scan a container image using Trivy's JSON report output.

    Trivy must be installed and able to access the image (locally or through its
    configured registry credentials). This function does not pull the image itself.
    """
    image = image.strip()
    if not image or image.startswith("-") or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+\-]*", image):
        raise ImageScanError("invalid image reference")

    executable = trivy_path or shutil.which("trivy")
    if not executable:
        raise ImageScanError("Trivy was not found; install Trivy and ensure it is on PATH")

    command = [
        executable,
        "image",
        "--format",
        "json",
        "--scanners",
        "vuln,misconfig",
        image,
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ImageScanError(f"Trivy image scan timed out after {timeout} seconds") from exc
    except OSError as exc:
        raise ImageScanError(f"could not execute Trivy: {exc}") from exc

    if completed.returncode != 0:
        raise ImageScanError(f"Trivy image scan failed (exit {completed.returncode}); check registry access and image reference")

    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ImageScanError(f"Trivy returned malformed JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ImageScanError("Trivy JSON report must be an object")

    target = f"image://{image}"
    result = ScanResult(target=target, files_scanned=1)
    results = document.get("Results")
    if not isinstance(results, list):
        raise ImageScanError("Trivy JSON report has an invalid Results field")

    for section in results:
        if not isinstance(section, dict):
            raise ImageScanError("Trivy JSON report has an invalid result entry")
        vulnerabilities = section.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise ImageScanError("Trivy JSON report contains an invalid Vulnerabilities field")
        for item in vulnerabilities:
            if not isinstance(item, dict):
                raise ImageScanError("invalid vulnerability entry")
            result.findings.append(_finding_from_vulnerability(image, target, item))

        misconfigurations = section.get("Misconfigurations") or []
        if not isinstance(misconfigurations, list):
            raise ImageScanError("Trivy JSON report contains an invalid Misconfigurations field")
        for item in misconfigurations:
            if not isinstance(item, dict):
                raise ImageScanError("invalid misconfiguration entry")
            status = item.get("Status")
            if status in {"PASS", "EXCEPTION"}:
                continue
            if status not in {None, "FAIL"}:
                raise ImageScanError("Trivy returned an unsupported misconfiguration status")
            result.findings.append(_finding_from_misconfiguration(image, target, item))

    # De-duplicate repeated reports for the same check/package and location.
    unique: dict[tuple[str, str, str | None], Finding] = {}
    for finding in result.findings:
        unique.setdefault((finding.rule_id, finding.path, finding.resource), finding)
    result.findings = list(unique.values())
    return result
