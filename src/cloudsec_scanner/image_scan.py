"""Container image scanning through the Trivy CLI."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from threading import Thread, Event
from dataclasses import replace
from cloudsec_scanner.safe_input import safe_json_document
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


MAX_TRIVY_OUTPUT_BYTES = 64 * 1024 * 1024


def _run_json(command, timeout, *, limit=MAX_TRIVY_OUTPUT_BYTES):
    """Drain subprocess pipes concurrently; bound memory, time and diagnostics."""
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        raise ImageScanError("could not execute Trivy") from exc
    output = bytearray()
    overflow = Event()
    failed = Event()

    def drain(stream, keep):
        count = 0
        try:
            with stream:
                while chunk := stream.read1(65536):
                    count += len(chunk)
                    if count > limit:
                        overflow.set()
                        process.kill()
                        return
                    if keep:
                        output.extend(chunk)
        except OSError:
            failed.set()

    threads = [Thread(target=drain, args=(process.stdout, True), daemon=True), Thread(target=drain, args=(process.stderr, False), daemon=True)]
    for thread in threads:
        thread.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise ImageScanError("Trivy image scan timed out") from exc
    finally:
        for thread in threads:
            thread.join(timeout=2)
    if overflow.is_set() or failed.is_set() or any(t.is_alive() for t in threads):
        raise ImageScanError("Trivy output exceeded bounds or could not be read")
    if process.returncode:
        raise ImageScanError(f"Trivy image scan failed (exit {process.returncode}); check registry access and image reference")
    try:
        return safe_json_document(output.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ImageScanError("Trivy returned malformed JSON") from exc


def _provenance(document, version):
    metadata = document.get("Metadata", {})
    if not isinstance(metadata, dict):
        raise ImageScanError("invalid Trivy metadata")
    digest = metadata.get("RepoDigests", [])
    if not isinstance(digest, list):
        raise ImageScanError("invalid image digests")
    # Do not copy image environment, build history or registry account names.
    digests = sorted({item.rsplit("@", 1)[-1] for item in digest if isinstance(item, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", item.rsplit("@", 1)[-1])})
    os_info = metadata.get("OS", {})
    db = version.get("VulnerabilityDB", {}) if isinstance(version, dict) else {}
    return {
        "scanner": "Trivy",
        "version": version.get("Version") if isinstance(version, dict) and isinstance(version.get("Version"), str) else None,
        "database_updated_at": db.get("UpdatedAt") if isinstance(db, dict) and isinstance(db.get("UpdatedAt"), str) else None,
        "image_digests": digests,
        "image_id": metadata.get("ImageID") if isinstance(metadata.get("ImageID"), str) and re.fullmatch(r"sha256:[0-9a-f]{64}", metadata["ImageID"]) else None,
        "os": {key: os_info[key] for key in ("Family", "Name") if isinstance(os_info, dict) and isinstance(os_info.get(key), str)},
    }


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

    if timeout <= 0:
        raise ImageScanError("timeout must be positive")
    command = [
        executable,
        "image",
        "--format",
        "json",
        "--scanners",
        "vuln,misconfig",
        image,
    ]
    document = _run_json(command, timeout)

    if not isinstance(document, dict):
        raise ImageScanError("Trivy JSON report must be an object")

    target = f"image://{image}"
    result = ScanResult(target=target, files_scanned=1)
    results = document.get("Results")
    if not isinstance(results, list) or not results:
        raise ImageScanError("Trivy JSON report has an invalid Results field")

    for section in results:
        if not isinstance(section, dict):
            raise ImageScanError("Trivy JSON report has an invalid result entry")
        if not isinstance(section.get("Target"), str) or not section["Target"].strip():
            raise ImageScanError("Trivy report section has no target")
        vulnerabilities = section.get("Vulnerabilities", [])
        if vulnerabilities is None:
            vulnerabilities = []
        if not isinstance(vulnerabilities, list):
            raise ImageScanError("Trivy JSON report contains an invalid Vulnerabilities field")
        for item in vulnerabilities:
            if not isinstance(item, dict) or any(not isinstance(item.get(key), str) or not item[key].strip() for key in ("VulnerabilityID", "PkgName", "InstalledVersion", "Severity")):
                raise ImageScanError("invalid vulnerability entry")
            result.findings.append(_finding_from_vulnerability(image, target, item))

        misconfigurations = section.get("Misconfigurations", [])
        if misconfigurations is None:
            misconfigurations = []
        if not isinstance(misconfigurations, list):
            raise ImageScanError("Trivy JSON report contains an invalid Misconfigurations field")
        for item in misconfigurations:
            if not isinstance(item, dict) or not isinstance(item.get("ID"), str) or not item["ID"].strip():
                raise ImageScanError("invalid misconfiguration entry")
            status = item.get("Status")
            if status == "PASS":
                continue
            if status == "EXCEPTION":
                result.warnings.append("Trivy reported an upstream exception; underlying check not assessed")
                result.coverage_complete = False
                continue
            if status not in {None, "FAIL"}:
                raise ImageScanError("Trivy returned an unsupported misconfiguration status")
            result.findings.append(_finding_from_misconfiguration(image, target, item))

        if not vulnerabilities and not misconfigurations and (section.get("Class") not in {"os-pkgs", "lang-pkgs", "config"} or not isinstance(section.get("Type"), str) or not section["Type"]):
            raise ImageScanError("Trivy clean section lacks assessment metadata")

    # Capture allowlisted version/database metadata; absence is disclosed.
    try:
        version = _run_json([executable, "version", "--format", "json"], min(timeout, 30), limit=1024 * 1024)
    except ImageScanError:
        version = {}
    result.provenance = _provenance(document, version)
    # De-duplicate repeated reports for the same check/package and location.
    unique: dict[tuple[str, str, str | None], Finding] = {}
    for finding in result.findings:
        unique.setdefault((finding.rule_id, finding.path, finding.resource), finding)
    result.findings = list(unique.values())
    return result
