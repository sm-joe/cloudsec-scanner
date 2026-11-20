"""OSV-backed dependency vulnerability scanning."""

from __future__ import annotations

import json
import re
import time
from urllib.parse import quote
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cloudsec_scanner.models import Finding
from cloudsec_scanner.lockfiles import LOCK_NAMES, parse_extra_lock

OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"
REQUEST_TIMEOUT_SECONDS = 15
MAX_BATCH_SIZE = 1000
MAX_ADVISORIES = 2000
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}

_REQUIREMENT_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)\s*$"
)


class DependencyScanError(ValueError):
    """Raised when dependency data or OSV responses cannot be processed safely."""


def _normalize_severity(value: Any) -> str:
    """Normalize an OSV severity label, defaulting conservatively to HIGH."""
    if isinstance(value, str):
        normalized = value.strip().upper()
        if normalized in SEVERITY_ORDER:
            return normalized
    return "HIGH"


def _parse_requirements(text: str) -> list[dict[str, str]]:
    """Extract exact pinned dependencies from requirements.txt."""
    dependencies: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for line in text.splitlines():
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith(("-", ".", "git+", "http:", "https:")):
            continue

        requirement = stripped.split(";", 1)[0].strip()
        match = _REQUIREMENT_RE.fullmatch(requirement)
        if not match:
            continue

        name, version = match.groups()
        key = (name.lower().replace("_", "-"), version)

        if key in seen:
            continue

        seen.add(key)
        dependencies.append(
            {
                "name": name,
                "version": version,
                "ecosystem": "PyPI",
            }
        )

    return dependencies


def _parse_package_lock(text: str) -> list[dict[str, str]]:
    """Extract resolved npm dependencies from package-lock v2/v3."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DependencyScanError(f"malformed package-lock.json: {exc}") from exc

    if not isinstance(document, dict):
        raise DependencyScanError("package-lock.json must contain a JSON object")

    lock_version = document.get("lockfileVersion")
    if not isinstance(lock_version, int) or lock_version not in {2, 3}:
        raise DependencyScanError("only package-lock.json version 2 and 3 are supported")

    packages = document.get("packages")
    if not isinstance(packages, dict):
        raise DependencyScanError("package-lock.json is missing its packages object")

    dependencies: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for package_path, metadata in packages.items():
        if not isinstance(package_path, str) or not package_path:
            continue

        # The empty path describes the project itself, not an installed package.
        if package_path == "" or "node_modules/" not in package_path:
            continue

        if not isinstance(metadata, dict):
            raise DependencyScanError("invalid npm package entry")
        if metadata.get("link") is True:
            continue

        name = metadata.get("name")
        if not isinstance(name, str) or not name:
            name = package_path.rsplit("node_modules/", 1)[-1]

        version = metadata.get("version")
        if not isinstance(version, str) or not version:
            raise DependencyScanError("npm package missing resolved version")

        key = (name.lower(), version)
        if key in seen:
            continue

        seen.add(key)
        dependencies.append(
            {
                "name": name,
                "version": version,
                "ecosystem": "npm",
            }
        )

    return dependencies


def parse_dependencies(path: Path, text: str) -> list[dict[str, str]]:
    """Parse a supported dependency file into OSV package queries."""
    if path.name == "requirements.txt":
        return _parse_requirements(text)

    if path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
        return _parse_package_lock(text)
    if path.name in LOCK_NAMES:
        try:
            return parse_extra_lock(path, text)
        except (ValueError, TypeError) as exc:
            raise DependencyScanError("invalid or unsupported dependency lockfile") from exc

    return []


def _request_json(request, *, timeout=REQUEST_TIMEOUT_SECONDS):
    """Bound response size and retry only transient transport failures."""
    for attempt in range(3):
        try:
            with urlopen(request, timeout=timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise DependencyScanError("OSV response exceeds size budget")
            return json.loads(raw.decode("utf-8"))
        except HTTPError as exc:
            if exc.code not in {429, 502, 503, 504} or attempt == 2:
                raise DependencyScanError("OSV API request failed") from exc
        except (URLError, TimeoutError, OSError) as exc:
            if attempt == 2:
                raise DependencyScanError("OSV API request failed") from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DependencyScanError("OSV API returned invalid JSON") from exc
        time.sleep(0.25 * (2 ** attempt))
    raise DependencyScanError("OSV retry budget exhausted")


def _fetch_advisory(identifier):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", identifier):
        raise DependencyScanError("invalid OSV advisory identifier")
    request = Request(OSV_VULN_URL + quote(identifier, safe=""), headers={"Accept": "application/json", "User-Agent": "cloudsec-scanner"})
    advisory = _request_json(request)
    if not isinstance(advisory, dict) or advisory.get("id") != identifier:
        raise DependencyScanError("OSV advisory identity mismatch")
    return advisory


def _query_osv_batch(
    queries: list[dict[str, Any]],
    *,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> list[dict[str, Any]]:
    """Submit one batch to OSV and validate the returned result structure."""
    payload = json.dumps({"queries": queries}).encode("utf-8")
    request = Request(
        OSV_QUERY_BATCH_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "cloudsec-scanner",
        },
        method="POST",
    )

    data = _request_json(request, timeout=timeout)

    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise DependencyScanError("OSV API response is missing a results array")

    results = data["results"]
    if len(results) != len(queries):
        raise DependencyScanError("OSV API response count does not match the submitted query count")

    if not all(isinstance(item, dict) for item in results):
        raise DependencyScanError("OSV API returned an invalid result entry")

    # OSV querybatch returns advisory IDs and modification timestamps,
    # not full advisory metadata. Resolve each unique ID once per batch.
    advisories = {}
    for result in results:
        entries = result.get("vulns", [])
        if not isinstance(entries, list):
            raise DependencyScanError("OSV API returned an invalid vulns array")
        resolved = []
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                raise DependencyScanError("OSV API returned an invalid advisory")
            identifier = entry["id"]
            if identifier not in advisories:
                if len(advisories) >= MAX_ADVISORIES:
                    raise DependencyScanError("OSV advisory budget exceeded")
                advisories[identifier] = _fetch_advisory(identifier)
            advisory = advisories[identifier]
            if not advisory.get("withdrawn"):
                resolved.append(advisory)
        result["vulns"] = resolved
    return results


def _vulnerability_severity(vulnerability: dict[str, Any]) -> str:
    """Use the database's explicit severity when available."""
    from cvss import CVSS3, CVSS4

    known = []
    database_specific = vulnerability.get("database_specific")
    if isinstance(database_specific, dict):
        label = database_specific.get("severity")
        if isinstance(label, str) and label.upper() in SEVERITY_ORDER:
            known.append(label.upper())
    entries = vulnerability.get("severity", [])
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("score"), str):
                continue
            try:
                vector = entry["score"]
                if entry.get("type") == "CVSS_V3":
                    score = CVSS3(vector).scores()[0]
                elif entry.get("type") == "CVSS_V4":
                    score = CVSS4(vector).scores()[0]
                else:
                    continue
                known.append("CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW")
            except Exception:
                # Invalid or unsupported vectors cannot downgrade severity.
                known.append("HIGH")
    return min(known, key=SEVERITY_ORDER.get) if known else "HIGH"


def _finding(
    path: Path,
    dependency: dict[str, str],
    vulnerability: dict[str, Any],
) -> Finding:
    """Convert an OSV vulnerability into the scanner's normalized finding model."""
    vulnerability_id = vulnerability.get("id")
    if not isinstance(vulnerability_id, str) or not vulnerability_id.strip():
        vulnerability_id = "OSV-UNKNOWN"

    summary = vulnerability.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        summary = "A known vulnerability affects this dependency version."

    package_name = dependency["name"]
    version = dependency["version"]
    severity = _vulnerability_severity(vulnerability)

    references = vulnerability.get("references")
    advisory_url = None
    if isinstance(references, list):
        for reference in references:
            if not isinstance(reference, dict):
                continue
            url = reference.get("url")
            if isinstance(url, str) and url.startswith("https://"):
                advisory_url = url
                break

    remediation = (
        f"Upgrade {package_name} from {version} to a patched version. "
        "Review the OSV advisory and compatibility requirements before updating."
    )

    if advisory_url:
        remediation += f" Advisory: {advisory_url}"

    return Finding(
        "SCA-OSV-001",
        f"Vulnerable dependency: {package_name}",
        severity,
        f"{vulnerability_id}: {summary}",
        str(path),
        1,
        f"{package_name}@{version}",
        "dependency",
        None,
        remediation,
        (),
        (),
        f"OSV: {vulnerability_id}",
    )


def scan_dependencies(
    path: Path,
    text: str,
    *,
    query_batch=_query_osv_batch,
) -> list[Finding]:
    """Scan supported dependency files against OSV."""
    dependencies = parse_dependencies(path, text)
    findings: list[Finding] = []

    if path.name == "requirements.txt":
        # A pin-only scan must not silently certify unresolved dependencies.
        for line in text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and not _REQUIREMENT_RE.fullmatch(stripped.split(";", 1)[0].strip()):
                raise DependencyScanError("unresolved requirements entry; supply a fully pinned requirements file")

    for offset in range(0, len(dependencies), MAX_BATCH_SIZE):
        batch = dependencies[offset : offset + MAX_BATCH_SIZE]
        queries = [
            {
                "package": {
                    "name": dependency["name"],
                    "ecosystem": dependency["ecosystem"],
                },
                "version": dependency["version"],
            }
            for dependency in batch
        ]

        results = query_batch(queries)

        if len(results) != len(batch):
            raise DependencyScanError(
                "OSV API response count does not match the submitted query count"
            )

        for dependency, result in zip(batch, results, strict=True):
            if not isinstance(result, dict):
                raise DependencyScanError("OSV API returned an invalid result entry")
            vulnerabilities = result.get("vulns", [])
            if not isinstance(vulnerabilities, list):
                raise DependencyScanError("OSV API returned an invalid vulns array")

            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict) or not isinstance(vulnerability.get("id"), str) or not vulnerability["id"].strip():
                    raise DependencyScanError("OSV API returned an invalid advisory")
                findings.append(_finding(path, dependency, vulnerability))

    # A package can be reported by multiple records; keep each advisory once.
    unique: dict[tuple[str, str, str], Finding] = {}
    for finding in findings:
        key = (
            finding.resource or "",
            finding.rule_id,
            finding.evidence or "",
        )
        unique[key] = finding

    return list(unique.values())
