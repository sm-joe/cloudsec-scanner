"""CycloneDX 1.6 SBOM from supported resolved dependency inventories."""
from __future__ import annotations

from pathlib import Path
from packageurl import PackageURL

from cloudsec_scanner.dependency_scan import parse_dependencies
from cloudsec_scanner.discovery import discover
from cloudsec_scanner.config import DEFAULT_CONFIG
from cloudsec_scanner.lockfiles import LOCK_NAMES

PURL_TYPES = {"PyPI": "pypi", "npm": "npm", "Go": "golang", "crates.io": "cargo", "Packagist": "composer", "Maven": "maven", "RubyGems": "gem"}


def build_sbom(target: str):
    files, _, warnings = discover(target, DEFAULT_CONFIG["exclude"], DEFAULT_CONFIG["max_file_bytes"])
    if warnings:
        raise ValueError("SBOM inventory incomplete")
    components = {}
    manifests = 0
    for path in files:
        if path.name not in LOCK_NAMES:
            continue
        manifests += 1
        text = path.read_text(encoding="utf-8")
        if path.name == "requirements.txt":
            from cloudsec_scanner.dependency_scan import _REQUIREMENT_RE
            for line in text.splitlines():
                value = line.strip()
                if value and not value.startswith("#") and not _REQUIREMENT_RE.fullmatch(value.split(";", 1)[0].strip()):
                    raise ValueError("SBOM requires resolved dependency versions")
        for package in parse_dependencies(Path(path), text):
            name = package["name"]
            version = package["version"]
            ecosystem = package["ecosystem"]
            namespace = None
            if ecosystem == "Maven":
                namespace, name = name.split(":", 1)
            elif ecosystem in {"npm", "Go", "Packagist"} and "/" in name:
                namespace, name = name.rsplit("/", 1)
            purl = PackageURL(type=PURL_TYPES[ecosystem], namespace=namespace, name=name, version=version).to_string()
            components[purl] = {"type": "library", "bom-ref": purl, "name": name, "version": version, "purl": purl}
    if not manifests:
        raise ValueError("no supported resolved dependency files found")
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [components[key] for key in sorted(components)]}
