"""Resolved package inventories, shared by SCA and SBOM generation."""
from __future__ import annotations

import re
import json
import tomllib
from pathlib import Path

from cloudsec_scanner.safe_input import safe_yaml_documents

LOCK_NAMES = frozenset({"requirements.txt", "package-lock.json", "npm-shrinkwrap.json", "poetry.lock", "uv.lock", "pnpm-lock.yaml", "go.sum", "Cargo.lock", "Gemfile.lock", "gradle.lockfile", "composer.lock"})


def _package(name, version, ecosystem):
    if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
        raise ValueError("lockfile package missing name or resolved version")
    return {"name": name, "version": version, "ecosystem": ecosystem}


def parse_extra_lock(path: Path, text: str):
    packages = []
    if path.name in {"poetry.lock", "uv.lock", "Cargo.lock"}:
        document = tomllib.loads(text)
        entries = document.get("package")
        if not isinstance(entries, list):
            raise ValueError("lockfile missing package array")
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("invalid lockfile entry")
            if path.name == "uv.lock" and isinstance(entry.get("source"), dict) and any(k in entry["source"] for k in ("editable", "virtual", "directory")):
                continue
            if path.name == "Cargo.lock" and not entry.get("source"):
                continue
            if path.name == "poetry.lock" and isinstance(entry.get("source"), dict) and entry["source"].get("type") in {"directory", "file"}:
                continue
            packages.append(_package(entry.get("name"), entry.get("version"), "crates.io" if path.name == "Cargo.lock" else "PyPI"))
    elif path.name == "composer.lock":
        document = json.loads(text)
        if not isinstance(document, dict) or not isinstance(document.get("packages"), list):
            raise ValueError("invalid Composer lockfile")
        for section in ("packages", "packages-dev"):
            entries = document.get(section, [])
            if not isinstance(entries, list):
                raise ValueError("invalid Composer package array")
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ValueError("invalid Composer package")
                name, version = entry.get("name"), entry.get("version")
                if not isinstance(name, str) or "/" not in name or not isinstance(version, str) or not re.match(r"^v?\d", version):
                    raise ValueError("unsupported Composer resolved package")
                packages.append(_package(name, version, "Packagist"))
    elif path.name == "gradle.lockfile":
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("empty="):
                continue
            match = re.fullmatch(r"([^:\s=]+):([^:\s=]+):([^:\s=]+)=(.+)", line)
            if not match or not re.match(r"^\d", match[3]):
                raise ValueError("invalid or unresolved Gradle lock entry")
            packages.append(_package(match[1] + ":" + match[2], match[3], "Maven"))
    elif path.name == "Gemfile.lock":
        in_gem = False
        in_specs = False
        recognized = False
        for line in text.splitlines():
            if line and not line[0].isspace():
                if line in {"GIT", "PATH", "PLUGIN"}:
                    raise ValueError("non-registry Ruby dependencies are unsupported")
                in_gem = line == "GEM"
                in_specs = False
                recognized = recognized or in_gem
            elif in_gem and line == "  specs:":
                in_specs = True
            elif in_specs and re.match(r"^ {4}\S", line):
                match = re.fullmatch(r" {4}([^\s]+) \(([^()\s]+)\)", line)
                if not match:
                    raise ValueError("invalid Ruby lock entry")
                version = match[2]
                # Bundler can append platform names to resolved gem versions.
                version = version.split("-", 1)[0]
                if not re.match(r"^\d", version):
                    raise ValueError("unresolved Ruby version")
                packages.append(_package(match[1], version, "RubyGems"))
        if not recognized:
            raise ValueError("Ruby lockfile missing GEM section")
    elif path.name == "go.sum":
        for line in text.splitlines():
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) != 3 or not parts[1].startswith("v") or not parts[2].startswith("h1:"):
                raise ValueError("invalid go.sum entry")
            packages.append(_package(parts[0], parts[1].removesuffix("/go.mod"), "Go"))
    elif path.name == "pnpm-lock.yaml":
        docs = safe_yaml_documents(text)
        if len(docs) != 1 or not isinstance(docs[0], dict):
            raise ValueError("invalid pnpm lockfile")
        document = docs[0]
        version = str(document.get("lockfileVersion", ""))
        if not version.startswith(("6.", "9.")):
            raise ValueError("unsupported pnpm lockfile version; supported versions are 6 and 9")
        entries = document.get("packages", {})
        if not isinstance(entries, dict):
            raise ValueError("invalid pnpm package mapping")
        for key in entries:
            if not isinstance(key, str):
                raise ValueError("invalid pnpm package key")
            key = key.lstrip("/").split("(", 1)[0]
            match = re.fullmatch(r"((?:@[^/]+/)?[^@/]+)@([^@/]+)", key)
            if not match:
                raise ValueError("unsupported pnpm package reference")
            packages.append(_package(match[1], match[2], "npm"))
    else:
        raise ValueError("unsupported lockfile")
    return list({(p["ecosystem"], p["name"], p["version"]): p for p in packages}.values())
