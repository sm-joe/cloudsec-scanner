"""Opt-in local path minimization for exported scan reports."""
from dataclasses import replace
from pathlib import Path

from cloudsec_scanner.comparison import _relative_finding


def relative_report(result):
    if result.target.startswith(("image://", "aws://")):
        return result
    root = result.target.replace("\\", "/").rstrip("/")
    absolute = str(Path(result.target).resolve()).replace("\\", "/").rstrip("/")
    def relative(path):
        return _relative_finding({"path": path}, {"target": result.target})["path"]
    def scrub(text):
        normalized = text.replace("\\", "/")
        for value in sorted({root, absolute}, key=len, reverse=True):
            if value and value != ".":
                normalized = normalized.replace(value + "/", "")
                if normalized.startswith(value + ":"):
                    normalized = "." + normalized[len(value):]
        return normalized
    return replace(result, target=".", project_key="", findings=[replace(item, path=relative(item.path)) for item in result.findings],
                   assessments=[{**entry, "path": relative(entry["path"])} for entry in result.assessments],
                   warnings=[scrub(item) for item in result.warnings], errors=[scrub(item) for item in result.errors])
