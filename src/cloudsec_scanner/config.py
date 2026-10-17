"""Configuration loading and validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "exclude": [".git/**", ".venv/**", "venv/**", "node_modules/**", "dist/**", "build/**"],
    "exclude_rules": [],
    "severity_threshold": "HIGH",
    "fail_on_findings": True,
    "max_file_bytes": 2 * 1024 * 1024,
    "scanners": ["iac", "secrets"],
}


def load_config(path: str | None) -> dict[str, Any]:
    config = dict(DEFAULT_CONFIG)
    if path is None:
        return config
    config_path = Path(path)
    if not config_path.is_file():
        raise ValueError(f"configuration file does not exist: {config_path}")
    try:
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"could not read configuration {config_path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError("configuration root must be a YAML mapping")
    config.update(loaded)
    threshold = str(config.get("severity_threshold", "HIGH")).upper()
    if threshold not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        raise ValueError("severity_threshold must be CRITICAL, HIGH, MEDIUM, LOW, or INFO")
    config["severity_threshold"] = threshold
    if not isinstance(config.get("exclude", []), list) or not all(isinstance(x, str) for x in config["exclude"]):
        raise ValueError("exclude must be a list of glob patterns")
    if not isinstance(config.get("exclude_rules", []), list):
        raise ValueError("exclude_rules must be a list of rule IDs")
    try:
        config["max_file_bytes"] = int(config["max_file_bytes"])
    except (TypeError, ValueError) as exc:
        raise ValueError("max_file_bytes must be a positive integer") from exc
    if config["max_file_bytes"] <= 0:
        raise ValueError("max_file_bytes must be a positive integer")
    return config


def write_default_config(path: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(yaml.safe_dump(DEFAULT_CONFIG, sort_keys=False), encoding="utf-8")
