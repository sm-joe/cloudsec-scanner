"""Configuration loading and validation."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "exclude": [
        ".git/**",
        ".venv/**",
        "venv/**",
        "node_modules/**",
        "dist/**",
        "build/**",
    ],
    "exclude_rules": [],
    "severity_threshold": "HIGH",
    "fail_on_findings": True,
    "fail_on_new_findings": False,
    "severity_overrides": {},
    "max_file_bytes": 2 * 1024 * 1024,
    "scanners": ["iac", "secrets", "dependencies"],
}

ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
ALLOWED_SCANNERS = {"iac", "secrets", "dependencies"}
DEFAULT_SCANNERS = ["iac", "secrets", "dependencies"]
ALLOWED_CONFIG_KEYS = frozenset(DEFAULT_CONFIG)


def _validate_string_list(value: Any, setting: str) -> list[str]:
    """Validate a list of non-empty strings without coercing values."""
    if not isinstance(value, list):
        raise ValueError(f"{setting} must be a list of strings")

    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{setting} must contain only non-empty strings")

    return value


def _validate_config(config: dict[str, Any]) -> dict[str, Any]:
    unknown_keys = set(config) - ALLOWED_CONFIG_KEYS
    if unknown_keys:
        names = ", ".join(sorted(str(key) for key in unknown_keys))
        raise ValueError(f"unknown configuration key(s): {names}")

    threshold = config["severity_threshold"]
    if not isinstance(threshold, str):
        raise ValueError("severity_threshold must be CRITICAL, HIGH, MEDIUM, LOW, or INFO")

    threshold = threshold.upper()
    if threshold not in ALLOWED_SEVERITIES:
        raise ValueError("severity_threshold must be CRITICAL, HIGH, MEDIUM, LOW, or INFO")
    config["severity_threshold"] = threshold

    config["exclude"] = _validate_string_list(config["exclude"], "exclude")
    config["exclude_rules"] = _validate_string_list(config["exclude_rules"], "exclude_rules")

    scanners = _validate_string_list(config["scanners"], "scanners")
    invalid_scanners = set(scanners) - ALLOWED_SCANNERS
    if invalid_scanners:
        names = ", ".join(sorted(invalid_scanners))
        raise ValueError(
            f"unsupported scanner(s): {names}; allowed scanners are: "
            f"{', '.join(sorted(ALLOWED_SCANNERS))}"
        )
    if not scanners:
        raise ValueError("at least one scanner is required")
    if len(scanners) != len(set(scanners)):
        raise ValueError("scanners must not contain duplicate entries")

    if not isinstance(config["fail_on_findings"], bool):
        raise ValueError("fail_on_findings must be a boolean")
    if not isinstance(config["fail_on_new_findings"], bool):
        raise ValueError("fail_on_new_findings must be a boolean")

    overrides = config["severity_overrides"]
    if not isinstance(overrides, dict):
        raise ValueError("severity_overrides must be a mapping of rule IDs to severities")
    normalized_overrides: dict[str, str] = {}
    for rule_id, severity in overrides.items():
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise ValueError("severity_overrides keys must be non-empty rule IDs")
        if not isinstance(severity, str) or severity.upper() not in ALLOWED_SEVERITIES:
            raise ValueError(
                "severity_overrides values must be CRITICAL, HIGH, MEDIUM, LOW, or INFO"
            )
        normalized_overrides[rule_id] = severity.upper()
    config["severity_overrides"] = normalized_overrides

    max_file_bytes = config["max_file_bytes"]
    if isinstance(max_file_bytes, bool) or not isinstance(max_file_bytes, int):
        raise ValueError("max_file_bytes must be a positive integer")
    if max_file_bytes <= 0:
        raise ValueError("max_file_bytes must be a positive integer")

    return config


def load_config(path: str | None) -> dict[str, Any]:
    """Load, merge, and validate configuration."""
    config = deepcopy(DEFAULT_CONFIG)
    config["scanners"] = list(DEFAULT_SCANNERS)

    if path is None:
        return config

    config_path = Path(path)
    if not config_path.is_file():
        raise ValueError(f"configuration file does not exist: {config_path}")

    try:
        from cloudsec_scanner.safe_input import safe_yaml_documents
        docs = safe_yaml_documents(config_path.read_text(encoding="utf-8"))
        if len(docs) > 1:
            raise ValueError("configuration must contain one YAML document")
        loaded = docs[0] if docs else None
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError(f"could not read configuration {config_path}: {exc}") from exc

    if loaded is None:
        loaded = {}

    if not isinstance(loaded, dict):
        raise ValueError("configuration root must be a YAML mapping")

    config.update(loaded)
    return _validate_config(config)


def write_default_config(path: str) -> None:
    """Write the default configuration to a file."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as stream:
        stream.write(yaml.safe_dump(DEFAULT_CONFIG, sort_keys=False))
