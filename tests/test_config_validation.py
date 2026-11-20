import pytest
import yaml

from cloudsec_scanner.config import DEFAULT_CONFIG, load_config


def write_config(tmp_path, data):
    path = tmp_path / ".cloudsec.yml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(path)


def test_default_config_returns_independent_mutable_values():
    first = load_config(None)
    first["exclude"].append("custom/**")
    first["scanners"].clear()

    second = load_config(None)

    assert "custom/**" not in second["exclude"]
    assert second["scanners"] == ["iac", "secrets", "dependencies"]
    assert DEFAULT_CONFIG["scanners"] == ["iac", "secrets", "dependencies"]


def test_valid_config_is_loaded_and_severity_is_normalized(tmp_path):
    path = write_config(
        tmp_path,
        {
            "severity_threshold": "medium",
            "fail_on_findings": False,
            "max_file_bytes": 4096,
            "scanners": ["iac"],
            "exclude": ["vendor/**"],
            "exclude_rules": ["AWS-TF-001"],
        },
    )

    config = load_config(path)

    assert config["severity_threshold"] == "MEDIUM"
    assert config["fail_on_findings"] is False
    assert config["max_file_bytes"] == 4096
    assert config["scanners"] == ["iac"]
    assert config["exclude"] == ["vendor/**"]
    assert config["exclude_rules"] == ["AWS-TF-001"]


@pytest.mark.parametrize(
    "value",
    ["", "URGENT", "DEBUG", 1, None, True],
)
def test_invalid_severity_threshold_is_rejected(tmp_path, value):
    path = write_config(tmp_path, {"severity_threshold": value})

    with pytest.raises(ValueError, match="severity_threshold"):
        load_config(path)


@pytest.mark.parametrize(
    "scanners",
    [
        "iac",
        ["unknown"],
        ["iac", "unknown"],
        ["iac", "iac"],
        [1],
        [""],
        [None],
    ],
)
def test_invalid_scanner_configuration_is_rejected(tmp_path, scanners):
    path = write_config(tmp_path, {"scanners": scanners})

    with pytest.raises(ValueError, match="scanners|scanner"):
        load_config(path)


@pytest.mark.parametrize(
    "setting,value",
    [
        ("exclude", "vendor/**"),
        ("exclude", [1]),
        ("exclude", [""]),
        ("exclude_rules", "AWS-TF-001"),
        ("exclude_rules", [None]),
        ("exclude_rules", [""]),
    ],
)
def test_invalid_exclusion_configuration_is_rejected(tmp_path, setting, value):
    path = write_config(tmp_path, {setting: value})

    with pytest.raises(ValueError, match=setting):
        load_config(path)


@pytest.mark.parametrize("value", [0, -1, 1.5, True, "4096", None])
def test_invalid_max_file_bytes_is_rejected(tmp_path, value):
    path = write_config(tmp_path, {"max_file_bytes": value})

    with pytest.raises(ValueError, match="max_file_bytes"):
        load_config(path)


@pytest.mark.parametrize("value", [0, 1, "true", None, [], {}])
def test_fail_on_findings_must_be_boolean(tmp_path, value):
    path = write_config(tmp_path, {"fail_on_findings": value})

    with pytest.raises(ValueError, match="fail_on_findings"):
        load_config(path)


def test_unknown_configuration_key_is_rejected(tmp_path):
    path = write_config(tmp_path, {"severity_treshold": "HIGH"})

    with pytest.raises(ValueError, match="severity_treshold"):
        load_config(path)


@pytest.mark.parametrize("contents", ["- iac\n- secrets\n", "true\n", "42\n"])
def test_non_mapping_configuration_root_is_rejected(tmp_path, contents):
    path = tmp_path / ".cloudsec.yml"
    path.write_text(contents, encoding="utf-8")

    with pytest.raises(ValueError, match="root must be a YAML mapping"):
        load_config(str(path))


def test_missing_configuration_file_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="does not exist"):
        load_config(str(tmp_path / "missing.yml"))



@pytest.mark.parametrize(
    "value",
    [1, "true", None],
)
def test_fail_on_new_findings_must_be_boolean(tmp_path, value):
    path = write_config(tmp_path, {"fail_on_new_findings": value})
    with pytest.raises(ValueError, match="fail_on_new_findings"):
        load_config(path)


@pytest.mark.parametrize(
    "overrides",
    [
        [],
        {"": "HIGH"},
        {"AWS-TF-001": "URGENT"},
        {"AWS-TF-001": 1},
    ],
)
def test_invalid_severity_overrides_are_rejected(tmp_path, overrides):
    path = write_config(tmp_path, {"severity_overrides": overrides})
    with pytest.raises(ValueError, match="severity_overrides"):
        load_config(path)


def test_severity_overrides_are_normalized(tmp_path):
    path = write_config(
        tmp_path,
        {"severity_overrides": {"AWS-TF-001": "critical"}},
    )
    assert load_config(path)["severity_overrides"] == {"AWS-TF-001": "CRITICAL"}
