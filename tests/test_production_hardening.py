import json

import pytest

from cloudsec_scanner.safe_input import safe_json_document, safe_yaml_documents
from cloudsec_scanner.models import ScanResult
from cloudsec_scanner.report import write_report
from cloudsec_scanner.scanner import scan_target
from cloudsec_scanner.config import load_config


@pytest.mark.parametrize("source", ['{"x": 1, "x": 2}', '{"x": NaN}', '{"x": Infinity}'])
def test_ambiguous_json_rejected(source):
    with pytest.raises(ValueError):
        safe_json_document(source)


def test_json_duplicate_blocks_assessment(tmp_path):
    path = tmp_path / "config.json"
    path.write_text('{"kind":"Pod","kind":"Service"}')
    result = scan_target(str(path), load_config(None))
    assert not result.coverage_complete
    assert result.errors


def test_recursive_yaml_rejected_before_construction():
    with pytest.raises(ValueError, match="complexity"):
        safe_yaml_documents("loop: &loop [*loop]")


def test_expanded_alias_bomb_rejected():
    lines = ["a0: &a0 [1, 2]"]
    for i in range(1, 20):
        lines.append(f"a{i}: &a{i} [*a{i-1}, *a{i-1}]")
    with pytest.raises(ValueError, match="complexity"):
        safe_yaml_documents("\n".join(lines))


def test_safe_aliases_still_supported():
    assert safe_yaml_documents("base: &base {x: 1}\ncopy: *base")[0]["copy"] == {"x": 1}


def test_duplicate_merge_rejected():
    with pytest.raises(ValueError, match="duplicate YAML merge"):
        safe_yaml_documents("x: {<<: {a: 1}, <<: {b: 2}}")


def test_atomic_report_replaces_existing(tmp_path):
    path = tmp_path / "report.json"
    path.write_text("old")
    write_report(ScanResult("sample"), "json", str(path))
    assert json.loads(path.read_text())["target"] == "sample"
    assert list(tmp_path.iterdir()) == [path]


def test_atomic_report_preserves_previous_on_failure(tmp_path, monkeypatch):
    path = tmp_path / "report.json"
    path.write_text("old")
    def fail(*args):
        raise OSError("simulated failure")
    monkeypatch.setattr("cloudsec_scanner.report.os.replace", fail)
    with pytest.raises(OSError):
        write_report(ScanResult("sample"), "json", str(path))
    assert path.read_text() == "old"
    assert list(tmp_path.iterdir()) == [path]
