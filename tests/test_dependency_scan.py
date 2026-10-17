import json

import pytest

from cloudsec_scanner.dependency_scan import (
    DependencyScanError,
    parse_dependencies,
    scan_dependencies,
)


def test_parses_only_exactly_pinned_python_requirements(tmp_path):
    path = tmp_path / "requirements.txt"
    text = """
# Comment
requests==2.31.0
PyYAML==6.0.2
requests>=2.0
-e .
"""

    dependencies = parse_dependencies(path, text)

    assert dependencies == [
        {"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"},
        {"name": "PyYAML", "version": "6.0.2", "ecosystem": "PyPI"},
    ]


def test_deduplicates_python_requirements(tmp_path):
    path = tmp_path / "requirements.txt"

    dependencies = parse_dependencies(
        path,
        "requests==2.31.0\nrequests==2.31.0\n",
    )

    assert len(dependencies) == 1


def test_parses_npm_lockfile_v3(tmp_path):
    path = tmp_path / "package-lock.json"
    text = json.dumps(
        {
            "name": "sample",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "sample", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.20"},
                "node_modules/@scope/pkg": {
                    "version": "1.2.3",
                    "name": "@scope/pkg",
                },
            },
        }
    )

    dependencies = parse_dependencies(path, text)

    assert dependencies == [
        {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
        {"name": "@scope/pkg", "version": "1.2.3", "ecosystem": "npm"},
    ]


def test_rejects_malformed_package_lock(tmp_path):
    with pytest.raises(DependencyScanError, match="malformed package-lock"):
        parse_dependencies(tmp_path / "package-lock.json", "{broken")


def test_rejects_unsupported_package_lock_version(tmp_path):
    text = json.dumps({"lockfileVersion": 1, "dependencies": {}})

    with pytest.raises(DependencyScanError, match="version 2 and 3"):
        parse_dependencies(tmp_path / "package-lock.json", text)


def test_returns_no_findings_when_osv_has_no_vulnerabilities(tmp_path):
    path = tmp_path / "requirements.txt"

    findings = scan_dependencies(
        path,
        "requests==2.31.0\n",
        query_batch=lambda queries: [{"vulns": []} for _ in queries],
    )

    assert findings == []


def test_maps_osv_vulnerability_to_normalized_finding(tmp_path):
    path = tmp_path / "requirements.txt"

    findings = scan_dependencies(
        path,
        "requests==2.31.0\n",
        query_batch=lambda queries: [
            {
                "vulns": [
                    {
                        "id": "GHSA-test-1234-5678",
                        "summary": "Example vulnerability",
                        "database_specific": {"severity": "CRITICAL"},
                        "references": [
                            {
                                "type": "ADVISORY",
                                "url": "https://example.com/advisory",
                            }
                        ],
                    }
                ]
            }
            for _ in queries
        ],
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "SCA-OSV-001"
    assert finding.severity == "CRITICAL"
    assert finding.category == "dependency"
    assert finding.resource == "requests@2.31.0"
    assert "GHSA-test-1234-5678" in finding.message
    assert "https://example.com/advisory" in finding.remediation


def test_defaults_to_high_when_osv_severity_is_missing(tmp_path):
    findings = scan_dependencies(
        tmp_path / "requirements.txt",
        "requests==2.31.0\n",
        query_batch=lambda queries: [
            {"vulns": [{"id": "OSV-TEST-1", "summary": "Test advisory"}]} for _ in queries
        ],
    )

    assert findings[0].severity == "HIGH"


def test_rejects_osv_result_count_mismatch(tmp_path):
    with pytest.raises(DependencyScanError, match="does not match"):
        scan_dependencies(
            tmp_path / "requirements.txt",
            "requests==2.31.0\nPyYAML==6.0.2\n",
            query_batch=lambda queries: [],
        )


def test_rejects_invalid_osv_vulnerability_list(tmp_path):
    with pytest.raises(DependencyScanError, match="invalid vulns"):
        scan_dependencies(
            tmp_path / "requirements.txt",
            "requests==2.31.0\n",
            query_batch=lambda queries: [{"vulns": "not-a-list"}],
        )


def test_ignores_unsupported_file_names(tmp_path):
    findings = scan_dependencies(
        tmp_path / "pyproject.toml",
        '[project]\ndependencies = ["requests==2.31.0"]\n',
        query_batch=lambda queries: [],
    )

    assert findings == []
