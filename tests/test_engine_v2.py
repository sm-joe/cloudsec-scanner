import json
from pathlib import Path

import pytest

from cloudsec_scanner.dependency_scan import parse_dependencies, scan_dependencies, DependencyScanError
from cloudsec_scanner.comparison import finding_identity
from cloudsec_scanner.sbom import build_sbom
from cloudsec_scanner.cli import main


@pytest.mark.parametrize("filename, source, name, version, ecosystem", [
    ("poetry.lock", '[[package]]\nname="requests"\nversion="2.31.0"\n', "requests", "2.31.0", "PyPI"),
    ("uv.lock", '[[package]]\nname="requests"\nversion="2.31.0"\n', "requests", "2.31.0", "PyPI"),
    ("Cargo.lock", '[[package]]\nname="serde"\nversion="1.0.0"\nsource="registry+example"\n', "serde", "1.0.0", "crates.io"),
    ("go.sum", "example.org/mod v1.2.0 h1:checksum\nexample.org/mod v1.2.0/go.mod h1:checksum\n", "example.org/mod", "v1.2.0", "Go"),
    ("pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  '@scope/pkg@1.2.3': {}\n", "@scope/pkg", "1.2.3", "npm"),
])
def test_lockfiles(filename, source, name, version, ecosystem):
    assert parse_dependencies(Path(filename), source) == [{"name": name, "version": version, "ecosystem": ecosystem}]


def test_requirements_unresolved_fail_closed():
    with pytest.raises(DependencyScanError, match="unresolved"):
        scan_dependencies(Path("requirements.txt"), "requests>=2", query_batch=lambda q: [])


def test_malformed_advisory_fails_closed():
    with pytest.raises(DependencyScanError, match="invalid advisory"):
        scan_dependencies(Path("requirements.txt"), "requests==2.31.0", query_batch=lambda q: [{"vulns": [{}]}])


def test_workspace_nested_package():
    payload = {"lockfileVersion": 3, "packages": {"apps/app/node_modules/lodash": {"version": "4.17.20"}}}
    assert parse_dependencies(Path("package-lock.json"), json.dumps(payload))[0]["name"] == "lodash"


def test_scoped_dependency_identity_stable():
    item = {"rule_id": "SCA-OSV-001", "path": "package-lock.json", "category": "dependency", "resource": "@scope/pkg@1", "evidence": "OSV: a"}
    assert finding_identity(item) == finding_identity({**item, "resource": "@scope/pkg@2"})
    assert finding_identity(item) != finding_identity({**item, "evidence": "OSV: b"})


def test_sbom_export(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    output = tmp_path / "bom.json"
    assert main(["sbom", str(tmp_path), "--output", str(output)]) == 0
    document = json.loads(output.read_text())
    assert document["bomFormat"] == "CycloneDX"
    assert document["components"][0]["purl"] == "pkg:pypi/requests@2.31.0"


def test_sbom_unresolved_rejected(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("requests>=2\n")
    with pytest.raises(ValueError, match="resolved"):
        build_sbom(str(path))


def test_sbom_no_manifests_rejected(tmp_path):
    with pytest.raises(ValueError, match="no supported"):
        build_sbom(str(tmp_path))
