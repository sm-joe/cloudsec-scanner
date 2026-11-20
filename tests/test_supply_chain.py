import json
from pathlib import Path

import pytest

from cloudsec_scanner import dependency_scan as osv
from cloudsec_scanner.sbom import build_sbom


@pytest.mark.parametrize("filename, contents, name, version, ecosystem", [
    ("composer.lock", '{"packages":[{"name":"vendor/library","version":"1.2.3"}]}', "vendor/library", "1.2.3", "Packagist"),
    ("gradle.lockfile", "org.example:library:1.2.3=runtimeClasspath\n", "org.example:library", "1.2.3", "Maven"),
    ("Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.0.0)\n      dep (~> 1)\n", "rack", "3.0.0", "RubyGems"),
])
def test_extra_lockfiles(filename, contents, name, version, ecosystem):
    assert osv.parse_dependencies(Path(filename), contents) == [{"name": name, "version": version, "ecosystem": ecosystem}]


def test_osv_batch_fetches_unique_full_advisories(monkeypatch):
    calls = []
    def request(req, **kwargs):
        calls.append(req.full_url)
        if req.full_url.endswith("querybatch"):
            return {"results": [{"vulns": [{"id": "OSV-TEST"}]}, {"vulns": [{"id": "OSV-TEST"}]}]}
        return {"id": "OSV-TEST", "summary": "Full advisory", "database_specific": {"severity": "CRITICAL"}}
    monkeypatch.setattr(osv, "_request_json", request)
    results = osv._query_osv_batch([{}, {}])
    assert len(calls) == 2
    assert results[0]["vulns"][0]["summary"] == "Full advisory"
    assert osv._vulnerability_severity(results[1]["vulns"][0]) == "CRITICAL"


def test_withdrawn_advisory_omitted(monkeypatch):
    monkeypatch.setattr(osv, "_request_json", lambda req, **kw: {"results": [{"vulns": [{"id": "OSV-TEST"}]}]})
    monkeypatch.setattr(osv, "_fetch_advisory", lambda identifier: {"id": identifier, "withdrawn": "2025-01-01T00:00:00Z"})
    assert osv._query_osv_batch([{}]) == [{"vulns": []}]


def test_osv_mismatched_details_rejected(monkeypatch):
    monkeypatch.setattr(osv, "_request_json", lambda *a, **kw: {"id": "OTHER"})
    with pytest.raises(osv.DependencyScanError, match="identity mismatch"):
        osv._fetch_advisory("OSV-TEST")


def test_cvss_vector():
    assert osv._vulnerability_severity({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}) == "CRITICAL"


def test_invalid_cvss_cannot_downgrade():
    assert osv._vulnerability_severity({"database_specific": {"severity": "LOW"}, "severity": [{"type": "CVSS_V3", "score": "invalid"}]}) == "HIGH"


def test_maven_sbom_purl(tmp_path):
    path = tmp_path / "gradle.lockfile"
    path.write_text("org.example:library:1.2.3=runtimeClasspath\n")
    component = build_sbom(str(path))["components"][0]
    assert component["purl"] == "pkg:maven/org.example/library@1.2.3"


def test_scoped_npm_sbom(tmp_path):
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps({"lockfileVersion": 3, "packages": {"node_modules/@scope/pkg": {"version": "1.0.0"}}}))
    assert build_sbom(str(path))["components"][0]["purl"] == "pkg:npm/%40scope/pkg@1.0.0"
