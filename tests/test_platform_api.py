"""Platform access isolation, job persistence and worker acceptance."""
import json

import pytest
from fastapi.testclient import TestClient
from cloudsec_scanner.platform.api import create_app
from cloudsec_scanner.platform.worker import run_once

# Synthetic credentials are restricted to test fixtures.
AUTH_A = {"Authorization": "Bearer " + "a" * 40}
AUTH_B = {"Authorization": "Bearer " + "b" * 40}


@pytest.fixture
def platform(tmp_path):
    root = tmp_path / "workspace"
    for owner in ("alice", "bob"):
        directory = root / owner
        directory.mkdir(parents=True)
        (directory / "main.tf").write_text('resource "aws_ebs_volume" "example" { encrypted = false }')
    app = create_app("sqlite:///" + str(tmp_path / "db.sqlite"), root, json.dumps({"a" * 40: "alice", "b" * 40: "bob"}))
    with TestClient(app) as client:
        yield client, app.state.engine, root


def project(client, auth=AUTH_A):
    response = client.post("/api/v1/projects", json={"name": "Example"}, headers=auth)
    assert response.status_code == 201
    return response.json()["id"]


def enqueue(client, pid, auth=AUTH_A, **kwargs):
    return client.post(f"/api/v1/projects/{pid}/scans", headers=auth, json={"target": "main.tf", **kwargs})


def test_authentication_required(platform):
    client, _, _ = platform
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").status_code == 200
    assert client.get("/api/v1/projects").status_code == 401


def test_project_and_scan_isolation(platform):
    client, _, _ = platform
    pid = project(client)
    assert client.get("/api/v1/projects", headers=AUTH_B).json() == []
    assert enqueue(client, pid, AUTH_B).status_code == 404
    sid = enqueue(client, pid).json()["id"]
    assert client.get(f"/api/v1/scans/{sid}", headers=AUTH_B).status_code == 404
    assert client.get(f"/api/v1/scans/{sid}/report", headers=AUTH_B).status_code == 404
    assert client.post(f"/api/v1/scans/{sid}/cancel", headers=AUTH_B).status_code == 404


def test_worker_persists_real_scanner_report(platform):
    client, engine, root = platform
    sid = enqueue(client, project(client)).json()["id"]
    assert run_once(engine, root)
    assert not run_once(engine, root)
    row = client.get(f"/api/v1/scans/{sid}", headers=AUTH_A).json()
    assert row["status"] == "SUCCEEDED"
    assert row["complete"]
    report = client.get(f"/api/v1/scans/{sid}/report", headers=AUTH_A).json()
    assert any(f["rule_id"] == "AWS-TF-003" for f in report["findings"])


def test_queue_idempotency(platform):
    client, _, _ = platform
    pid = project(client)
    headers = {**AUTH_A, "Idempotency-Key": "sample"}
    a = enqueue(client, pid, headers)
    b = enqueue(client, pid, headers)
    assert a.status_code == b.status_code == 202
    assert a.json()["id"] == b.json()["id"]


def test_cancel_queued_job(platform):
    client, engine, root = platform
    sid = enqueue(client, project(client)).json()["id"]
    assert client.post(f"/api/v1/scans/{sid}/cancel", headers=AUTH_A).status_code == 200
    assert not run_once(engine, root)


@pytest.mark.parametrize("path", ["../bob/main.tf", "/etc/passwd", ".", "absent"])
def test_rejects_unsafe_workspace_targets(platform, path):
    client, _, _ = platform
    pid = project(client)
    assert enqueue(client, pid, target=path).status_code == 400


def test_symlink_rejected(platform):
    client, _, root = platform
    (root / "alice" / "link").symlink_to(root / "bob" / "main.tf")
    assert enqueue(client, project(client), target="link").status_code == 400


def test_worker_failure_is_persisted(platform):
    client, engine, root = platform
    sid = enqueue(client, project(client)).json()["id"]
    (root / "alice" / "main.tf").write_text("resource {")
    assert run_once(engine, root)
    assert client.get(f"/api/v1/scans/{sid}", headers=AUTH_A).json()["status"] == "FAILED"


def test_dashboard_isolation(platform):
    client, _, _ = platform
    enqueue(client, project(client))
    assert client.get("/api/v1/dashboard", headers=AUTH_A).json()["scans_by_status"] == {"QUEUED": 1}
    assert client.get("/api/v1/dashboard", headers=AUTH_B).json()["projects"] == 0
