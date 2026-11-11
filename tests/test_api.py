import sqlite3
import threading
import time
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from sentinel_audit.api import create_app
from sentinel_audit.storage import ScanStore


def client_for(path, runner):
    return TestClient(create_app(path, runner=runner), base_url="http://127.0.0.1")


def headers(client):
    return {"x-sentinel-token": client.get("/api/session").json()["token"]}


def wait_scan(client, scan_id):
    for _ in range(100):
        scan = client.get(f"/api/scans/{scan_id}").json()
        if scan["status"] in {"completed", "failed"}:
            return scan
        time.sleep(0.01)
    pytest.fail("Scan did not finish")


def test_lifecycle_and_persistence(tmp_path):
    path = tmp_path / "scans.db"
    report = {"findings": [], "system_info": {"hostname": "test-host"}}
    with client_for(path, lambda **kwargs: report) as client:
        response = client.post("/api/scans", json={}, headers=headers(client))
        assert response.status_code == 202
        scan_id = response.json()["id"]
        scan = wait_scan(client, scan_id)
        assert scan["status"] == "completed"
        assert scan["report"] == report
        assert scan["duration_seconds"] >= 0
        assert scan["created_at"].endswith("+00:00")
    with client_for(path, lambda **kwargs: report) as client:
        history = client.get("/api/scans").json()
        assert history["total"] == 1
        assert "report" not in history["items"][0]
        assert client.get(f"/api/scans/{scan_id}").json()["report"] == report
        assert client.get("/api/scans?offset=1").json()["items"] == []


def test_duplicate_scan(tmp_path):
    release = threading.Event()
    def runner(**kwargs):
        assert release.wait(5)
        return {}
    with client_for(tmp_path / "scans.db", runner) as client:
        try:
            auth = headers(client)
            assert client.post("/api/scans", json={}, headers=auth).status_code == 202
            assert client.post("/api/scans", json={}, headers=auth).status_code == 409
        finally:
            release.set()


def test_failure_and_recovery(tmp_path):
    path = tmp_path / "scans.db"
    store = ScanStore(path)
    interrupted = store.create()
    store.start(interrupted)
    def runner(**kwargs):
        raise ValueError("sensitive exception")
    with client_for(path, runner) as client:
        assert client.get(f"/api/scans/{interrupted}").json()["status"] == "failed"
        scan_id = client.post("/api/scans", json={}, headers=headers(client)).json()["id"]
        scan = wait_scan(client, scan_id)
        assert scan["status"] == "failed"
        assert "sensitive" not in scan["error"]


def test_security_and_validation(tmp_path):
    with client_for(tmp_path / "scans.db", lambda **kwargs: {}) as client:
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/session", headers={"Host": "evil.example"}).status_code == 403
        assert client.get("/api/session", headers={"Origin": "https://evil.example"}).status_code == 403
        assert client.get("/api/session", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
        assert client.post("/api/scans", json={}).status_code == 403
        assert client.post("/api/scans", json={"config_path": "/etc/passwd"}, headers=headers(client)).status_code == 422
        assert client.get("/api/scans?limit=0").status_code == 422
        assert client.get("/api/scans?offset=-1").status_code == 422
        assert client.get("/api/scans/not-a-uuid").status_code == 422
        assert client.get(f"/api/scans/{uuid4()}").status_code == 404


def test_second_server_cannot_recover_active_scan(tmp_path):
    path = tmp_path / "scans.db"
    with (
        client_for(path, lambda **kwargs: {}),
        pytest.raises(sqlite3.OperationalError),
        client_for(path, lambda **kwargs: {}),
    ):
        pass
