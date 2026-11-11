import sqlite3

from fastapi.testclient import TestClient

from sentinel_audit.api import create_app
from sentinel_audit.storage import ScanStore


def test_dashboard_assets_and_security_headers(tmp_path):
    with TestClient(create_app(tmp_path / "scans.db"), base_url="http://localhost") as client:
        for path in ["/", "/assets/dashboard.css", "/assets/dashboard.js", "/assets/vendor/lucide.min.js"]:
            response = client.get(path)
            assert response.status_code == 200
            assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
            assert response.headers["cache-control"] == "no-store"
        assert "Run scan" in client.get("/").text
        assert client.get("/assets/../../api.py").status_code == 404


def test_migrates_v1_database_and_preserves_history(tmp_path):
    path = tmp_path / "scans.db"
    with sqlite3.connect(path) as db:
        db.execute("""
            CREATE TABLE scans (
                id TEXT PRIMARY KEY, status TEXT NOT NULL, created_at TEXT NOT NULL,
                started_at TEXT, finished_at TEXT, duration_seconds REAL,
                schema_version INTEGER NOT NULL DEFAULT 1, report TEXT, error TEXT
            )
        """)
        db.execute("PRAGMA user_version=1")
        db.execute("INSERT INTO scans (id,status,created_at) VALUES ('old','completed','2026-01-01')")
    store = ScanStore(path)
    assert store.get("old")["progress"] == {}
    with store.connection() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 3


def test_history_filters_and_active_progress(tmp_path):
    path = tmp_path / "scans.db"
    store = ScanStore(path)
    finished = store.create()
    store.finish(finished, 1, report={"system_info": {"hostname": "Workstation"}, "risk_score": {"score": 80}, "findings": []})
    with TestClient(create_app(path), base_url="http://localhost") as client:
        scan_id = store.create()
        store.start(scan_id)
        store.progress(scan_id, "system", "finished")
        store.progress(scan_id, "disk", "running")
        active = client.get("/api/scans/active").json()["scan"]
        assert active["id"] == scan_id
        assert active["progress"] == {"system": "finished", "disk": "running"}
        result = client.get("/api/scans?status=completed&query=WORKSTATION").json()
        assert result["total"] == 1
        assert result["items"][0]["score"] == 80
        assert result["items"][0]["findings_count"] == 0
        assert client.get("/api/scans?query=missing").json()["total"] == 0
        assert client.get("/api/scans?status=invalid").status_code == 422
        store.finish(scan_id, 1, error="Test failure")
        assert client.get("/api/scans/active").json()["scan"] is None
