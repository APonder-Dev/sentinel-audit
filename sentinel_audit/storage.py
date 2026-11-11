"""Local scan persistence. Each operation owns its SQLite connection."""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from sentinel_audit.coverage import summarize_coverage


def utc_now():
    return datetime.now(UTC).isoformat()


def data_directory():
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local")) / "SentinelAudit"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "sentinel-audit"


class ScanStore:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.connection() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2, 3):
                raise RuntimeError("Unsupported scan database version")
            db.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY, status TEXT NOT NULL,
                    created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
                    duration_seconds REAL, schema_version INTEGER NOT NULL DEFAULT 1,
                    report TEXT, error TEXT
                )
            """)
            db.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS one_active_scan ON scans ((1))
                WHERE status IN ('queued', 'running')
            """)
            columns = {row["name"] for row in db.execute("PRAGMA table_info(scans)")}
            if "progress" not in columns:
                db.execute("ALTER TABLE scans ADD COLUMN progress TEXT NOT NULL DEFAULT '{}'")
            if "mode" not in columns:
                db.execute("ALTER TABLE scans ADD COLUMN mode TEXT NOT NULL DEFAULT 'standard'")
            if "error_code" not in columns:
                db.execute("ALTER TABLE scans ADD COLUMN error_code TEXT")
            if version < 3:
                db.execute("DROP INDEX one_active_scan")
                db.execute("""
                    CREATE UNIQUE INDEX one_active_scan ON scans ((1))
                    WHERE status IN ('queued', 'awaiting_approval', 'running')
                """)
            db.execute("PRAGMA user_version = 3")
        if os.name != "nt":
            path.chmod(0o600)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def recover(self):
        with self.connection() as db:
            db.execute(
                "UPDATE scans SET status='failed', finished_at=?, error=? "
                "WHERE status IN ('queued', 'awaiting_approval', 'running')",
                (utc_now(), "Scan interrupted by application shutdown."),
            )

    def create(self, mode="standard"):
        scan_id = str(uuid4())
        with self.connection() as db:
            db.execute(
                "INSERT INTO scans (id,status,created_at,mode) VALUES (?, 'queued', ?, ?)",
                (scan_id, utc_now(), mode),
            )
        return scan_id

    def start(self, scan_id):
        with self.connection() as db:
            db.execute("UPDATE scans SET status='running', started_at=? WHERE id=?", (utc_now(), scan_id))

    def awaiting_approval(self, scan_id):
        with self.connection() as db:
            db.execute("UPDATE scans SET status='awaiting_approval' WHERE id=?", (scan_id,))

    def progress(self, scan_id, name, status):
        with self.connection() as db:
            db.execute(
                "UPDATE scans SET progress=json_set(progress, ?, ?) WHERE id=?",
                (f"$.{name}", status, scan_id),
            )

    def active(self):
        with self.connection() as db:
            row = db.execute("SELECT id FROM scans WHERE status IN ('queued', 'awaiting_approval', 'running')").fetchone()
        return self.get(row["id"]) if row else None

    def finish(self, scan_id, duration, report=None, error=None, status=None, error_code=None):
        with self.connection() as db:
            db.execute(
                "UPDATE scans SET status=?, finished_at=?, duration_seconds=?, report=?, error=?, error_code=? WHERE id=?",
                (status or ("failed" if error else "completed"), utc_now(), duration,
                 json.dumps(report) if report is not None else None, error, error_code, scan_id),
            )

    def get(self, scan_id):
        with self.connection() as db:
            row = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["report"] = json.loads(result["report"]) if result["report"] else None
        if result["report"] is not None:
            result["coverage"] = summarize_coverage(result["report"])
        result["progress"] = json.loads(result["progress"])
        return result

    def history(self, limit, offset, status=None, query=""):
        where = (
            "WHERE (? IS NULL OR status=?) AND "
            "(instr(lower(id), lower(?)) > 0 OR "
            "instr(lower(COALESCE(json_extract(report, '$.system_info.hostname'), '')), lower(?)) > 0)"
        )
        parameters = (status, status, query, query)
        with self.connection() as db:
            rows = db.execute(
                "SELECT id,status,mode,error_code,created_at,started_at,finished_at,duration_seconds,schema_version,error, "
                "json_extract(report, '$.system_info.hostname') AS hostname, "
                "json_extract(report, '$.risk_score.score') AS score, "
                "json_extract(report, '$.coverage.collected') AS coverage_collected, "
                "json_array_length(report, '$.findings') AS findings_count "
                f"FROM scans {where} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
                (*parameters, limit, offset),
            ).fetchall()
            total = db.execute(f"SELECT COUNT(*) FROM scans {where}", parameters).fetchone()[0]
        return {"items": [dict(row) for row in rows], "total": total}
