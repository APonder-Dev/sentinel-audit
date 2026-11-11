"""Loopback-only API and single-worker scan lifecycle."""

import logging
import os
import secrets
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict

from sentinel_audit.audit import run_audit
from sentinel_audit.comparison import compare_scans
from sentinel_audit.elevation import DeepScanError, ElevationDenied, run_deep_scan
from sentinel_audit.findings.identity import normalize_findings
from sentinel_audit.reporting.exports import export_report
from sentinel_audit.storage import ScanStore, data_directory

logger = logging.getLogger(__name__)


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["standard", "deep"] = "standard"


def deep_scan_available():
    return os.name == "nt"


def create_app(db_path: Path | None = None, runner=None, config_path=None, deep_runner=None):
    path = db_path or data_directory() / "scans.sqlite3"
    audit = runner or run_audit
    deep_audit = deep_runner or run_deep_scan
    token = secrets.token_urlsafe(32)

    @asynccontextmanager
    async def lifespan(app):
        # A dedicated transaction lock spans the server lifetime, not scan writes.
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock_path = path.with_suffix(".lock.sqlite3")
        lock = sqlite3.connect(lock_path, timeout=0)
        try:
            lock.execute("BEGIN EXCLUSIVE")
            if os.name != "nt":
                lock_path.chmod(0o600)
            store = ScanStore(path)
            store.recover()
            app.state.store = store
            with ThreadPoolExecutor(max_workers=1, thread_name_prefix="audit") as pool:
                app.state.pool = pool
                yield
        finally:
            lock.close()

    app = FastAPI(
        title="SentinelAudit Local API", version="0.5.0-dev", lifespan=lifespan,
        docs_url=None, redoc_url=None,
    )
    static = Path(__file__).parent / "web"
    app.mount("/assets", StaticFiles(directory=static), name="assets")

    @app.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(static / "index.html")

    @app.middleware("http")
    async def local_only(request: Request, call_next):
        host = request.url.hostname
        if host not in {"localhost", "127.0.0.1", "::1"}:
            return JSONResponse({"detail": "Local host required"}, status_code=403)
        origin = request.headers.get("origin")
        expected = f"{request.url.scheme}://{request.url.netloc}"
        if origin and origin != expected:
            return JSONResponse({"detail": "Cross-origin requests forbidden"}, status_code=403)
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail": "Cross-site requests forbidden"}, status_code=403)
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            supplied = request.headers.get("x-sentinel-token", "")
            if not secrets.compare_digest(supplied, token):
                return JSONResponse({"detail": "Session token required"}, status_code=403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.get("/api/session")
    def session():
        return {"token": token, "capabilities": {"deep_scan": deep_scan_available()}}

    def execute(scan_id, mode):
        start = time.monotonic()
        store = app.state.store
        try:
            progress = lambda name, status: store.progress(scan_id, name, status)
            if mode == "deep":
                store.awaiting_approval(scan_id)
                report = deep_audit(
                    config_path=config_path, on_progress=progress,
                    on_started=lambda: store.start(scan_id),
                )
            else:
                store.start(scan_id)
                report = audit(config_path=config_path, on_progress=progress)
            store.finish(scan_id, time.monotonic() - start, report=report)
        except ElevationDenied as error:
            store.finish(
                scan_id, time.monotonic() - start, error=str(error),
                status="denied", error_code="uac_denied",
            )
        except DeepScanError as error:
            store.finish(scan_id, time.monotonic() - start, error=str(error), error_code="deep_scan_failed")
        except Exception:
            # Isolate worker failures; detailed errors stay in local logs.
            logger.exception("Scan %s failed", scan_id)
            store.finish(scan_id, time.monotonic() - start, error="Scan failed; see server logs.")

    @app.post("/api/scans", status_code=202)
    def launch(body: ScanRequest):
        if body.mode == "deep" and not deep_scan_available():
            raise HTTPException(422, "Deep scan with UAC is available only on Windows.")
        try:
            scan_id = app.state.store.create(body.mode)
        except sqlite3.IntegrityError as error:
            raise HTTPException(409, "A scan is already active") from error
        try:
            app.state.pool.submit(execute, scan_id, body.mode)
        except RuntimeError as error:
            app.state.store.finish(scan_id, 0, error="Server is shutting down.")
            raise HTTPException(503, "Server is shutting down") from error
        return {"id": scan_id, "status": "queued", "mode": body.mode}

    @app.get("/api/scans")
    def history(
        limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
        status: Literal["queued", "awaiting_approval", "running", "completed", "failed", "denied"] | None = None,
        query: str = Query("", max_length=200),
    ):
        return app.state.store.history(limit, offset, status, query)

    @app.get("/api/scans/active")
    def active():
        return {"scan": app.state.store.active()}

    @app.get("/api/scans/{scan_id}")
    def detail(scan_id: UUID):
        scan = app.state.store.get(str(scan_id))
        if scan is None:
            raise HTTPException(404, "Scan not found")
        if scan["report"] is not None:
            scan["report"]["findings"] = normalize_findings(scan["report"].get("findings", []))
        return scan

    def completed(scan_id):
        scan = app.state.store.get(str(scan_id))
        if scan is None:
            raise HTTPException(404, "Scan not found")
        if scan["status"] != "completed" or scan["report"] is None:
            raise HTTPException(409, "A completed scan with a report is required.")
        return scan

    @app.get("/api/scans/{scan_id}/export")
    def download(scan_id: UUID, format: Literal["json", "markdown", "html"] = "html", sanitize: bool = True):
        scan = completed(scan_id)
        content, media_type, extension = export_report(scan, format, sanitize)
        suffix = "-sanitized" if sanitize else ""
        return Response(content, media_type=media_type, headers={
            "Content-Disposition": f'attachment; filename="sentinel-audit-{scan_id}{suffix}.{extension}"',
        })

    @app.get("/api/scans/{scan_id}/compare")
    def compare(scan_id: UUID, baseline: UUID):
        if scan_id == baseline:
            raise HTTPException(422, "Choose a different baseline scan.")
        current, previous = completed(scan_id), completed(baseline)
        if previous["created_at"] > current["created_at"]:
            raise HTTPException(422, "The baseline must be earlier than the current scan.")
        return compare_scans(previous, current)

    return app


def serve(port=8765, config_path=None):
    import uvicorn

    uvicorn.run(
        create_app(config_path=config_path), host="127.0.0.1", port=port,
        proxy_headers=False,
    )
