import os
import socket
import struct
import threading
import time
from unittest.mock import Mock, patch

import pytest
from fastapi.testclient import TestClient

from sentinel_audit.api import create_app
from sentinel_audit.elevation import (
    DeepScanError,
    ElevationDenied,
    launch_elevated,
    run_deep_scan,
)
from sentinel_audit.privileged_worker import work
from sentinel_audit.storage import ScanStore
from sentinel_audit.worker_protocol import (
    MAX_FRAME,
    receive_message,
    send_message,
    validate_rules,
)


class FakeProcess:
    def __init__(self, thread=None):
        self.thread = thread
        self.closed = False

    def exited(self):
        return self.thread is not None and not self.thread.is_alive()

    def close(self):
        self.closed = True
        if self.thread:
            self.thread.join(timeout=3)
            assert not self.thread.is_alive()


def test_authenticated_worker_round_trip_without_uac():
    def audit(**kwargs):
        kwargs["on_progress"]("system", "finished")
        assert isinstance(kwargs["port_rules"], dict)
        return {"findings": [], "system_info": {"hostname": "test"}}
    processes = []
    def launcher(port, token):
        thread = threading.Thread(target=work, args=(port, token))
        thread.start()
        process = FakeProcess(thread)
        processes.append(process)
        return process
    progress = []
    started = Mock()
    with (
        patch("sentinel_audit.privileged_worker.is_administrator", return_value=True),
        patch("sentinel_audit.privileged_worker.run_audit", side_effect=audit),
    ):
        result = run_deep_scan(
            launcher=launcher, on_started=started,
            on_progress=lambda *event: progress.append(event),
        )
    assert result["execution"] == {"mode": "deep", "elevated": True}
    assert progress == [("system", "finished")]
    started.assert_called_once()
    assert processes[0].closed


def test_worker_without_elevation_does_not_scan():
    def launcher(port, token):
        thread = threading.Thread(target=work, args=(port, token))
        thread.start()
        return FakeProcess(thread)
    with (
        patch("sentinel_audit.privileged_worker.is_administrator", return_value=False),
        patch("sentinel_audit.privileged_worker.run_audit") as audit,
        pytest.raises(DeepScanError, match="administrator rights"),
    ):
        run_deep_scan(launcher=launcher)
    audit.assert_not_called()


def test_worker_authentication_failure():
    def launcher(port, token):
        def spoof():
            with socket.create_connection(("127.0.0.1", port)) as connection:
                send_message(connection, {"type": "hello", "token": "wrong", "elevated": True})
        thread = threading.Thread(target=spoof)
        thread.start()
        return FakeProcess(thread)
    with pytest.raises(DeepScanError, match="authentication"):
        run_deep_scan(launcher=launcher)


def test_worker_timeout_closes_handle():
    process = FakeProcess()
    with pytest.raises(DeepScanError, match="timed out"):
        run_deep_scan(launcher=lambda *args: process, timeout=0)
    assert process.closed


def test_worker_exits_before_connecting():
    process = FakeProcess()
    process.exited = lambda: True
    with pytest.raises(DeepScanError, match="exited"):
        run_deep_scan(launcher=lambda *args: process)
    assert process.closed


def test_bounded_json_frames():
    left, right = socket.socketpair()
    with left, right:
        left.sendall(struct.pack("!I", MAX_FRAME + 1))
        with pytest.raises(ValueError):
            receive_message(right)
    left, right = socket.socketpair()
    with left, right:
        send_message(left, {"type": "heartbeat"})
        assert receive_message(right) == {"type": "heartbeat"}


@pytest.mark.parametrize("rules", [
    {"0": ["high", "service", "advice"]},
    {"80": ["invalid", "service", "advice"]},
    {"80": ["high", {"command": "not allowed"}, "advice"]},
])
def test_worker_rejects_invalid_rules(rules):
    with pytest.raises(ValueError):
        validate_rules(rules)


def terminal(client, scan_id):
    for _ in range(200):
        result = client.get("/api/scans/" + scan_id).json()
        if result["status"] in {"completed", "denied", "failed"}:
            return result
        time.sleep(0.01)
    pytest.fail("Scan did not reach a terminal state")


def test_api_denial_stops_scan_without_fallback(tmp_path):
    standard = Mock()
    deep = Mock(side_effect=ElevationDenied("Administrator approval was denied or cancelled. Deep scan was not run."))
    with (
        patch("sentinel_audit.api.deep_scan_available", return_value=True),
        TestClient(create_app(tmp_path / "scans.db", runner=standard, deep_runner=deep), base_url="http://localhost") as client,
    ):
        token = client.get("/api/session").json()["token"]
        response = client.post("/api/scans", json={"mode": "deep"}, headers={"x-sentinel-token": token})
        assert response.status_code == 202
        result = terminal(client, response.json()["id"])
        assert result["status"] == "denied"
        assert result["error_code"] == "uac_denied"
        assert result["started_at"] is None
        assert result["report"] is None
        assert result["mode"] == "deep"
        assert client.get("/api/scans/active").json()["scan"] is None
        assert client.get("/api/scans?status=denied").json()["total"] == 1
    standard.assert_not_called()


def test_api_waiting_blocks_duplicate_then_runs(tmp_path):
    approved = threading.Event()
    def deep(**kwargs):
        assert approved.wait(5)
        kwargs["on_started"]()
        kwargs["on_progress"]("system", "finished")
        return {"findings": [], "execution": {"mode": "deep", "elevated": True}}
    with (
        patch("sentinel_audit.api.deep_scan_available", return_value=True),
        TestClient(create_app(tmp_path / "scans.db", deep_runner=deep), base_url="http://localhost") as client,
    ):
        headers = {"x-sentinel-token": client.get("/api/session").json()["token"]}
        try:
            scan_id = client.post("/api/scans", json={"mode": "deep"}, headers=headers).json()["id"]
            for _ in range(100):
                if client.get("/api/scans/" + scan_id).json()["status"] == "awaiting_approval":
                    break
                time.sleep(0.01)
            assert client.get("/api/scans/active").json()["scan"]["status"] == "awaiting_approval"
            assert client.post("/api/scans", json={}, headers=headers).status_code == 409
        finally:
            approved.set()
        result = terminal(client, scan_id)
        assert result["status"] == "completed"
        assert result["started_at"] is not None
        assert result["progress"]["system"] == "finished"


def test_non_windows_and_unknown_modes_rejected(tmp_path):
    with (
        patch("sentinel_audit.api.deep_scan_available", return_value=False),
        TestClient(create_app(tmp_path / "scans.db"), base_url="http://localhost") as client,
    ):
        session = client.get("/api/session").json()
        assert session["capabilities"]["deep_scan"] is False
        headers = {"x-sentinel-token": session["token"]}
        assert client.post("/api/scans", json={"mode": "deep"}, headers=headers).status_code == 422
        assert client.post("/api/scans", json={"mode": "arbitrary"}, headers=headers).status_code == 422
        assert client.get("/api/scans").json()["total"] == 0


def test_restart_recovers_waiting_scan(tmp_path):
    store = ScanStore(tmp_path / "scans.db")
    scan_id = store.create("deep")
    store.awaiting_approval(scan_id)
    store.recover()
    assert store.get(scan_id)["status"] == "failed"
    assert store.get(scan_id)["mode"] == "deep"
    assert store.get(scan_id)["report"] is None


@pytest.mark.skipif(os.name != "nt", reason="Windows ctypes launch boundary")
def test_native_uac_cancellation_mapping_without_prompt():
    shell = Mock()
    shell.ShellExecuteExW.return_value = False
    with (
        patch("ctypes.WinDLL", return_value=shell),
        patch("ctypes.OleDLL"),
        patch("ctypes.get_last_error", return_value=1223),
        pytest.raises(ElevationDenied, match="denied or cancelled"),
    ):
        launch_elevated(12345, "a" * 64)
