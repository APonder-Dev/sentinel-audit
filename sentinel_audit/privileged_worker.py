"""One scan, no HTTP server, no database or caller-selected filesystem writes."""

import os
import secrets
import socket
import sys
import threading
import time
from pathlib import Path

# Launched by absolute script path with Python isolated mode (-I).
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel_audit.audit import run_audit
from sentinel_audit.elevation import is_administrator
from sentinel_audit.worker_protocol import receive_message, send_message, validate_rules


def work(port, token):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        send_message(connection, {"type": "hello", "token": token, "elevated": is_administrator()})
        if not is_administrator():
            return 1
        request = receive_message(connection)
        if request.get("type") != "start" or not secrets.compare_digest(str(request.get("token", "")), token):
            return 1
        rules = validate_rules(request.get("rules"))
        lock = threading.Lock()
        stopped = threading.Event()

        def send(message):
            with lock:
                send_message(connection, message)

        def watchdog():
            deadline = time.monotonic() + 180
            while not stopped.wait(1):
                if time.monotonic() >= deadline:
                    os._exit(2)
                try:
                    send({"type": "heartbeat"})
                except OSError:
                    os._exit(2)  # Parent disappeared: do not leave an elevated worker behind.

        thread = threading.Thread(target=watchdog, daemon=True)
        thread.start()
        try:
            report = run_audit(
                port_rules=rules,
                on_progress=lambda name, status: send({"type": "progress", "name": name, "status": status}),
            )
            send({"type": "result", "report": report})
            return 0
        except Exception:  # noqa: BLE001 - worker boundary; never silently retry without elevation.
            # Isolate collector failures without exposing privileged tracebacks to callers.
            send({"type": "error"})
            return 1
        finally:
            stopped.set()
            thread.join(timeout=2)


if __name__ == "__main__":
    if len(sys.argv) != 3 or len(sys.argv[2]) != 64:
        raise SystemExit(2)
    try:
        raise SystemExit(work(int(sys.argv[1]), sys.argv[2]))
    except (OSError, ValueError, TypeError, EOFError):
        raise SystemExit(1) from None
