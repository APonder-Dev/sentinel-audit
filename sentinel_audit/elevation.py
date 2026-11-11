"""Windows UAC launcher and one-shot, authenticated worker transport."""

import ctypes
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

from sentinel_audit.audit import COLLECTORS
from sentinel_audit.config import load_port_rules
from sentinel_audit.worker_protocol import receive_message, send_message


class ElevationDenied(RuntimeError):
    pass


class DeepScanError(RuntimeError):
    pass


def is_administrator():
    return os.name == "nt" and bool(ctypes.windll.shell32.IsUserAnAdmin())


class WindowsProcess:
    def __init__(self, handle):
        from ctypes import wintypes

        self.handle = handle
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.kernel.WaitForSingleObject.restype = wintypes.DWORD
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL

    def exited(self):
        return self.kernel.WaitForSingleObject(self.handle, 0) == 0

    def close(self):
        self.kernel.CloseHandle(self.handle)


def launch_elevated(port, token):
    if os.name != "nt":
        raise DeepScanError("Deep scan with UAC is available only on Windows.")
    from ctypes import wintypes

    class ShellExecuteInfo(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
            ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
            ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
            ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR),
            ("hkeyClass", wintypes.HKEY), ("dwHotKey", wintypes.DWORD),
            ("hIcon", wintypes.HANDLE), ("hProcess", wintypes.HANDLE),
        ]

    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(ShellExecuteInfo)]
    shell.ShellExecuteExW.restype = wintypes.BOOL
    ole = ctypes.OleDLL("ole32")
    ole.CoInitializeEx(None, 6)  # STA plus disabled OLE1 DDE, on this executor thread.
    try:
        info = ShellExecuteInfo()
        info.cbSize = ctypes.sizeof(info)
        info.fMask = 0x40 | 0x100 | 0x400  # Process handle, synchronous launch, no error dialogs.
        info.lpVerb = "runas"
        info.lpFile = sys.executable
        bootstrap = Path(__file__).with_name("privileged_worker.py").resolve()
        info.lpParameters = subprocess.list2cmdline(["-I", str(bootstrap), str(port), token])
        info.lpDirectory = str(bootstrap.parent.parent)
        info.nShow = 0  # Hide worker console; Windows still displays the UAC prompt.
        if not shell.ShellExecuteExW(ctypes.byref(info)):
            code = ctypes.get_last_error()
            if code == 1223:
                raise ElevationDenied("Administrator approval was denied or cancelled. Deep scan was not run.")
            raise DeepScanError(f"Windows could not launch the privileged worker (error {code}).")
        if not info.hProcess:
            raise DeepScanError("Windows did not return a worker process handle.")
        return WindowsProcess(info.hProcess)
    finally:
        ole.CoUninitialize()


def run_deep_scan(config_path=None, on_progress=None, on_started=None, launcher=None, timeout=180):
    """The launcher is injectable for tests; API clients cannot select it."""
    token = secrets.token_hex(32)
    rules = load_port_rules(config_path)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(0.25)
        process = (launcher or launch_elevated)(listener.getsockname()[1], token)
        try:
            deadline = time.monotonic() + timeout
            while True:
                if time.monotonic() >= deadline:
                    raise DeepScanError("The privileged worker timed out. Deep scan stopped.")
                try:
                    connection, _ = listener.accept()
                    break
                except TimeoutError:
                    if process.exited():
                        raise DeepScanError("The privileged worker exited before connecting.")
            with connection:
                connection.settimeout(10)
                hello = receive_message(connection)
                if hello.get("type") != "hello" or not secrets.compare_digest(str(hello.get("token", "")), token):
                    raise DeepScanError("Privileged worker authentication failed.")
                if hello.get("elevated") is not True:
                    raise DeepScanError("The worker did not receive administrator rights. Deep scan stopped.")
                send_message(connection, {"type": "start", "token": token, "rules": rules})
                if on_started:
                    on_started()
                while time.monotonic() < deadline:
                    connection.settimeout(min(10, max(0.1, deadline - time.monotonic())))
                    message = receive_message(connection)
                    kind = message.get("type")
                    if kind == "heartbeat":
                        continue
                    if kind == "progress":
                        if message.get("name") not in COLLECTORS or message.get("status") not in {
                            "running", "finished", "partial", "unknown", "error", "unsupported",
                        }:
                            raise DeepScanError("Invalid worker progress.")
                        if on_progress:
                            on_progress(message["name"], message["status"])
                    elif kind == "result":
                        report = message.get("report")
                        if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
                            raise DeepScanError("Invalid worker result.")
                        report["execution"] = {"mode": "deep", "elevated": True}
                        return report
                    elif kind == "error":
                        raise DeepScanError("The privileged worker failed. No complete scan result was saved.")
                    else:
                        raise DeepScanError("Unexpected worker message.")
                raise DeepScanError("The privileged worker timed out. Deep scan stopped.")
        except (OSError, EOFError, ValueError, TypeError) as error:
            raise DeepScanError("The privileged worker connection failed. Deep scan stopped.") from error
        finally:
            process.close()
