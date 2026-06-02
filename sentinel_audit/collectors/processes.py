import platform
import subprocess


def collect_process_info() -> dict:
    system = platform.system().lower()
    if system == "windows":
        return _collect_windows()
    elif system in ("linux", "darwin"):
        return _collect_unix()
    return {
        "status": "unsupported",
        "privileged_count": 0,
        "privileged_processes": [],
        "details": "Process collection not supported on this platform.",
    }


def _collect_windows() -> dict:
    try:
        result = subprocess.run(
            ["tasklist", "/fo", "csv", "/nh", "/v"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode != 0:
            return {
                "status": "error",
                "privileged_count": 0,
                "privileged_processes": [],
                "details": result.stderr.strip() or "tasklist returned a non-zero exit code.",
            }

        privileged = []
        _PRIVILEGED_ACCOUNTS = ("SYSTEM", "NT AUTHORITY", "LOCAL SERVICE", "NETWORK SERVICE")

        for line in result.stdout.splitlines():
            parts = [p.strip('"') for p in line.strip().split('","')]
            if len(parts) < 7:
                continue
            name, pid, _session_name, _session_num, _mem, _status, user = parts[:7]
            if any(account in user.upper() for account in _PRIVILEGED_ACCOUNTS):
                privileged.append({"name": name, "pid": pid, "user": user})

        return {
            "status": "collected",
            "privileged_count": len(privileged),
            "privileged_processes": privileged[:30],
            "details": "",
        }

    except Exception as error:
        return {
            "status": "error",
            "privileged_count": 0,
            "privileged_processes": [],
            "details": str(error),
        }


def _collect_unix() -> dict:
    try:
        result = subprocess.run(
            ["ps", "aux"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode != 0:
            return {
                "status": "error",
                "privileged_count": 0,
                "privileged_processes": [],
                "details": result.stderr.strip() or "ps returned a non-zero exit code.",
            }

        privileged = []
        for line in result.stdout.splitlines()[1:]:
            parts = line.split(None, 10)
            if len(parts) < 11:
                continue
            user, pid, command = parts[0], parts[1], parts[10].strip()
            if user == "root":
                process_name = command.split()[0] if command else "unknown"
                privileged.append({"name": process_name, "pid": pid, "user": user})

        return {
            "status": "collected",
            "privileged_count": len(privileged),
            "privileged_processes": privileged[:30],
            "details": "",
        }

    except Exception as error:
        return {
            "status": "error",
            "privileged_count": 0,
            "privileged_processes": [],
            "details": str(error),
        }
