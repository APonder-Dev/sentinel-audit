import platform
import subprocess


def collect_disk_encryption_status() -> dict:
    system = platform.system().lower()
    if system == "windows":
        return _collect_windows_bitlocker()
    elif system == "darwin":
        return _collect_macos_filevault()
    elif system == "linux":
        return _collect_linux_luks()
    return {
        "status": "unsupported",
        "encrypted": None,
        "details": "Disk encryption collection not supported on this platform.",
    }


def _collect_windows_bitlocker() -> dict:
    try:
        result = subprocess.run(
            ["manage-bde", "-status"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        output = result.stdout.strip() or result.stderr.strip()
        if result.returncode != 0:
            return {"status": "error", "encrypted": None, "details": output}

        encrypted = "protection on" in output.lower() or "fully encrypted" in output.lower()
        return {"status": "collected", "encrypted": encrypted, "details": output}

    except FileNotFoundError:
        return {
            "status": "error",
            "encrypted": None,
            "details": "manage-bde not found. BitLocker may not be available on this edition of Windows.",
        }
    except Exception as error:
        return {"status": "error", "encrypted": None, "details": str(error)}


def _collect_macos_filevault() -> dict:
    try:
        result = subprocess.run(
            ["fdesetup", "status"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        output = result.stdout.strip() or result.stderr.strip()
        if result.returncode not in (0, 1):
            return {"status": "error", "encrypted": None, "details": output}

        encrypted = "filevault is on" in output.lower()
        return {"status": "collected", "encrypted": encrypted, "details": output}

    except Exception as error:
        return {"status": "error", "encrypted": None, "details": str(error)}


def _collect_linux_luks() -> dict:
    try:
        result = subprocess.run(
            ["lsblk", "-o", "NAME,FSTYPE", "--noheadings"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode != 0:
            return {
                "status": "error",
                "encrypted": None,
                "details": result.stderr.strip() or "lsblk returned a non-zero exit code.",
            }

        output = result.stdout.strip()
        encrypted = "crypto_luks" in output.lower()
        return {"status": "collected", "encrypted": encrypted, "details": output}

    except FileNotFoundError:
        return {
            "status": "error",
            "encrypted": None,
            "details": "lsblk not found. Unable to determine disk encryption status.",
        }
    except Exception as error:
        return {"status": "error", "encrypted": None, "details": str(error)}
