import platform
import re
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


def parse_bitlocker_status(output: str) -> dict:
    headers = list(re.finditer(r"^\s*Volume ([^:\r\n]+):[^\r\n]*", output, re.MULTILINE))
    blocks = [
        (match[1].strip() + ":", output[match.end():headers[index + 1].start() if index + 1 < len(headers) else len(output)])
        for index, match in enumerate(headers)
    ]
    if not blocks:
        conversions = list(re.finditer(r"^[ \t]*Conversion Status:", output, re.MULTILINE | re.IGNORECASE))
        blocks = [
            (f"Reported volume {index + 1}", output[match.start():conversions[index + 1].start() if index + 1 < len(conversions) else len(output)])
            for index, match in enumerate(conversions)
        ] or [("Reported volume", output)]
    volumes = []
    for volume, block in blocks:
        conversions = re.findall(r"^[ \t]*Conversion Status:[ \t]*([^\r\n]+)", block, re.MULTILINE | re.IGNORECASE)
        protections = re.findall(r"^[ \t]*Protection Status:[ \t]*([^\r\n]+)", block, re.MULTILINE | re.IGNORECASE)
        conversion = conversions[0].strip() if len(conversions) == 1 else "Unknown"
        protection = protections[0].strip() if len(protections) == 1 else "Unknown"
        state = conversion.lower()
        protected = protection.lower()
        volumes.append({
            "volume": volume,
            "encrypted": True if state in {"fully encrypted", "used space only encrypted"} else False if state == "fully decrypted" else None,
            "protection_active": True if protected == "protection on" else False if protected == "protection off" else None,
            "conversion_status": conversion,
            "protection_status": protection,
        })
    encrypted = True if all(v["encrypted"] is True for v in volumes) else False if all(v["encrypted"] is False for v in volumes) else None
    protected = False if any(v["protection_active"] is False for v in volumes) else True if all(v["protection_active"] is True for v in volumes) else None
    complete = encrypted is not None and protected is not None
    return {
        "provider": "bitlocker", "status": "collected" if complete else "partial",
        "encrypted": encrypted, "protection_active": protected, "volumes": volumes,
        "details": output,
        "remediation": "" if complete else "Verify encryption and protection for each reported volume in BitLocker settings. Missing or unrecognized states remain unknown.",
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
            return {
                "status": "error", "encrypted": None, "details": output,
                "remediation": "Verify BitLocker using Windows settings or an appropriately authorized administrator session. No automatic elevation is attempted.",
            }

        return parse_bitlocker_status(output)

    except FileNotFoundError:
        return {
            "status": "error",
            "encrypted": None,
            "details": "manage-bde not found. BitLocker may not be available on this edition of Windows.",
        }
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
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

        lowered = output.lower()
        encrypted = True if "filevault is on" in lowered else False if "filevault is off" in lowered else None
        return {"status": "collected" if encrypted is not None else "partial", "encrypted": encrypted, "details": output}

    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
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
        return {
            "status": "partial", "encrypted": None, "details": output,
            "remediation": "lsblk filesystem types alone cannot verify encryption of every mounted volume. Review root, data, and swap encryption and their device mappings.",
        }

    except FileNotFoundError:
        return {
            "status": "error",
            "encrypted": None,
            "details": "lsblk not found. Unable to determine disk encryption status.",
        }
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        return {"status": "error", "encrypted": None, "details": str(error)}
