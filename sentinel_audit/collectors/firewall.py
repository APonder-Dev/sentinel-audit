import platform
import subprocess

def collect_firewall_status() -> dict:
    """Collects firewall-related information."""
    system = platform.system().lower()

    if system == "windows":
        command = ["netsh", "advfirewall", "show", "allprofiles"]
    elif system == "linux":
        command = ["ufw", "status"]
    else:
        return {
            "status": "unsupported",
            "details": "Firewall collection is not supported on this operating system yet.",
        }

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        return {
            "status": "collected" if result.returncode == 0 else "error",
            "details": result.stdout.strip() or result.stderr.strip(),
        }

    except Exception as error:
        return {
            "status": "error",
            "details": str(error),
        }