import getpass
import platform
import socket


def collect_system_info() -> dict:
    """Collect basic host and operating system information."""
    return {
        "hostname": socket.gethostname(),
        "current_user": getpass.getuser(),

        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),

        "platform": platform.platform(),
        "platform_version": platform.version(),

        "architecture": platform.architecture()[0],
        "machine": platform.machine(),
        "processor": platform.processor(),
    }