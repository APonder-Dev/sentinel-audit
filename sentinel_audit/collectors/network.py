import platform
import socket
import subprocess

def get_ip_address() -> str:
    """Get the IP address of the machine."""
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except socket.error:
        return "Unable to determine IP address"


def get_listening_ports() -> list[str]:
    system = platform.system().lower()
    command = ["netstat", "-ano"] if system == "windows" else ["ss", "-tuln"]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            return [result.stderr.strip() or "Unable to collect listening ports"]
        return result.stdout.splitlines()
    except Exception as error:
        return [f"Error collecting listening ports: {error}"]


def collect_network_info() -> dict:
    return {
        "ip_address": get_ip_address(),
        "listening_ports": get_listening_ports(),
    }