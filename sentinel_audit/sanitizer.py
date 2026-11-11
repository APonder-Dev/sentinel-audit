import re
from copy import deepcopy

IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_PATTERN = re.compile(r"\[[0-9a-fA-F:]+(?:%\d+)?\]|(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:]*")


def redact_network_identifiers(value: str) -> str:
    """
    Redact IPv4 and IPv6 addresses from a string.
    """

    value = IPV4_PATTERN.sub("[REDACTED_IP]", value)
    value = IPV6_PATTERN.sub("[REDACTED_IP]", value)

    return value


def sanitize_report(report: dict) -> dict:
    """
    Redact sensitive values from audit reports without mutating the original report.
    """

    sanitized = deepcopy(report)

    system = sanitized.get("system_info", {})
    network = sanitized.get("network_info", {})

    if "hostname" in system:
        system["hostname"] = "[REDACTED]"

    if "current_user" in system:
        system["current_user"] = "[REDACTED]"

    if "ip_address" in network:
        network["ip_address"] = "[REDACTED]"

    if "local_ip" in network:
        network["local_ip"] = "[REDACTED]"

    if "listening_ports" in network:
        network["listening_ports"] = [
            redact_network_identifiers(line)
            for line in network["listening_ports"]
        ]

    for entry in network.get("inventory", []):
        entry["address"] = "[REDACTED_IP]"
    for process in sanitized.get("process_info", {}).get("privileged_processes", []):
        process["user"] = "[REDACTED]"

    identifiers = {
        str(value) for value in (
            report.get("system_info", {}).get("hostname"),
            report.get("system_info", {}).get("current_user"),
            *(process.get("user") for process in report.get("process_info", {}).get("privileged_processes", [])),
        ) if value
    }
    identifiers |= {value.rsplit("\\", 1)[-1] for value in identifiers}

    def redact(value, key=""):
        if key in {"details", "command_line", "cmdline", "executable"}:
            return "[OMITTED FROM SANITIZED REPORT]"
        if isinstance(value, dict):
            return {name: redact(item, name) for name, item in value.items()}
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, str):
            if key in {"hostname", "current_user", "user", "username", "ip_address", "local_ip", "address"}:
                return "[REDACTED_IP]" if key == "address" else "[REDACTED]"
            if key in {"id", "generated_at", "created_at", "started_at", "finished_at"}:
                return value
            for identifier in sorted(identifiers, key=len, reverse=True):
                if len(identifier) >= 3:
                    value = re.sub(re.escape(identifier), "[REDACTED]", value, flags=re.IGNORECASE)
            value = re.sub(r"\b(?:\d{6}-){7}\d{6}\b", "[REDACTED_RECOVERY_KEY]", value)
            return redact_network_identifiers(value)
        return value

    return redact(sanitized)
