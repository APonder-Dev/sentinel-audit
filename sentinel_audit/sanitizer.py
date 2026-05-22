from copy import deepcopy
import re


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

    return sanitized