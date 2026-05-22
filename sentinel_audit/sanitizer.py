def sanitize_report(report: dict) -> dict:
    """
    Redact sensitive values from audit reports.
    """

    sanitized = report.copy()
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
    
    sanitized["system_info"] = system
    sanitized["network_info"] = network

    return sanitized