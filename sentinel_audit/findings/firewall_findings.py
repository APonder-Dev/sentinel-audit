def analyze_firewall_status(firewall_status: dict) -> list[dict]:
    """
    Analyze firewall telemetry and return security findings.
    """

    findings = []

    status = firewall_status.get("status", "unknown")
    details = firewall_status.get("details", "").lower()

    if status == "unsupported":
        findings.append(
            {
                "severity": "low",
                "title": "Firewall status collection is unsupported",
            "id": "SA-FW-UNSUPPORTED", "collector": "firewall", "kind": "gap",
                "description": "SentinelAudit could not collect firewall status on this operating system.",
                "recommendation": "Manually verify firewall configuration using platform-specific tooling.",
            }
        )

    elif status == "error":
        findings.append(
            {
                "severity": "medium",
                "title": "Firewall status could not be verified",
            "id": "SA-FW-UNVERIFIED", "collector": "firewall", "kind": "gap",
                "description": "SentinelAudit encountered an error while attempting to collect firewall status.",
                "recommendation": "Review firewall configuration manually and confirm host firewall protection is enabled.",
            }
        )

    elif "off" in details or "inactive" in details or "disabled" in details:
        findings.append(
            {
                "severity": "high",
                "title": "Firewall may be disabled",
            "id": "SA-FW-DISABLED", "collector": "firewall", "kind": "risk",
                "description": "Firewall telemetry indicates that one or more firewall profiles may be disabled.",
                "recommendation": "Enable the host firewall and verify inbound rules are restricted to required services only.",
            }
        )

    else:
        findings.append(
            {
                "severity": "informational",
                "title": "Firewall status collected",
            "id": "SA-FW-COLLECTED", "collector": "firewall", "kind": "observation",
                "description": "Firewall telemetry was collected successfully.",
                "recommendation": "Review collected firewall details for profile-specific configuration issues.",
            }
        )

    return findings
