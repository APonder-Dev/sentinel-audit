from sentinel_audit.config import _DEFAULT_PORT_RULES


def _extract_listening_ports(listening_ports: list[str]) -> set[int]:
    ports: set[int] = set()
    for line in listening_ports:
        parts = line.split()
        if not parts or "listen" not in line.lower():
            continue
        # Legacy ss output uses field 5; Windows netstat uses field 2.
        local = parts[4] if len(parts) >= 5 and parts[1].upper() == "LISTEN" else parts[1]
        try:
            port = int(local.rsplit(":", 1)[1])
            if 1 <= port <= 65535:
                ports.add(port)
        except (ValueError, IndexError):
            continue
    return ports


def analyze_network_info(
    network_info: dict,
    port_rules: dict[int, tuple[str, str, str]] | None = None,
) -> list[dict]:
    rules = port_rules if port_rules is not None else _DEFAULT_PORT_RULES
    findings: list[dict] = []
    listening_ports = network_info.get("listening_ports", [])
    structured = "inventory" in network_info
    status = network_info.get("status")

    if status in {"error", "partial", "unsupported", "unknown"} or (
        not structured and (not listening_ports or (len(listening_ports) == 1 and "error" in listening_ports[0].lower()))
    ):
        findings.append({
            "severity": "medium",
            "title": "Listening port data could not be collected",
            "id": "SA-NET-UNVERIFIED", "collector": "network", "kind": "gap",
            "description": "SentinelAudit was unable to retrieve the list of listening ports.",
            "recommendation": "Manually review open ports using netstat or ss and audit exposed services.",
        })
        return findings

    open_ports = (
        {entry["port"] for entry in network_info["inventory"]}
        if structured else _extract_listening_ports(listening_ports)
    )

    for port, (severity, service, recommendation) in rules.items():
        if port in open_ports:
            findings.append({
                "severity": severity,
                "title": f"Risky port open: {port}/{service}",
            "id": f"SA-NET-PORT-{port}", "collector": "network", "kind": "risk",
                "description": f"Port {port} matches the configured {service} rule in local socket data. This is a rule match, not a verified service vulnerability or remote-reachability test.",
                "recommendation": recommendation,
            })

    if not findings:
        findings.append({
            "severity": "informational",
            "title": "No configured port rules matched",
            "id": "SA-NET-NO-MATCH", "collector": "network", "kind": "observation",
            "description": "No observed local sockets matched the configured rules. This does not establish that the host is vulnerability-free.",
            "recommendation": "Periodically re-audit open ports as services and configurations change.",
        })

    return findings
