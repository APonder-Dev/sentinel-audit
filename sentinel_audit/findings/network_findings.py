import re

from sentinel_audit.config import _DEFAULT_PORT_RULES

_PORT_PATTERN = re.compile(r":(\d+)")


def _extract_listening_ports(listening_ports: list[str]) -> set[int]:
    ports: set[int] = set()
    for line in listening_ports:
        if "listen" not in line.lower():
            continue
        for match in _PORT_PATTERN.finditer(line):
            try:
                port = int(match.group(1))
                if 1 <= port <= 65535:
                    ports.add(port)
            except ValueError:
                pass
    return ports


def analyze_network_info(
    network_info: dict,
    port_rules: dict[int, tuple[str, str, str]] | None = None,
) -> list[dict]:
    rules = port_rules if port_rules is not None else _DEFAULT_PORT_RULES
    findings: list[dict] = []
    listening_ports = network_info.get("listening_ports", [])

    if not listening_ports or (len(listening_ports) == 1 and "error" in listening_ports[0].lower()):
        findings.append({
            "severity": "medium",
            "title": "Listening port data could not be collected",
            "description": "SentinelAudit was unable to retrieve the list of listening ports.",
            "recommendation": "Manually review open ports using netstat or ss and audit exposed services.",
        })
        return findings

    open_ports = _extract_listening_ports(listening_ports)

    for port, (severity, service, recommendation) in rules.items():
        if port in open_ports:
            findings.append({
                "severity": severity,
                "title": f"Risky port open: {port}/{service}",
                "description": f"Port {port} ({service}) is listening on this host.",
                "recommendation": recommendation,
            })

    if not findings:
        findings.append({
            "severity": "informational",
            "title": "No high-risk listening ports detected",
            "description": "No well-known high-risk ports were found in the listening port data.",
            "recommendation": "Periodically re-audit open ports as services and configurations change.",
        })

    return findings
