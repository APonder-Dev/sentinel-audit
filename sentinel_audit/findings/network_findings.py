import re

_PORT_PATTERN = re.compile(r":(\d+)")

# Ports that warrant a finding when found listening. Format: port -> (severity, service, recommendation)
_RISKY_PORTS: dict[int, tuple[str, str, str]] = {
    21:   ("high",   "FTP",        "Disable FTP and migrate to SFTP or SCP for encrypted file transfers."),
    23:   ("high",   "Telnet",     "Disable Telnet immediately and use SSH for all remote access."),
    135:  ("medium", "MS-RPC",     "Restrict RPC access via firewall rules to trusted hosts only."),
    139:  ("medium", "NetBIOS",    "Disable NetBIOS over TCP/IP if not required by legacy applications."),
    445:  ("medium", "SMB",        "Restrict SMB to internal trusted networks and apply latest patches."),
    1433: ("medium", "MSSQL",      "Ensure MSSQL is firewalled and not exposed to untrusted networks."),
    1521: ("medium", "Oracle DB",  "Ensure Oracle DB is firewalled and not exposed to untrusted networks."),
    3306: ("medium", "MySQL",      "Ensure MySQL is firewalled and not exposed to untrusted networks."),
    3389: ("high",   "RDP",        "Restrict RDP access to VPN or jump hosts and enable NLA."),
    4444: ("high",   "Unknown (Metasploit default)", "Investigate this port immediately — 4444 is a common backdoor/C2 port."),
    5432: ("medium", "PostgreSQL", "Ensure PostgreSQL is firewalled and not exposed to untrusted networks."),
    5900: ("high",   "VNC",        "Disable VNC or restrict it to localhost/VPN and require authentication."),
    6379: ("medium", "Redis",      "Ensure Redis is bound to localhost or firewalled from external access."),
    27017:("medium", "MongoDB",    "Ensure MongoDB is firewalled and authentication is enforced."),
}


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


def analyze_network_info(network_info: dict) -> list[dict]:
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

    for port, (severity, service, recommendation) in _RISKY_PORTS.items():
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
