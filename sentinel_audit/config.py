import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    raise RuntimeError("Python 3.11+ required for tomllib support")

_DEFAULT_PORT_RULES: dict[int, tuple[str, str, str]] = {
    21:    ("high",   "FTP",                        "Disable FTP and migrate to SFTP or SCP for encrypted file transfers."),
    23:    ("high",   "Telnet",                     "Disable Telnet immediately and use SSH for all remote access."),
    135:   ("medium", "MS-RPC",                     "Restrict RPC access via firewall rules to trusted hosts only."),
    139:   ("medium", "NetBIOS",                    "Disable NetBIOS over TCP/IP if not required by legacy applications."),
    445:   ("medium", "SMB",                        "Restrict SMB to internal trusted networks and apply latest patches."),
    1433:  ("medium", "MSSQL",                      "Ensure MSSQL is firewalled and not exposed to untrusted networks."),
    1521:  ("medium", "Oracle DB",                  "Ensure Oracle DB is firewalled and not exposed to untrusted networks."),
    3306:  ("medium", "MySQL",                      "Ensure MySQL is firewalled and not exposed to untrusted networks."),
    3389:  ("high",   "RDP",                        "Restrict RDP access to VPN or jump hosts and enable NLA."),
    4444:  ("high",   "Unknown (Metasploit default)", "Investigate this port immediately — 4444 is a common backdoor/C2 port."),
    5432:  ("medium", "PostgreSQL",                 "Ensure PostgreSQL is firewalled and not exposed to untrusted networks."),
    5900:  ("high",   "VNC",                        "Disable VNC or restrict it to localhost/VPN and require authentication."),
    6379:  ("medium", "Redis",                      "Ensure Redis is bound to localhost or firewalled from external access."),
    27017: ("medium", "MongoDB",                    "Ensure MongoDB is firewalled and authentication is enforced."),
}


def load_port_rules(config_path: str | None = None) -> dict[int, tuple[str, str, str]]:
    """Load port rules from a TOML config file, falling back to built-in defaults."""
    path = Path(config_path) if config_path else Path("sentinel_audit_config.toml")

    if not path.exists():
        return dict(_DEFAULT_PORT_RULES)

    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except Exception:
        return dict(_DEFAULT_PORT_RULES)

    ports_section = data.get("ports", {})
    if not ports_section:
        return dict(_DEFAULT_PORT_RULES)

    rules: dict[int, tuple[str, str, str]] = {}
    for port_str, entry in ports_section.items():
        try:
            port = int(port_str)
            severity = entry.get("severity", "medium")
            service = entry.get("service", f"Port {port}")
            recommendation = entry.get(
                "recommendation", "Review this port and restrict access as needed."
            )
            rules[port] = (severity, service, recommendation)
        except (ValueError, AttributeError):
            continue

    return rules if rules else dict(_DEFAULT_PORT_RULES)
