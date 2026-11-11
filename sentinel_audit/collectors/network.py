import ipaddress
import socket

import psutil


def get_ip_address() -> str:
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "Unable to determine IP address"


def binding_scope(address: str) -> str:
    try:
        ip = ipaddress.ip_address(address.split("%")[0])
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    if ip.is_unspecified:
        return "all interfaces"
    return "specific interface"


def collect_network_info() -> dict:
    result = {
        "ip_address": get_ip_address(), "status": "collected",
        "source": "psutil.net_connections", "inventory": [], "listening_ports": [],
        "details": "", "remediation": "",
    }
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.Error, OSError) as error:
        result.update(
            status="error", details=f"Socket inventory unavailable: {type(error).__name__}: {error}",
            remediation="Review local sockets with netstat or ss. Check OS permissions; no privilege elevation is performed automatically.",
        )
        return result
    names = {}
    seen = set()
    for connection in connections:
        if not connection.laddr or (connection.type == socket.SOCK_STREAM and connection.status != psutil.CONN_LISTEN):
            continue
        if connection.type not in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            continue
        address, port = connection.laddr
        protocol = "tcp" if connection.type == socket.SOCK_STREAM else "udp"
        key = (protocol, address, port, connection.pid)
        if key in seen:
            continue
        seen.add(key)
        if connection.pid not in names:
            try:
                names[connection.pid] = psutil.Process(connection.pid).name() if connection.pid is not None else None
            except (psutil.Error, OSError):
                names[connection.pid] = None
        try:
            service = socket.getservbyport(port, protocol)
        except OSError:
            service = None
        row = {
            "protocol": protocol, "family": "IPv6" if connection.family == socket.AF_INET6 else "IPv4",
            "address": address, "port": port, "state": "LISTEN" if protocol == "tcp" else "BOUND",
            "binding": binding_scope(address), "pid": connection.pid,
            "process": names[connection.pid], "service_hint": service,
        }
        result["inventory"].append(row)
    result["inventory"].sort(key=lambda row: (row["port"], row["protocol"], row["address"], row["pid"] or -1))
    result["listening_ports"] = [
        f"{row['protocol']} {row['state']} [{row['address']}]:{row['port']} pid={row['pid']}"
        for row in result["inventory"]
    ]
    result["unknown_process_count"] = sum(row["process"] is None for row in result["inventory"])
    result["details"] = (
        "Local TCP listeners and bound UDP sockets. Service hints are local port-name conventions, "
        "not verified application identities. Bindings do not establish remote reachability. "
        "OS permissions may limit socket and process visibility."
    )
    return result


def get_listening_ports() -> list[str]:
    """Compatibility wrapper for consumers of the legacy text inventory."""
    result = collect_network_info()
    return result["listening_ports"] if result["status"] == "collected" else [result["details"]]
