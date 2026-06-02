from sentinel_audit.findings.network_findings import analyze_network_info


def test_risky_port_generates_high_finding():
    network_info = {
        "ip_address": "192.168.1.1",
        "listening_ports": [
            "tcp   LISTEN  0  128  0.0.0.0:3389  0.0.0.0:*",
        ],
    }
    findings = analyze_network_info(network_info)
    assert any(f["severity"] == "high" and "3389" in f["title"] for f in findings)


def test_telnet_port_generates_high_finding():
    network_info = {
        "ip_address": "10.0.0.1",
        "listening_ports": [
            "tcp   LISTEN  0  5  0.0.0.0:23  0.0.0.0:*",
        ],
    }
    findings = analyze_network_info(network_info)
    assert any(f["severity"] == "high" and "23" in f["title"] for f in findings)


def test_no_risky_ports_generates_informational():
    network_info = {
        "ip_address": "10.0.0.1",
        "listening_ports": [
            "tcp   LISTEN  0  128  0.0.0.0:8080  0.0.0.0:*",
        ],
    }
    findings = analyze_network_info(network_info)
    assert len(findings) == 1
    assert findings[0]["severity"] == "informational"


def test_error_in_ports_generates_medium_finding():
    network_info = {
        "ip_address": "10.0.0.1",
        "listening_ports": ["error collecting listening ports"],
    }
    findings = analyze_network_info(network_info)
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"


def test_empty_ports_generates_medium_finding():
    network_info = {"ip_address": "10.0.0.1", "listening_ports": []}
    findings = analyze_network_info(network_info)
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
