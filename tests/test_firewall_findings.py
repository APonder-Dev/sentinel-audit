from sentinel_audit.findings.firewall_findings import analyze_firewall_status


def test_firewall_error_generates_medium_finding():
    firewall_status = {
        "status": "error",
        "details": "Unable to query firewall status",
    }

    findings = analyze_firewall_status(firewall_status)

    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert findings[0]["title"] == "Firewall status could not be verified"


def test_disabled_firewall_generates_high_finding():
    firewall_status = {
        "status": "collected",
        "details": "Firewall status: off",
    }

    findings = analyze_firewall_status(firewall_status)

    assert len(findings) == 1
    assert findings[0]["severity"] == "high"