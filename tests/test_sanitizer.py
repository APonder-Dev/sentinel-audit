from sentinel_audit.sanitizer import sanitize_report


def test_sanitize_report_redacts_sensitive_fields():
    report = {
        "system_info": {
            "hostname": "DESKTOP-TEST",
            "current_user": "Anthony",
        },
        "network_info": {
            "ip_address": "192.168.1.10",
        },
    }

    sanitized = sanitize_report(report)

    assert sanitized["system_info"]["hostname"] == "[REDACTED]"
    assert sanitized["system_info"]["current_user"] == "[REDACTED]"
    assert sanitized["network_info"]["ip_address"] == "[REDACTED]"


def test_sanitize_report_redacts_listening_port_addresses():
    report = {
        "system_info": {},
        "network_info": {
            "listening_ports": [
                "TCP 0.0.0.0:445 0.0.0.0:0 LISTENING 4",
                "TCP 192.168.1.10:139 0.0.0.0:0 LISTENING 4",
                "TCP [::]:445 [::]:0 LISTENING 4",
            ],
        },
    }

    sanitized = sanitize_report(report)

    joined_output = "\n".join(sanitized["network_info"]["listening_ports"])

    assert "192.168.1.10" not in joined_output
    assert "0.0.0.0" not in joined_output
    assert "[::]" not in joined_output
    assert "[REDACTED_IP]" in joined_output


def test_sanitize_report_does_not_mutate_original_report():
    report = {
        "system_info": {
            "hostname": "DESKTOP-TEST",
            "current_user": "Anthony",
        },
        "network_info": {
            "ip_address": "192.168.1.10",
        },
    }

    sanitized = sanitize_report(report)

    assert sanitized["system_info"]["hostname"] == "[REDACTED]"
    assert report["system_info"]["hostname"] == "DESKTOP-TEST"
    assert report["network_info"]["ip_address"] == "192.168.1.10"