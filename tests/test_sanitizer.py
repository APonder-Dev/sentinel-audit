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