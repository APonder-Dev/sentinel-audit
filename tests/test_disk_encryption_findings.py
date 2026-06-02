from sentinel_audit.findings.disk_encryption_findings import analyze_disk_encryption_status


def test_unsupported_generates_low_finding():
    result = analyze_disk_encryption_status({"status": "unsupported", "encrypted": None, "details": ""})
    assert len(result) == 1
    assert result[0]["severity"] == "low"


def test_error_generates_medium_finding():
    result = analyze_disk_encryption_status({"status": "error", "encrypted": None, "details": "Access denied"})
    assert len(result) == 1
    assert result[0]["severity"] == "medium"


def test_not_encrypted_generates_high_finding():
    result = analyze_disk_encryption_status({"status": "collected", "encrypted": False, "details": "Protection Off"})
    assert len(result) == 1
    assert result[0]["severity"] == "high"


def test_encrypted_generates_informational():
    result = analyze_disk_encryption_status({"status": "collected", "encrypted": True, "details": "Protection On"})
    assert len(result) == 1
    assert result[0]["severity"] == "informational"
