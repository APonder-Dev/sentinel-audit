from sentinel_audit.findings.process_findings import analyze_process_info


def test_unsupported_generates_low_finding():
    process_info = {"status": "unsupported", "privileged_count": 0, "privileged_processes": []}
    findings = analyze_process_info(process_info)
    assert len(findings) == 1
    assert findings[0]["severity"] == "low"


def test_error_generates_medium_finding():
    process_info = {"status": "error", "privileged_count": 0, "privileged_processes": [], "details": "Access denied"}
    findings = analyze_process_info(process_info)
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"


def test_low_privileged_count_generates_informational():
    process_info = {
        "status": "collected",
        "privileged_count": 10,
        "privileged_processes": [{"name": "svchost.exe", "pid": "1234", "user": "SYSTEM"}],
    }
    findings = analyze_process_info(process_info)
    assert len(findings) == 1
    assert findings[0]["severity"] == "informational"
    assert "10" in findings[0]["title"]


def test_high_privileged_count_generates_medium():
    process_info = {
        "status": "collected",
        "privileged_count": 50,
        "privileged_processes": [{"name": f"proc{i}", "pid": str(i), "user": "root"} for i in range(50)],
    }
    findings = analyze_process_info(process_info)
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
