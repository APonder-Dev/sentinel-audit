from copy import deepcopy
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from sentinel_audit.api import create_app
from sentinel_audit.collectors.disk_encryption import parse_bitlocker_status
from sentinel_audit.comparison import compare_scans
from sentinel_audit.findings.disk_encryption_findings import (
    analyze_disk_encryption_status,
)
from sentinel_audit.findings.identity import normalize_findings
from sentinel_audit.reporting.exports import export_report
from sentinel_audit.storage import ScanStore


def report():
    return {
        "analysis_version": 2, "port_rules": {},
        "system_info": {"hostname": "private-host", "current_user": "private-user", "os": "Windows"},
        "network_info": {"status": "collected", "inventory": [], "ip_address": "192.0.2.7"},
        "firewall_status": {"status": "collected", "details": "private-host diagnostic"},
        "process_info": {"status": "collected", "privileged_count": 0},
        "disk_encryption": {"status": "collected", "provider": "bitlocker", "encrypted": True, "protection_active": True},
        "risk_score": {"score": 100, "label": "Low Risk"}, "findings": [],
    }


def scan(data):
    return {"id": str(uuid4()), "mode": "deep", "report": data}


def finding(identity, title="Test finding", collector="network"):
    return {"id": identity, "title": title, "collector": collector, "severity": "high", "kind": "risk"}


def test_comparison_groups_and_no_mutation():
    before, after = report(), report()
    before["findings"] = [finding("gone"), finding("same"), finding("changed")]
    after["findings"] = [finding("new"), finding("same"), finding("changed", "New evidence")]
    original = deepcopy(before)
    result = compare_scans(scan(before), scan(after))
    assert result["compatible"]
    assert result["counts"] == {"new": 1, "resolved": 1, "changed": 1, "unchanged": 1, "newly_observed": 0, "no_longer_observed": 0, "unverified": 0}
    assert before == original


@pytest.mark.parametrize("mismatch", ["coverage", "host", "mode", "rules", "version", "legacy"])
def test_missing_evidence_never_implies_resolution(mismatch):
    before, after = scan(report()), scan(report())
    before["report"]["findings"] = [finding("gone")]
    after["report"]["findings"] = [finding("new")]
    if mismatch == "coverage":
        after["report"]["network_info"]["status"] = "error"
    elif mismatch == "host":
        after["report"]["system_info"]["hostname"] = "another-host"
    elif mismatch == "mode":
        after["mode"] = "standard"
    elif mismatch == "rules":
        after["report"]["port_rules"] = {"22": "changed"}
    elif mismatch == "version":
        del before["report"]["analysis_version"]
    else:
        before["report"]["findings"] = [{"title": "Unknown legacy rule"}]
        after["report"]["findings"] = [{"title": "Other legacy rule"}]
    result = compare_scans(before, after)
    assert result["counts"]["resolved"] == result["counts"]["new"] == 0
    assert result["counts"]["unverified"] == result["counts"]["newly_observed"] == 1


def test_legacy_ids_survive_count_and_service_label_changes():
    inputs = [{"title": "Privileged process audit completed (14)"}, {"title": "Risky port open: 22/SSH"}]
    changed = [{"title": "Privileged process audit completed (27)"}, {"title": "Risky port open: 22/custom"}]
    assert [f["id"] for f in normalize_findings(inputs)] == [f["id"] for f in normalize_findings(changed)]
    assert all("id" not in f for f in inputs)


@pytest.mark.parametrize("kind,severity", [("observation", "informational"), ("gap", "medium"), ("risk", "informational"), (None, "high")])
@pytest.mark.parametrize("complete", [True, False])
def test_disappearing_non_risks_are_not_resolved(kind, severity, complete):
    before, after = report(), report()
    item = finding("absent")
    item.update(kind=kind, severity=severity)
    before["findings"] = [item]
    if not complete:
        after["network_info"]["status"] = "error"
    result = compare_scans(scan(before), scan(after))
    assert result["counts"]["resolved"] == 0
    group = "no_longer_observed" if complete else "unverified"
    assert result["groups"][group][0]["id"] == "absent"


def test_legacy_no_port_matches_is_not_a_resolved_risk():
    before, after = report(), report()
    before["findings"] = [{"title": "No configured port rules matched", "severity": "informational"}]
    result = compare_scans(scan(before), scan(after))
    assert result["counts"]["resolved"] == 0
    assert result["groups"]["no_longer_observed"][0]["id"] == "SA-NET-NO-MATCH"


@pytest.mark.parametrize("protection, expected", [("Protection On", True), ("Protection Off", False), ("Unknown", None)])
def test_encrypted_data_and_protection_are_independent(protection, expected):
    data = parse_bitlocker_status("Volume C:\nConversion Status: Used Space Only Encrypted\nProtection Status: " + protection)
    assert data["encrypted"] is True
    assert data["protection_active"] is expected
    findings = analyze_disk_encryption_status(data)
    ids = {item["id"] for item in findings}
    assert "SA-DISK-ENCRYPTED" in ids
    assert ("SA-DISK-PROTECTION-OFF" in ids) == (expected is False)
    assert ("SA-DISK-PROTECTION-UNKNOWN" in ids) == (expected is None)


def test_multiple_volumes_and_conflicting_protection():
    output = "Volume C:\nConversion Status: Fully Encrypted\nProtection Status: Protection On\nVolume D:\nConversion Status: Fully Encrypted\nProtection Status: Protection Off"
    data = parse_bitlocker_status(output)
    assert data["encrypted"] is True
    assert data["protection_active"] is False
    assert len(data["volumes"]) == 2
    ambiguous = parse_bitlocker_status(output.split("Volume D:")[0] + "Protection Status: Protection Off")
    assert ambiguous["protection_active"] is None
    assert ambiguous["status"] == "partial"


@pytest.mark.parametrize("format", ["json", "html", "markdown"])
def test_exports_sanitize_without_mutating_source(format):
    source = scan(report())
    recovery = "111111-222222-333333-444444-555555-666666-777777-888888"
    source["report"]["disk_encryption"]["details"] = recovery
    source["report"]["findings"] = [finding("stable-id", "<script>alert('x')</script> private-user 192.0.2.7")]
    original = deepcopy(source)
    content, _, _ = export_report(source, format)
    for secret in ("private-host", "private-user", "192.0.2.7", recovery):
        assert secret not in content
    if format != "json":
        assert "<script>alert" not in content
    assert source == original
    raw, _, _ = export_report(source, format, sanitize=False)
    assert "private" in raw


def test_export_and_compare_api_validation_and_storage(tmp_path):
    path = tmp_path / "scans.db"
    store = ScanStore(path)
    baseline = store.create()
    store.finish(baseline, 1, report=report())
    current = store.create()
    store.finish(current, 1, report=report())
    original = store.get(current)
    with TestClient(create_app(path), base_url="http://localhost") as client:
        for format, mime in [("json", "application/json"), ("html", "text/html"), ("markdown", "text/markdown")]:
            response = client.get(f"/api/scans/{current}/export?format={format}")
            assert response.status_code == 200
            assert response.headers["content-type"].startswith(mime)
            assert "-sanitized." in response.headers["content-disposition"]
            assert "private-host" not in response.text
        assert client.get(f"/api/scans/{current}/export?format=json&sanitize=false").json()["system_info"]["hostname"] == "private-host"
        assert client.get(f"/api/scans/{current}/export?format=pdf").status_code == 422
        assert client.get(f"/api/scans/{uuid4()}/export").status_code == 404
        assert client.get(f"/api/scans/{current}/compare?baseline={baseline}").json()["compatible"]
        assert client.get(f"/api/scans/{current}/compare?baseline={current}").status_code == 422
        assert client.get(f"/api/scans/{baseline}/compare?baseline={current}").status_code == 422
        pending = store.create()
        assert client.get(f"/api/scans/{pending}/export").status_code == 409
        assert client.get(f"/api/scans/{current}/compare?baseline={pending}").status_code == 409
        store.finish(pending, 0, error="Denied", status="denied")
        assert client.get(f"/api/scans/{pending}/export").status_code == 409
    assert store.get(current) == original
