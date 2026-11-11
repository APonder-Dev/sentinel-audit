"""Run with SENTINEL_BROWSER_TESTS=1 after installing requirements-browser.txt."""

import os
import socket
import threading
import time
from copy import deepcopy
from pathlib import Path

import pytest
import uvicorn

from sentinel_audit.api import create_app
from sentinel_audit.elevation import ElevationDenied
from sentinel_audit.storage import ScanStore

pytestmark = pytest.mark.skipif(
    os.environ.get("SENTINEL_BROWSER_TESTS") != "1", reason="Opt-in browser tests",
)

REPORT = {
    "version": "0.5.0",
    "system_info": {"hostname": "workstation-07", "os": "Windows", "os_release": "11", "architecture": "64bit", "current_user": "analyst"},
    "network_info": {
        "status": "collected", "ip_address": "192.0.2.7",
        "listening_ports": ["TCP 0.0.0.0:3389 LISTENING"],
        "inventory": [
            {"protocol": "tcp", "family": "IPv4", "address": "0.0.0.0", "port": 3389, "state": "LISTEN", "binding": "all interfaces", "pid": 123, "process": "svchost.exe", "service_hint": "ms-wbt-server"},
            {"protocol": "udp", "family": "IPv6", "address": "::1", "port": 53, "state": "BOUND", "binding": "loopback", "pid": None, "process": None, "service_hint": "domain"},
        ],
    },
    "firewall_status": {"status": "collected", "details": "Domain profile: OFF"},
    "process_info": {"status": "collected", "privileged_count": 14},
    "disk_encryption": {"status": "error", "encrypted": None, "details": "Access denied"},
    "risk_score": {"score": 40, "label": "High Risk"},
    "findings": [
        {"severity": "high", "title": "Firewall may be disabled", "description": "Domain profile is OFF.", "recommendation": "Enable the host firewall and verify inbound rules."},
        {"severity": "high", "title": "Risky port open: 3389/RDP", "description": "Port 3389 is listening.", "recommendation": "Restrict RDP access to VPN or jump hosts."},
        {"severity": "medium", "title": "Disk encryption could not be verified", "description": "Collection returned access denied.", "recommendation": "Verify BitLocker status with appropriate privileges."},
        {"severity": "medium", "title": "Privileged processes detected", "description": "14 privileged processes were recorded.", "recommendation": "Review process ownership and necessity."},
        {"severity": "low", "title": "Review listening services", "description": "Review the local service inventory.", "recommendation": "Disable unused services."},
        {"severity": "informational", "title": "Host inventory collected", "description": "<img src=x onerror=alert('unsafe')>", "recommendation": "Retain the audit record."},
    ],
}


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setattr("sentinel_audit.api.deep_scan_available", lambda: True)
    release = threading.Event()
    control = {"fail": False, "deep_denied": False}
    def runner(config_path=None, on_progress=None):
        for name in ["system", "network", "firewall", "processes", "disk"]:
            on_progress(name, "running")
        on_progress("system", "finished")
        on_progress("network", "finished")
        if not release.wait(20):
            raise RuntimeError("Test scan timed out")
        if control["fail"]:
            raise RuntimeError("Test failure")
        for name in ["firewall", "processes"]:
            on_progress(name, "finished")
        on_progress("disk", "error")
        return REPORT
    path = tmp_path / "scans.db"
    def deep_runner(config_path=None, on_progress=None, on_started=None):
        if not release.wait(20):
            raise RuntimeError("Test approval timed out")
        if control["deep_denied"]:
            raise ElevationDenied("Administrator approval was denied or cancelled. Deep scan was not run.")
        on_started()
        result = deepcopy(runner(config_path, on_progress))
        result["execution"] = {"mode": "deep", "elevated": True}
        return result
    app = create_app(path, runner=runner, deep_runner=deep_runner)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        assert server.started
        yield f"http://127.0.0.1:{port}", release, path, control
    finally:
        release.set()
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
        assert not thread.is_alive()


@pytest.fixture
def page():
    playwright = pytest.importorskip("playwright.sync_api")
    with playwright.sync_playwright() as engine:
        browser = engine.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 1000}, device_scale_factor=1)
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        yield page
        browser.close()
        assert errors == []


def test_scan_workflow_and_responsive_layout(server, page):
    from playwright.sync_api import expect

    url, release, _, _ = server
    requests = []
    page.on("request", lambda request: requests.append(request.url))
    page.goto(url)
    expect(page.get_by_role("heading", name="No scans yet")).to_be_visible()
    page.get_by_role("button", name="Run first scan").click()
    expect(page.locator("#active-panel")).to_be_visible()
    expect(page.locator("#active-count")).to_have_text("2 / 5 finished", timeout=10000)
    expect(page.locator("#run-scan")).to_be_disabled()
    page.reload()
    expect(page.locator("#active-count")).to_have_text("2 / 5 finished", timeout=10000)
    release.set()
    expect(page.locator("#report-view")).to_be_visible(timeout=15000)
    expect(page.locator("#active-panel")).to_be_hidden()
    expect(page.locator("#score-value")).to_have_text("40")
    expect(page.locator("#coverage-warning")).to_be_visible()
    expect(page.locator("#coverage-value")).to_have_text("4")
    expect(page.locator("#score-confidence")).to_contain_text("Provisional")
    page.locator("#gap-toggle").click()
    expect(page.locator("#gap-list")).to_contain_text("Access denied")
    page.get_by_role("tab", name="Ports & services").click()
    expect(page.locator("#port-rows tr")).to_have_count(2)
    page.locator("#port-protocol").select_option("udp")
    expect(page.locator("#port-rows tr")).to_have_count(1)
    expect(page.locator("#port-rows")).to_contain_text("Unknown process")
    page.locator("#port-protocol").select_option("")
    page.get_by_label("Search ports").fill("svchost")
    expect(page.locator("#port-rows")).to_contain_text("3389")
    page.locator("#port-binding").select_option("loopback")
    expect(page.locator("#ports-empty")).to_contain_text("No sockets match")
    page.locator("#port-binding").select_option("")
    page.get_by_label("Search ports").fill("")
    page.get_by_role("tab", name="Findings").click()
    expect(page.locator("#findings-list details")).to_have_count(6)
    page.locator("#finding-severity").select_option("high")
    expect(page.locator("#findings-list details")).to_have_count(2)
    page.get_by_label("Search findings").fill("RDP")
    expect(page.locator("#findings-list details")).to_have_count(1)
    page.locator(".finding summary").click()
    expect(page.get_by_text("Restrict RDP access to VPN or jump hosts.")).to_be_visible()
    page.get_by_label("Search findings").fill("no-such-finding")
    expect(page.locator("#findings-empty")).to_be_visible()
    page.get_by_label("Search findings").fill("")
    page.locator("#finding-severity").select_option("")
    page.get_by_role("tab", name="Host details").click()
    expect(page.locator("#host-fields")).to_contain_text("workstation-07")
    page.get_by_role("tab", name="Host details").press("ArrowRight")
    expect(page.get_by_role("tab", name="Collection")).to_be_focused()
    expect(page.locator("#collection-list")).to_contain_text("error")
    page.get_by_role("tab", name="Findings").click()
    page.get_by_text("Host inventory collected", exact=True).click()
    expect(page.locator(".finding-body").filter(has_text="<img src=x")).to_be_visible()
    assert page.locator("#findings-list img").count() == 0
    page.get_by_text("Host inventory collected", exact=True).click()
    shots = Path(".cache/dashboard")
    shots.mkdir(parents=True, exist_ok=True)
    page.evaluate("window.scrollTo(0, 0)")
    page.screenshot(path=str(shots / "desktop.png"), full_page=True)
    page.set_viewport_size({"width": 390, "height": 844})
    page.evaluate("window.scrollTo(0, 0)")
    page.screenshot(path=str(shots / "mobile.png"), full_page=True)
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.get_by_role("tab", name="Ports & services").click()
    expect(page.locator("#port-rows tr")).to_have_count(2)
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.locator("#nav-history").click()
    expect(page.locator("#history-rows tr")).to_have_count(1)
    page.get_by_role("link", name="workstation-07").click()
    expect(page.locator("#score-value")).to_have_text("40")
    assert all(request.startswith(url) for request in requests)


def test_history_pagination_filters_failure_and_reconnect(server, page):
    from playwright.sync_api import expect

    url, release, path, control = server
    store = ScanStore(path)
    for _ in range(12):
        scan_id = store.create()
        store.finish(scan_id, 1, report=REPORT)
    page.goto(url + "/#history")
    expect(page.locator("#history-rows tr")).to_have_count(10)
    page.get_by_role("button", name="Next page").click()
    expect(page.locator("#history-rows tr")).to_have_count(2)
    page.get_by_label("Search history").fill("missing")
    expect(page.locator("#history-empty")).to_be_visible()
    page.get_by_label("Search history").fill("WORKSTATION")
    expect(page.locator("#history-rows tr")).to_have_count(10)
    control["fail"] = True
    release.set()
    page.get_by_role("button", name="Run scan", exact=True).click()
    expect(page.locator("#scan-error")).to_be_visible(timeout=15000)
    expect(page.locator("#scan-error")).to_contain_text("Scan failed")
    page.get_by_label("Main navigation").get_by_role("link", name="Scan history").click()
    page.get_by_label("Search history").fill("")
    page.locator("#history-status").select_option("failed")
    expect(page.locator("#history-rows tr")).to_have_count(1)
    page.route("**/api/**", lambda route: route.abort())
    page.get_by_role("button", name="Refresh history").click()
    expect(page.locator("#connection")).to_have_text("Disconnected")
    expect(page.locator("#run-scan")).to_be_disabled()
    page.unroute("**/api/**")
    page.get_by_role("button", name="Retry").click()
    expect(page.locator("#connection")).to_have_text("Local connection")
    expect(page.locator("#run-scan")).to_be_enabled()


def test_clear_gap_messages_and_collapsed_technical_output(server, page):
    from playwright.sync_api import expect

    url, _, path, _ = server
    report = deepcopy(REPORT)
    report["process_info"] = {
        "status": "partial", "process_count": 479, "unknown_owner_count": 187,
        "details": "Raw process diagnostic <script>unsafe()</script>",
    }
    report["disk_encryption"]["details"] = "BitLocker Drive Encryption: Configuration Tool\nERROR: Access denied. Check administrative rights."
    store = ScanStore(path)
    scan_id = store.create()
    store.finish(scan_id, 1, report=report)
    page.goto(url + "/#scan/" + scan_id)
    page.locator("#gap-toggle").click()
    gaps = page.locator("#gap-list")
    expect(gaps).to_contain_text("Process ownership partially available")
    expect(gaps).to_contain_text("187 of 479 processes")
    expect(gaps).to_contain_text("BitLocker status requires elevated access")
    expect(gaps).to_contain_text("does not mean encryption is disabled")
    for raw in gaps.locator("pre").all():
        expect(raw).to_be_hidden()
    disk = gaps.locator(".coverage-gap").filter(has_text="BitLocker status requires elevated access")
    disk.get_by_text("Technical details", exact=True).click()
    expect(disk.locator("pre")).to_be_visible()
    expect(disk.locator("pre")).to_contain_text("BitLocker Drive Encryption: Configuration Tool")
    disk.get_by_text("Technical details", exact=True).click()
    expect(disk.locator("pre")).to_be_hidden()
    assert gaps.locator("script").count() == 0
    page.get_by_role("tab", name="Collection", exact=True).click()
    process = page.locator(".collection-item").filter(has_text="Process ownership partially available")
    process.locator(":scope > summary").click()
    expect(process.locator(".collection-explanation")).to_be_visible()
    expect(process.locator("pre")).to_be_hidden()


def test_deep_scan_approval_denied_then_explicit_retry(server, page):
    from playwright.sync_api import expect

    url, release, _, control = server
    control["deep_denied"] = True
    page.goto(url)
    expect(page.locator("#scan-mode")).to_be_enabled()
    page.get_by_label("Scan mode").select_option("deep")
    page.get_by_role("button", name="Run deep scan", exact=True).click()
    expect(page.locator("#active-title")).to_have_text("Waiting for administrator approval")
    expect(page.locator("#pending-result")).to_contain_text("No scan runs")
    expect(page.locator("#scan-mode")).to_be_disabled()
    release.set()
    expect(page.locator("#scan-error")).to_contain_text("approval was denied", timeout=15000)
    expect(page.locator("#scan-status")).to_have_text("Approval denied")
    expect(page.locator("#report-view")).to_be_hidden()
    expect(page.locator("#active-panel")).to_be_hidden()
    page.locator("#nav-history").click()
    expect(page.locator("#history-rows tr")).to_have_count(1)
    expect(page.locator("#history-rows")).to_contain_text("Deep scan")
    expect(page.locator("#history-rows")).to_contain_text("Approval denied")
    control["deep_denied"] = False
    page.get_by_role("button", name="Run deep scan", exact=True).click()
    expect(page.locator("#report-view")).to_be_visible(timeout=15000)
    expect(page.locator("#scan-status")).to_have_text("completed")


def test_exports_comparison_and_protection_states(server, page):
    import json

    from playwright.sync_api import expect

    from sentinel_audit.findings.disk_encryption_findings import (
        analyze_disk_encryption_status,
    )

    url, _, path, _ = server
    store = ScanStore(path)
    report = deepcopy(REPORT)
    report.update(analysis_version=2, port_rules={})
    report["disk_encryption"] = {
        "status": "collected", "provider": "bitlocker", "encrypted": True, "protection_active": False,
    }
    report["findings"] = analyze_disk_encryption_status(report["disk_encryption"])
    report["findings"].append({
        "id": "SA-NET-NO-MATCH", "collector": "network", "kind": "observation",
        "severity": "informational", "title": "No configured port rules matched",
    })
    baseline = store.create()
    store.finish(baseline, 1, report=report)
    report["disk_encryption"]["protection_active"] = True
    report["findings"] = analyze_disk_encryption_status(report["disk_encryption"])
    current = store.create()
    store.finish(current, 1, report=report)
    page.goto(url + "/#scan/" + current)
    expect(page.locator("#export-toolbar")).to_be_visible()
    expect(page.locator("#export-sanitize")).to_be_checked()
    page.locator("#export-format").select_option("json")
    with page.expect_download() as download:
        page.locator("#export-report").click()
    data = json.loads(Path(download.value.path()).read_text(encoding="utf-8"))
    assert data["sanitized"] is True
    assert data["system_info"]["hostname"] != "workstation-07"
    assert data["scan"]["id"] == current
    page.get_by_role("tab", name="Collection", exact=True).click()
    expect(page.locator("#protection-summary")).to_contain_text("Data encrypted: Yes")
    expect(page.locator("#protection-summary")).to_contain_text("Active protection: On")
    page.get_by_role("tab", name="Compare", exact=True).click()
    expect(page.locator("#comparison-baseline option")).to_have_count(2)
    page.locator("#comparison-baseline").select_option(baseline)
    page.locator("#compare-scans").click()
    expect(page.locator("#comparison-counts")).to_contain_text("1 resolved")
    expect(page.locator("#comparison-counts")).to_contain_text("1 no longer observed")
    page.locator("#comparison-filter").select_option("no_longer_observed")
    expect(page.locator("#comparison-list details")).to_have_count(1)
    expect(page.locator("#comparison-list .badge.no_longer_observed")).to_have_text("no longer observed")
    expect(page.locator("#comparison-list")).to_contain_text("No configured port rules matched")
    expect(page.locator("#comparison-list .badge.resolved")).to_have_count(0)
    page.locator("#comparison-filter").select_option("resolved")
    expect(page.locator("#comparison-list details")).to_have_count(1)
    expect(page.locator("#comparison-list")).to_contain_text("SA-DISK-PROTECTION-OFF")
    page.locator("#comparison-list summary").click()
    expect(page.locator("#comparison-list")).to_contain_text("Not observed in this scan.")
    shots = Path(".cache/dashboard")
    shots.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(shots / "comparison-desktop.png"), full_page=True)
    page.set_viewport_size({"width": 390, "height": 844})
    page.screenshot(path=str(shots / "comparison-mobile.png"), full_page=True)
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
