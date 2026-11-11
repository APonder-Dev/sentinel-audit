import socket
from types import SimpleNamespace
from unittest.mock import Mock, patch

import psutil
import pytest

from sentinel_audit.collectors.disk_encryption import _collect_windows_bitlocker
from sentinel_audit.collectors.network import binding_scope, collect_network_info
from sentinel_audit.collectors.processes import collect_process_info
from sentinel_audit.coverage import summarize_coverage
from sentinel_audit.findings.disk_encryption_findings import (
    analyze_disk_encryption_status,
)
from sentinel_audit.findings.network_findings import analyze_network_info
from sentinel_audit.sanitizer import sanitize_report


def connection(address, port, protocol=socket.SOCK_STREAM, status=psutil.CONN_LISTEN, pid=1):
    return SimpleNamespace(
        laddr=(address, port), type=protocol, status=status, pid=pid,
        family=socket.AF_INET6 if ":" in address else socket.AF_INET,
    )


def test_inventory_filters_connections_preserves_ipv6_udp_and_unknown_processes():
    sockets = [
        connection("::", 3389), connection("::", 3389),
        connection("127.0.0.1", 53, socket.SOCK_DGRAM, psutil.CONN_NONE, None),
        connection("192.0.2.1", 4444, status=psutil.CONN_ESTABLISHED),
    ]
    with (
        patch("psutil.net_connections", return_value=sockets),
        patch("psutil.Process", side_effect=psutil.AccessDenied()),
        patch("socket.getservbyport", return_value="port-convention"),
    ):
        result = collect_network_info()
    assert result["status"] == "collected"
    assert len(result["inventory"]) == 2
    udp, tcp = result["inventory"]
    assert udp["protocol"] == "udp"
    assert udp["state"] == "BOUND"
    assert udp["binding"] == "loopback"
    assert udp["pid"] is None
    assert tcp["family"] == "IPv6"
    assert tcp["binding"] == "all interfaces"
    assert tcp["process"] is None
    assert result["unknown_process_count"] == 2
    findings = analyze_network_info(result)
    assert any("3389" in finding["title"] for finding in findings)
    assert not any("4444" in finding["title"] for finding in findings)


@pytest.mark.parametrize("failure", [psutil.AccessDenied(), OSError("socket access failed")])
def test_socket_failure_is_not_a_clean_scan(failure):
    with patch("psutil.net_connections", side_effect=failure):
        result = collect_network_info()
    assert result["status"] == "error"
    assert result["inventory"] == []
    assert analyze_network_info(result)[0]["severity"] == "medium"


def test_successful_empty_socket_inventory_is_distinct_from_failure():
    with patch("psutil.net_connections", return_value=[]):
        result = collect_network_info()
    assert result["status"] == "collected"
    assert analyze_network_info(result)[0]["severity"] == "informational"


@pytest.mark.parametrize(("address", "expected"), [
    ("::1", "loopback"), ("0.0.0.0", "all interfaces"),
    ("fe80::1%eth0", "specific interface"), ("invalid", "unknown"),
])
def test_bindings(address, expected):
    assert binding_scope(address) == expected


def test_process_ownership_gaps_are_partial():
    processes = [
        SimpleNamespace(info={"pid": 1, "name": "init", "username": "root"}),
        SimpleNamespace(info={"pid": 2, "name": "protected", "username": None}),
    ]
    with patch("psutil.process_iter", return_value=processes):
        result = collect_process_info()
    assert result["status"] == "partial"
    assert result["unknown_owner_count"] == 1
    assert result["privileged_count"] == 1
    assert result["process_count"] == 2


def test_process_failure_preserves_unknown_state():
    with patch("psutil.process_iter", side_effect=psutil.AccessDenied()):
        assert collect_process_info()["status"] == "error"


@pytest.mark.parametrize(("output", "encrypted", "status"), [
    ("Conversion Status: Fully Encrypted", True, "partial"),
    ("Conversion Status: Used Space Only Encrypted", True, "partial"),
    ("Conversion Status:   USED SPACE ONLY ENCRYPTED  \r\n", True, "partial"),
    ("Conversion Status: Fully Encrypted\nConversion Status: Used Space Only Encrypted", True, "partial"),
    ("Conversion Status: Used Space Only Encrypted\nConversion Status: Fully Decrypted", None, "partial"),
    ("Conversion Status: Used Space Only Encrypted\nConversion Status: Encryption in Progress", None, "partial"),
    ("Conversion Status: Used Space Only Encrypted\nConversion Status: Unrecognized", None, "partial"),
    ("Conversion Status: Fully Decrypted", False, "partial"),
    ("Conversion Status: Fully Encrypted\nConversion Status: Fully Decrypted", None, "partial"),
    ("Unrecognized or localized output", None, "partial"),
])
def test_bitlocker_does_not_assume_all_volumes_are_encrypted(output, encrypted, status):
    with patch("subprocess.run", return_value=Mock(stdout=output, stderr="", returncode=0)):
        result = _collect_windows_bitlocker()
    assert result["encrypted"] is encrypted
    assert result["status"] == status


def test_unknown_encryption_never_becomes_active():
    findings = analyze_disk_encryption_status({"status": "collected", "encrypted": None})
    assert findings[0]["severity"] == "medium"
    assert not any(finding["title"] == "Disk encryption is active" for finding in findings)


def test_used_space_only_output_clears_encryption_gap():
    output = (
        "Volume C: []\n[OS Volume]\n"
        "    Conversion Status:    Used Space Only Encrypted\n"
        "    Percentage Encrypted: 100.0%\n"
        "    Protection Status:    Protection On\n"
    )
    with patch("subprocess.run", return_value=Mock(stdout=output, stderr="", returncode=0)):
        result = _collect_windows_bitlocker()
    findings = analyze_disk_encryption_status(result)
    assert [finding["id"] for finding in findings] == ["SA-DISK-ENCRYPTED", "SA-DISK-PROTECTION-ON"]
    coverage = summarize_coverage({"disk_encryption": result})
    assert next(check for check in coverage["checks"] if check["key"] == "disk")["status"] == "collected"


def test_coverage_does_not_trust_legacy_network_or_unknown_encryption():
    report = {
        "system_info": {"hostname": "test"},
        "network_info": {"listening_ports": ["legacy data"]},
        "firewall_status": {"status": "collected"},
        "process_info": {"status": "partial"},
        "disk_encryption": {"status": "collected", "encrypted": None},
    }
    result = summarize_coverage(report)
    assert result["collected"] == 2
    assert not result["complete"]
    assert [item["status"] for item in result["checks"]] == ["collected", "unknown", "collected", "partial", "unknown"]


def test_sanitizes_new_network_inventory_without_mutation():
    report = {"network_info": {"inventory": [{"address": "::1", "port": 80}]}}
    assert sanitize_report(report)["network_info"]["inventory"][0]["address"] == "[REDACTED_IP]"
    assert report["network_info"]["inventory"][0]["address"] == "::1"


def test_legacy_ipv6_does_not_match_address_segments_as_ports():
    result = analyze_network_info({"listening_ports": ["tcp LISTEN 0 128 [2001:3389::1]:8080 [::]:*"]})
    assert result[0]["severity"] == "informational"
