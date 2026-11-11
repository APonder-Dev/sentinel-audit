from unittest.mock import patch

from sentinel_audit.audit import run_audit


def test_shared_engine_returns_report_without_console_output(capsys):
    progress = []
    with (
        patch("sentinel_audit.audit.collect_system_info", return_value={"hostname": "test"}),
        patch("sentinel_audit.audit.collect_network_info", return_value={"listening_ports": []}),
        patch("sentinel_audit.audit.collect_firewall_status", return_value={"status": "unsupported"}),
        patch("sentinel_audit.audit.collect_process_info", return_value={"status": "unsupported"}),
        patch("sentinel_audit.audit.collect_disk_encryption_status", return_value={"status": "unsupported"}),
        patch("sentinel_audit.audit.load_port_rules", return_value={22: ("low", "SSH", "Review")}),
    ):
        report = run_audit(on_progress=lambda name, status: progress.append((name, status)))
    assert report["system_info"]["hostname"] == "test"
    assert report["generated_at"].endswith("+00:00")
    assert report["port_rules"]["22"]["service"] == "SSH"
    assert capsys.readouterr().out == ""
    assert len(progress) == 10
    assert ("system", "finished") in progress
    assert ("firewall", "unsupported") in progress
