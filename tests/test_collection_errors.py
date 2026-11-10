import subprocess
from unittest.mock import patch

import pytest

from sentinel_audit.collectors import disk_encryption, firewall, network, processes
from sentinel_audit.config import load_port_rules


@pytest.mark.parametrize(
    "collector",
    [
        disk_encryption._collect_windows_bitlocker,
        disk_encryption._collect_macos_filevault,
        disk_encryption._collect_linux_luks,
        firewall.collect_firewall_status,
        processes._collect_windows,
        processes._collect_unix,
        network.get_listening_ports,
    ],
)
@pytest.mark.parametrize(
    "error",
    [
        FileNotFoundError("missing command"),
        PermissionError("access denied"),
        subprocess.TimeoutExpired("command", 10),
        UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid byte"),
    ],
)
def test_collectors_report_expected_errors(collector, error):
    with (
        patch("platform.system", return_value="Windows"),
        patch("subprocess.run", side_effect=error),
    ):
        result = collector()

    if collector is network.get_listening_ports:
        assert result == [f"Error collecting listening ports: {error}"]
    else:
        assert result["status"] == "error"
        assert result["details"]


@pytest.mark.parametrize("contents", [b"[invalid", b"\xff"])
def test_config_falls_back_for_invalid_files(tmp_path, contents):
    defaults = load_port_rules(str(tmp_path / "missing.toml"))
    config = tmp_path / "rules.toml"
    config.write_bytes(contents)
    assert load_port_rules(str(config)) == defaults


def test_config_falls_back_for_read_errors(tmp_path):
    defaults = load_port_rules(str(tmp_path / "missing.toml"))
    with (
        patch("pathlib.Path.exists", return_value=True),
        patch("pathlib.Path.open", side_effect=PermissionError("access denied")),
    ):
        assert load_port_rules("rules.toml") == defaults
