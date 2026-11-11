import sys
from unittest.mock import patch

import pytest

from sentinel_audit.cli import parse_args


def test_default_cli_arguments():
    with patch.object(sys, "argv", ["sentinel-audit"]):
        args = parse_args()
    assert args.format == "all"
    assert args.output == "reports/sentinel-audit-report"
    assert args.version is False
    assert args.config is None

def test_json_format_argument():
    with patch.object(sys, "argv", ["sentinel-audit", "--format", "json"]):
        args = parse_args()
    assert args.format == "json"

def test_custom_output_argument():
    with patch.object(
        sys,
        "argv",
        ["sentinel-audit", "--output", "reports/custom-audit"],
    ):
        args = parse_args()
    assert args.output == "reports/custom-audit"

def test_version_argument():
    with patch.object(sys, "argv", ["sentinel-audit", "--version"]):
        args = parse_args()
    assert args.version is True


def test_serve_arguments():
    with patch.object(sys, "argv", ["sentinel-audit", "--serve", "--port", "9001"]):
        args = parse_args()
    assert args.serve is True
    assert args.port == 9001


def test_invalid_port():
    with (
        patch.object(sys, "argv", ["sentinel-audit", "--serve", "--port", "0"]),
        pytest.raises(SystemExit),
    ):
        parse_args()
