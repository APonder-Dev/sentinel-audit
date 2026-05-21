import sys
from unittest.mock import patch
from sentinel_audit.cli import parse_args


def test_default_cli_arguments():
    with patch.object(sys, "argv", ["sentinel-audit"]):
        args = parse_args()
    assert args.format == "both"
    assert args.output == "reports/sentinel-audit-report"
    assert args.version is False

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