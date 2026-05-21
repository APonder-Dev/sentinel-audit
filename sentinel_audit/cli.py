import argparse


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sentinel-audit",
        description="Run a local endpoint security audit and generate structured reports.",
    )

    parser.add_argument(
        "--format",
        choices=["json", "markdown", "both"],
        default="both",
        help="Report format to generate. Default: both",
    )

    parser.add_argument(
        "--output",
        default="reports/sentinel-audit-report",
        help="Base output path without extension. Default: reports/sentinel-audit-report",
    )

    parser.add_argument(
        "--version",
        action="store_true",
        help="Show SentinelAudit version and exit.",
    )
    
    return parser.parse_args()