from datetime import datetime

from rich.console import Console

from sentinel_audit.collectors.firewall import collect_firewall_status
from sentinel_audit.collectors.network import collect_network_info
from sentinel_audit.collectors.system_info import collect_system_info
from sentinel_audit.reporting.json_report import save_json_report
from sentinel_audit.reporting.markdown_report import save_markdown_report


console = Console()


def run_audit() -> dict:
    console.print("[bold cyan]Running SentinelAudit v0.1.1...[/bold cyan]")

    return {
        "tool": "SentinelAudit",
        "version": "0.1.1",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "system_info": collect_system_info(),
        "network_info": collect_network_info(),
        "firewall_status": collect_firewall_status(),
    }


def main() -> None:
    report = run_audit()

    save_json_report(report, "reports/sentinel-audit-report.json")
    save_markdown_report(report, "reports/sentinel-audit-report.md")

    console.print("[green]Audit complete.[/green]")
    console.print("Reports saved:")
    console.print("- reports/sentinel-audit-report.json")
    console.print("- reports/sentinel-audit-report.md")


if __name__ == "__main__":
    main()