from datetime import datetime

from rich.console import Console

from sentinel_audit.cli import parse_args
from sentinel_audit.collectors.firewall import collect_firewall_status
from sentinel_audit.collectors.network import collect_network_info
from sentinel_audit.collectors.system_info import collect_system_info
from sentinel_audit.findings.firewall_findings import analyze_firewall_status
from sentinel_audit.reporting.json_report import save_json_report
from sentinel_audit.reporting.markdown_report import save_markdown_report

VERSION = "0.2.0"
console = Console()


def run_audit() -> dict:
    console.print(f"[bold cyan]Running SentinelAudit v{VERSION}...[/bold cyan]")

    system_info = collect_system_info()
    network_info = collect_network_info()
    firewall_status = collect_firewall_status()
    findings = analyze_firewall_status(firewall_status)
    return {
        "tool": "SentinelAudit",
        "version": VERSION,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "system_info": system_info,
        "network_info": network_info,
        "firewall_status": firewall_status,
        "findings": findings,
    }

def main() -> None:
    args = parse_args()

    if args.version:
        console.print(f"SentinelAudit v{VERSION}")
        return
    report = run_audit()
    if args.format in ["json", "both"]:
        save_json_report(report, f"{args.output}.json")
    if args.format in ["markdown", "both"]:
        save_markdown_report(report, f"{args.output}.md")
    console.print("[green]Audit complete.[/green]")
    console.print("Reports saved:")
    if args.format in ["json", "both"]:
        console.print(f"- {args.output}.json")
    if args.format in ["markdown", "both"]:
        console.print(f"- {args.output}.md")
if __name__ == "__main__":
    main()