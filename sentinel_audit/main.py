from datetime import datetime

from rich.console import Console

from sentinel_audit.cli import parse_args
from sentinel_audit.collectors.disk_encryption import collect_disk_encryption_status
from sentinel_audit.collectors.firewall import collect_firewall_status
from sentinel_audit.collectors.network import collect_network_info
from sentinel_audit.collectors.processes import collect_process_info
from sentinel_audit.collectors.system_info import collect_system_info
from sentinel_audit.findings.disk_encryption_findings import analyze_disk_encryption_status
from sentinel_audit.findings.firewall_findings import analyze_firewall_status
from sentinel_audit.findings.network_findings import analyze_network_info
from sentinel_audit.findings.process_findings import analyze_process_info
from sentinel_audit.reporting.json_report import save_json_report
from sentinel_audit.reporting.markdown_report import save_markdown_report
from sentinel_audit.sanitizer import sanitize_report
from sentinel_audit.scoring import calculate_risk_score

VERSION = "0.3.0"
console = Console()

_SEVERITY_COLOR = {
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "informational": "green",
}


def run_audit() -> dict:
    console.print(f"[bold cyan]Running SentinelAudit v{VERSION}...[/bold cyan]")

    system_info = collect_system_info()
    network_info = collect_network_info()
    firewall_status = collect_firewall_status()
    process_info = collect_process_info()
    disk_encryption = collect_disk_encryption_status()

    findings = (
        analyze_firewall_status(firewall_status)
        + analyze_network_info(network_info)
        + analyze_process_info(process_info)
        + analyze_disk_encryption_status(disk_encryption)
    )

    risk_score = calculate_risk_score(findings)

    return {
        "tool": "SentinelAudit",
        "version": VERSION,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "risk_score": risk_score,
        "system_info": system_info,
        "network_info": network_info,
        "firewall_status": firewall_status,
        "process_info": process_info,
        "disk_encryption": disk_encryption,
        "findings": findings,
    }


def _print_risk_score(risk_score: dict) -> None:
    score = risk_score["score"]
    label = risk_score["label"]

    if score >= 90:
        color = "green"
    elif score >= 70:
        color = "yellow"
    elif score >= 50:
        color = "orange3"
    else:
        color = "red"

    console.print(f"\n[bold]Risk Score:[/bold] [{color}]{score}/100 — {label}[/{color}]")


def _print_findings_summary(findings: list[dict]) -> None:
    if not findings:
        return
    console.print("\n[bold]Findings Summary:[/bold]")
    for finding in findings:
        severity = finding.get("severity", "informational")
        color = _SEVERITY_COLOR.get(severity, "white")
        console.print(f"  [{color}][{severity.upper()}][/{color}] {finding['title']}")


def main() -> None:
    args = parse_args()

    if args.version:
        console.print(f"SentinelAudit v{VERSION}")
        return

    report = run_audit()

    _print_risk_score(report["risk_score"])
    _print_findings_summary(report["findings"])

    if args.sanitize:
        report = sanitize_report(report)

    if args.format in ["json", "both"]:
        save_json_report(report, f"{args.output}.json")
    if args.format in ["markdown", "both"]:
        save_markdown_report(report, f"{args.output}.md")

    console.print("\n[green]Audit complete.[/green]")
    console.print("Reports saved:")
    if args.format in ["json", "both"]:
        console.print(f"  - {args.output}.json")
    if args.format in ["markdown", "both"]:
        console.print(f"  - {args.output}.md")


if __name__ == "__main__":
    main()
