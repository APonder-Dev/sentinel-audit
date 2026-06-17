import asyncio
from datetime import datetime

from rich.console import Console

from sentinel_audit.cli import parse_args
from sentinel_audit.collectors.disk_encryption import collect_disk_encryption_status
from sentinel_audit.collectors.firewall import collect_firewall_status
from sentinel_audit.collectors.network import collect_network_info
from sentinel_audit.collectors.processes import collect_process_info
from sentinel_audit.collectors.system_info import collect_system_info
from sentinel_audit.config import load_port_rules
from sentinel_audit.findings.disk_encryption_findings import analyze_disk_encryption_status
from sentinel_audit.findings.firewall_findings import analyze_firewall_status
from sentinel_audit.findings.network_findings import analyze_network_info
from sentinel_audit.findings.process_findings import analyze_process_info
from sentinel_audit.reporting.html_report import save_html_report
from sentinel_audit.reporting.json_report import save_json_report
from sentinel_audit.reporting.markdown_report import save_markdown_report
from sentinel_audit.sanitizer import sanitize_report
from sentinel_audit.scoring import calculate_risk_score

VERSION = "0.4.0"
console = Console()

_SEVERITY_COLOR = {
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "informational": "green",
}


async def _collect_all() -> tuple:
    return await asyncio.gather(
        asyncio.to_thread(collect_system_info),
        asyncio.to_thread(collect_network_info),
        asyncio.to_thread(collect_firewall_status),
        asyncio.to_thread(collect_process_info),
        asyncio.to_thread(collect_disk_encryption_status),
    )


def run_audit(config_path: str | None = None) -> dict:
    console.print(f"[bold cyan]Running SentinelAudit v{VERSION}...[/bold cyan]")

    port_rules = load_port_rules(config_path)

    system_info, network_info, firewall_status, process_info, disk_encryption = asyncio.run(
        _collect_all()
    )

    findings = (
        analyze_firewall_status(firewall_status)
        + analyze_network_info(network_info, port_rules)
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

    report = run_audit(config_path=args.config)

    _print_risk_score(report["risk_score"])
    _print_findings_summary(report["findings"])

    if args.sanitize:
        report = sanitize_report(report)

    fmt = args.format
    saved: list[str] = []

    if fmt in ("json", "all"):
        path = f"{args.output}.json"
        save_json_report(report, path)
        saved.append(path)
    if fmt in ("markdown", "all"):
        path = f"{args.output}.md"
        save_markdown_report(report, path)
        saved.append(path)
    if fmt in ("html", "all"):
        path = f"{args.output}.html"
        save_html_report(report, path)
        saved.append(path)

    console.print("\n[green]Audit complete.[/green]")
    console.print("Reports saved:")
    for p in saved:
        console.print(f"  - {p}")


if __name__ == "__main__":
    main()
