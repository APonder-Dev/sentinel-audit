from rich.console import Console

from sentinel_audit.audit import VERSION, run_audit
from sentinel_audit.cli import parse_args
from sentinel_audit.reporting.html_report import save_html_report
from sentinel_audit.reporting.json_report import save_json_report
from sentinel_audit.reporting.markdown_report import save_markdown_report
from sentinel_audit.sanitizer import sanitize_report

console = Console()

_SEVERITY_COLOR = {
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "informational": "green",
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

    if args.serve:
        from sentinel_audit.api import serve

        serve(port=args.port, config_path=args.config)
        return

    console.print(f"[bold cyan]Running SentinelAudit v{VERSION}...[/bold cyan]")
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
