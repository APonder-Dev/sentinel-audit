import json
from copy import deepcopy

from sentinel_audit.coverage import summarize_coverage
from sentinel_audit.findings.identity import normalize_findings
from sentinel_audit.reporting.html_report import render_html_report
from sentinel_audit.reporting.markdown_report import render_markdown_report
from sentinel_audit.sanitizer import sanitize_report


def export_report(scan, report_format, sanitize=True):
    report = deepcopy(scan["report"])
    report["findings"] = normalize_findings(report.get("findings", []))
    report["coverage"] = summarize_coverage(report)
    report["scan"] = {key: scan.get(key) for key in ("id", "mode", "created_at", "finished_at", "duration_seconds")}
    report["sanitized"] = sanitize
    if sanitize:
        report = sanitize_report(report)
    if report_format == "json":
        return json.dumps(report, indent=2, allow_nan=False), "application/json", "json"
    if report_format == "markdown":
        return render_markdown_report(report), "text/markdown", "md"
    if report_format == "html":
        return render_html_report(report), "text/html", "html"
    raise ValueError("Unsupported report format")
