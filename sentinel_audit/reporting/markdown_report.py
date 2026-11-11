import html
import re
from pathlib import Path


def _text(value):
    value = html.escape(str(value)).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\\x60*_{}\[\]()#+.!|>-])", r"\\\1", value)


def _raw(value):
    text = str(value)
    longest = max((len(match[0]) for match in re.finditer(r"\x60+", text)), default=0)
    fence = "\x60" * max(3, longest + 1)
    return [fence + "text", text, fence, ""]


def render_markdown_report(data: dict) -> str:
    coverage = data.get("coverage", {})
    score = data.get("risk_score", {})
    scan = data.get("scan", {})
    lines = [
        "# SentinelAudit Report", "", "## Metadata",
        f"- **Version:** {_text(data.get('version', 'Unknown'))}",
        f"- **Generated At:** {_text(data.get('generated_at', 'Unknown'))}",
        f"- **Scan ID:** {_text(scan.get('id', 'CLI scan'))}",
        f"- **Mode:** {_text(scan.get('mode', data.get('execution', {}).get('mode', 'standard')))}",
        f"- **Sanitized:** {_text(data.get('sanitized', False))}", "",
        "## Assessment",
        f"- **Score:** {_text(score.get('score', 'Unknown'))}/100",
        f"- **Rating:** {_text(score.get('label', 'Unknown'))}",
        f"- **Coverage:** {_text(coverage.get('collected', 'Unknown'))}/5 checks",
        "Collection complete; not a security guarantee." if coverage.get("complete") else "Incomplete assessment; score is provisional.",
        "", "## System Information",
    ]
    for key, value in data.get("system_info", {}).items():
        lines.append(f"- **{_text(key)}:** {_text(value)}")
    lines += ["", "## Network Information", f"- **IP Address:** {_text(data.get('network_info', {}).get('ip_address', 'Unknown'))}", ""]
    network = data.get("network_info", {})
    lines += _raw("\n".join(network.get("listening_ports", [])))
    if network.get("inventory"):
        lines += ["| Protocol | Address | Port | Binding | Process | Service hint |", "| --- | --- | --- | --- | --- | --- |"]
        for entry in network["inventory"]:
            lines.append("| " + " | ".join(_text(entry.get(key) or "Unknown") for key in ("protocol", "address", "port", "binding", "process", "service_hint")) + " |")
    for label, field in (("Firewall", "firewall_status"), ("Processes", "process_info"), ("Disk Encryption", "disk_encryption")):
        result = data.get(field, {})
        lines += ["", f"## {label}", f"- **Collection status:** {_text(result.get('status', 'unknown'))}"]
        if field == "disk_encryption":
            encrypted, protection = result.get("encrypted"), result.get("protection_active")
            lines += [
                f"- **Data encrypted:** {'Yes' if encrypted is True else 'No' if encrypted is False else 'Unknown'}",
                f"- **Active protection:** {'On' if protection is True else 'Off / suspended' if protection is False else 'Unknown / not recorded'}",
                "Encrypted data and active key protection are separate states.",
            ]
        if field == "process_info":
            lines += [f"- **Privileged processes:** {_text(result.get('privileged_count', 'Unknown'))}"]
            if result.get("privileged_processes"):
                lines += ["", "| Process | PID | User |", "| --- | --- | --- |"]
                for process in result["privileged_processes"][:15]:
                    lines.append("| " + " | ".join(_text(process.get(key, "Unknown")) for key in ("name", "pid", "user")) + " |")
        lines += ["", *_raw(result.get("details", "No raw output recorded."))]
    lines += ["## Security Findings", ""]
    for finding in data.get("findings", []):
        lines += [
            f"### {_text(finding.get('title', 'Untitled'))}",
            f"- **ID:** {_text(finding.get('id', 'Legacy finding'))}",
            f"- **Severity:** {_text(finding.get('severity', 'unknown'))}",
            f"- **Description:** {_text(finding.get('description', ''))}",
            f"- **Recommendation:** {_text(finding.get('recommendation', ''))}", "",
        ]
    if not data.get("findings"):
        lines.append("No findings generated. Review collection coverage.")
    return "\n".join(lines)


def save_markdown_report(data: dict, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown_report(data), encoding="utf-8")
