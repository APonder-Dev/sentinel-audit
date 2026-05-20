from pathlib import Path


def save_markdown_report(data: dict, output_path: str) -> None:
    """Saves the collected data as a Markdown report."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    system = data["system_info"]
    network = data["network_info"]
    firewall = data["firewall_status"]
    findings = data.get("findings", [])

    lines = [
        "# SentinelAudit Report",
        "",
        "## Metadata",
        f"- **Tool:** {data['tool']}",
        f"- **Version:** {data['version']}",
        f"- **Generated At:** {data['generated_at']}",
        "",
        "## System Information",
        f"- **Hostname:** {system['hostname']}",
        f"- **Current User:** {system['current_user']}",
        f"- **OS:** {system['os']}",
        f"- **OS Release:** {system['os_release']}",
        f"- **OS Version:** {system['os_version']}",
        f"- **Platform:** {system['platform']}",
        f"- **Platform Version:** {system['platform_version']}",
        f"- **Architecture:** {system['architecture']}",
        f"- **Machine:** {system['machine']}",
        f"- **Processor:** {system['processor']}",
        "",
        "## Network Information",
        f"- **IP Address:** {network['ip_address']}",
        "",
        "### Listening Ports",
        "```text",
        *network["listening_ports"],
        "```",
        "",
        "## Firewall Status",
        f"- **Status:** {firewall['status']}",
        "",
        "```text",
        firewall["details"],
        "```",
        "",
        "## Security Findings",
    ]
    
    if findings:
        for finding in findings:
            lines.extend(
                [
                    "",
                    f"### {finding['title']}",
                    f"- **Severity:** {finding['severity']}",
                    f"- **Description:** {finding['description']}",
                    f"- **Recommendation:** {finding['recommendation']}",
                ]
            )
    else:
        lines.extend(["", "No security findings generated."])
        
    with path.open("w", encoding="utf-8") as file:
        file.write("\n".join(lines))