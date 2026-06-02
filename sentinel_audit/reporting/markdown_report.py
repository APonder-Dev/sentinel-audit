from pathlib import Path


def save_markdown_report(data: dict, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    system = data["system_info"]
    network = data["network_info"]
    firewall = data["firewall_status"]
    process_info = data.get("process_info", {})
    disk_encryption = data.get("disk_encryption", {})
    findings = data.get("findings", [])
    risk_score = data.get("risk_score", {})

    lines = [
        "# SentinelAudit Report",
        "",
        "## Metadata",
        f"- **Tool:** {data['tool']}",
        f"- **Version:** {data['version']}",
        f"- **Generated At:** {data['generated_at']}",
        "",
    ]

    if risk_score:
        lines += [
            "## Risk Score",
            f"- **Score:** {risk_score.get('score', 'N/A')}/100",
            f"- **Rating:** {risk_score.get('label', 'N/A')}",
            "",
        ]

    lines += [
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
    ]

    if process_info:
        privileged_count = process_info.get("privileged_count", 0)
        privileged_processes = process_info.get("privileged_processes", [])
        lines += [
            "## Process Audit",
            f"- **Status:** {process_info.get('status', 'unknown')}",
            f"- **Privileged Process Count:** {privileged_count}",
            "",
        ]
        if privileged_processes:
            lines += ["### Privileged Processes (sample)", ""]
            lines += ["| Name | PID | User |", "| --- | --- | --- |"]
            for proc in privileged_processes[:15]:
                lines.append(f"| {proc['name']} | {proc['pid']} | {proc['user']} |")
            lines.append("")

    if disk_encryption:
        encrypted = disk_encryption.get("encrypted")
        encryption_label = "Yes" if encrypted is True else ("No" if encrypted is False else "Unknown")
        lines += [
            "## Disk Encryption",
            f"- **Status:** {disk_encryption.get('status', 'unknown')}",
            f"- **Encrypted:** {encryption_label}",
            "",
            "```text",
            disk_encryption.get("details", ""),
            "```",
            "",
        ]

    lines.append("## Security Findings")

    if findings:
        for finding in findings:
            lines += [
                "",
                f"### {finding['title']}",
                f"- **Severity:** {finding['severity']}",
                f"- **Description:** {finding['description']}",
                f"- **Recommendation:** {finding['recommendation']}",
            ]
    else:
        lines += ["", "No security findings generated."]

    with path.open("w", encoding="utf-8") as file:
        file.write("\n".join(lines))
