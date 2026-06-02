def analyze_process_info(process_info: dict) -> list[dict]:
    findings: list[dict] = []
    status = process_info.get("status", "unknown")

    if status == "unsupported":
        findings.append({
            "severity": "low",
            "title": "Process auditing not supported on this platform",
            "description": "SentinelAudit could not audit running processes on this operating system.",
            "recommendation": "Manually review running processes and ensure no unauthorized services are active.",
        })
        return findings

    if status == "error":
        findings.append({
            "severity": "medium",
            "title": "Process information could not be collected",
            "description": "SentinelAudit encountered an error while retrieving the running process list.",
            "recommendation": "Review running processes manually and verify no unauthorized privileged services are active.",
        })
        return findings

    privileged_count = process_info.get("privileged_count", 0)
    privileged_processes = process_info.get("privileged_processes", [])

    sample_names = ", ".join(p["name"] for p in privileged_processes[:5])
    sample_text = f" Sample processes: {sample_names}." if sample_names else ""

    if privileged_count > 40:
        findings.append({
            "severity": "medium",
            "title": f"High number of privileged processes detected ({privileged_count})",
            "description": (
                f"{privileged_count} processes are running under a high-privilege account "
                f"(SYSTEM, root, or equivalent).{sample_text}"
            ),
            "recommendation": (
                "Review privileged processes and apply the principle of least privilege. "
                "Services should run under dedicated low-privilege service accounts where possible."
            ),
        })
    else:
        findings.append({
            "severity": "informational",
            "title": f"Privileged process audit completed ({privileged_count} found)",
            "description": (
                f"{privileged_count} processes are running under a high-privilege account "
                f"(SYSTEM, root, or equivalent).{sample_text}"
            ),
            "recommendation": (
                "Periodically review privileged processes to ensure only expected services "
                "are running with elevated permissions."
            ),
        })

    return findings
