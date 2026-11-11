def analyze_process_info(process_info: dict) -> list[dict]:
    findings: list[dict] = []
    status = process_info.get("status", "unknown")

    if status == "unsupported":
        findings.append({
            "severity": "low",
            "title": "Process auditing not supported on this platform",
            "id": "SA-PROC-UNSUPPORTED", "collector": "processes", "kind": "gap",
            "description": "SentinelAudit could not audit running processes on this operating system.",
            "recommendation": "Manually review running processes and ensure no unauthorized services are active.",
        })
        return findings

    if status in {"error", "partial", "unknown"}:
        findings.append({
            "severity": "medium",
            "title": "Process information is incomplete" if status == "partial" else "Process information could not be collected",
            "id": "SA-PROC-UNVERIFIED", "collector": "processes", "kind": "gap",
            "description": process_info.get("details") or "Process ownership could not be fully verified.",
            "recommendation": "Review running processes manually and verify no unauthorized privileged services are active.",
        })
        if status != "partial":
            return findings

    privileged_count = process_info.get("privileged_count", 0)
    privileged_processes = process_info.get("privileged_processes", [])

    sample_names = ", ".join(p["name"] for p in privileged_processes[:5])
    sample_text = f" Sample processes: {sample_names}." if sample_names else ""

    if privileged_count > 40:
        findings.append({
            "severity": "medium",
            "title": f"High number of privileged processes detected ({privileged_count})",
            "id": "SA-PROC-HIGH-COUNT", "collector": "processes", "kind": "risk",
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
            "id": "SA-PROC-COUNT", "collector": "processes", "kind": "observation",
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
