"""Collection confidence independent of the heuristic risk score."""

CHECKS = (
    ("system", "System", "system_info"),
    ("network", "Network", "network_info"),
    ("firewall", "Firewall", "firewall_status"),
    ("processes", "Processes", "process_info"),
    ("disk", "Encryption", "disk_encryption"),
)


def summarize_coverage(report):
    checks = []
    for key, label, field in CHECKS:
        data = report.get(field) or {}
        status = data.get("status", "collected" if key == "system" and data else "unknown")
        if key == "disk" and status == "collected" and data.get("encrypted") is None:
            status = "unknown"
        if key == "disk" and status == "collected" and (
            data.get("provider") == "bitlocker" or report.get("system_info", {}).get("os") == "Windows"
        ) and data.get("protection_active") is None:
            status = "partial"
        if status not in {"collected", "partial", "error", "unsupported", "unknown"}:
            status = "unknown"
        checks.append({
            "key": key, "label": label, "status": status,
            "details": data.get("details") or ("Coverage was not recorded for this check." if status == "unknown" else ""),
            "remediation": data.get("remediation") or (
                "Review this check with native OS tools and appropriate permissions."
                if status != "collected" else ""
            ),
        })
    complete = sum(check["status"] == "collected" for check in checks)
    return {"complete": complete == len(checks), "collected": complete, "total": len(checks), "checks": checks}
