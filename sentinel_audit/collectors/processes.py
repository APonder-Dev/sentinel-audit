import psutil


def collect_process_info() -> dict:
    result = {
        "status": "collected", "privileged_count": 0, "privileged_processes": [],
        "process_count": 0, "unknown_owner_count": 0, "details": "", "remediation": "",
    }
    privileged = []
    try:
        for process in psutil.process_iter(["pid", "name", "username"], ad_value=None):
            info = process.info
            result["process_count"] += 1
            user = info.get("username")
            if not user:
                result["unknown_owner_count"] += 1
                continue
            if user.lower() in {"root", "system", "nt authority\\system", "nt authority\\local service", "nt authority\\network service"}:
                privileged.append({
                    "name": info.get("name") or "Unknown", "pid": str(info["pid"]), "user": user,
                })
    except (psutil.Error, OSError) as error:
        result.update(status="error", details=f"Process inventory unavailable: {type(error).__name__}: {error}")
    result["privileged_count"] = len(privileged)
    result["privileged_processes"] = privileged[:30]
    if result["status"] != "error" and result["unknown_owner_count"]:
        result.update(
            status="partial",
            details=f"Ownership unavailable for {result['unknown_owner_count']} of {result['process_count']} processes. Privileged counts are a lower bound.",
        )
    if result["status"] != "collected":
        result["remediation"] = "Review processes with OS tools and appropriate permissions. Protected or exited processes may remain unavailable."
    return result
