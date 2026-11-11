import asyncio
from datetime import UTC, datetime

from sentinel_audit.collectors.disk_encryption import collect_disk_encryption_status
from sentinel_audit.collectors.firewall import collect_firewall_status
from sentinel_audit.collectors.network import collect_network_info
from sentinel_audit.collectors.processes import collect_process_info
from sentinel_audit.collectors.system_info import collect_system_info
from sentinel_audit.config import load_port_rules
from sentinel_audit.coverage import summarize_coverage
from sentinel_audit.findings.disk_encryption_findings import (
    analyze_disk_encryption_status,
)
from sentinel_audit.findings.firewall_findings import analyze_firewall_status
from sentinel_audit.findings.network_findings import analyze_network_info
from sentinel_audit.findings.process_findings import analyze_process_info
from sentinel_audit.scoring import calculate_risk_score

VERSION = "0.5.0"


COLLECTORS = ("system", "network", "firewall", "processes", "disk")


async def _collect_all(on_progress=None) -> tuple:
    async def collect(name, collector):
        if on_progress:
            on_progress(name, "running")
        result = await asyncio.to_thread(collector)
        if on_progress:
            status = result.get("status", "collected")
            on_progress(name, status if status in {"error", "unsupported", "partial", "unknown"} else "finished")
        return result

    return await asyncio.gather(*(
        collect(name, collector)
        for name, collector in zip(COLLECTORS, (
            collect_system_info, collect_network_info, collect_firewall_status,
            collect_process_info, collect_disk_encryption_status,
        ), strict=True)
    ))


def run_audit(config_path: str | None = None, on_progress=None, port_rules=None) -> dict:
    port_rules = load_port_rules(config_path) if port_rules is None else port_rules

    system_info, network_info, firewall_status, process_info, disk_encryption = asyncio.run(
        _collect_all(on_progress)
    )

    findings = (
        analyze_firewall_status(firewall_status)
        + analyze_network_info(network_info, port_rules)
        + analyze_process_info(process_info)
        + analyze_disk_encryption_status(disk_encryption)
    )

    risk_score = calculate_risk_score(findings)

    report = {
        "tool": "SentinelAudit",
        "version": VERSION,
        "analysis_version": 2,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "port_rules": {
            str(port): {"severity": rule[0], "service": rule[1], "recommendation": rule[2]}
            for port, rule in port_rules.items()
        },
        "risk_score": risk_score,
        "system_info": system_info,
        "network_info": network_info,
        "firewall_status": firewall_status,
        "process_info": process_info,
        "disk_encryption": disk_encryption,
        "findings": findings,
    }
    report["coverage"] = summarize_coverage(report)
    return report
