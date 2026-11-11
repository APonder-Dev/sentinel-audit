"""Conservative comparison: absence is not resolution without compatible coverage."""

from sentinel_audit.coverage import summarize_coverage
from sentinel_audit.findings.identity import normalize_findings


def compare_scans(baseline, current):
    before, after = baseline["report"], current["report"]
    warnings = []
    host_a = before.get("system_info", {}).get("hostname")
    host_b = after.get("system_info", {}).get("hostname")
    if not host_a or not host_b or host_a.casefold() != host_b.casefold():
        warnings.append("Host identities differ or are unavailable.")
    if baseline.get("mode") != current.get("mode"):
        warnings.append("Scan modes differ; visibility may have changed.")
    if before.get("port_rules") is None or before.get("port_rules") != after.get("port_rules"):
        warnings.append("Port-rule configuration differs or was not recorded.")
    if not before.get("analysis_version") or before.get("analysis_version") != after.get("analysis_version"):
        warnings.append("Analysis versions differ or were not recorded.")
    compatible = not warnings
    old = {item["id"]: item for item in normalize_findings(before.get("findings", []))}
    new = {item["id"]: item for item in normalize_findings(after.get("findings", []))}
    coverage_a = {item["key"]: item["status"] for item in summarize_coverage(before)["checks"]}
    coverage_b = {item["key"]: item["status"] for item in summarize_coverage(after)["checks"]}
    if any(status != "collected" for status in [*coverage_a.values(), *coverage_b.values()]):
        warnings.append("Incomplete collection: missing findings may be unverified rather than resolved.")
    groups = {key: [] for key in ("new", "resolved", "changed", "unchanged", "newly_observed", "no_longer_observed", "unverified")}
    for identity in sorted(old.keys() | new.keys()):
        previous, latest = old.get(identity), new.get(identity)
        finding = latest or previous
        collector = finding.get("collector", "unknown")
        complete = coverage_a.get(collector) == coverage_b.get(collector) == "collected"
        if previous and latest:
            fields = ("title", "severity", "description", "recommendation")
            group = "unchanged" if all(previous.get(key) == latest.get(key) for key in fields) else "changed"
        elif latest:
            group = "new" if compatible and complete else "newly_observed"
        else:
            if not (compatible and complete):
                group = "unverified"
            elif finding.get("kind") == "risk" and finding.get("severity") in {"low", "medium", "high", "critical"}:
                group = "resolved"
            else:
                group = "no_longer_observed"
        groups[group].append({"id": identity, "before": previous, "after": latest})
    return {
        "baseline_id": baseline["id"], "current_id": current["id"],
        "compatible": compatible, "warnings": warnings,
        "counts": {key: len(value) for key, value in groups.items()}, "groups": groups,
    }
