"""Explicit detector IDs, with a read-only adapter for older reports."""

import hashlib
import re
from copy import deepcopy

LEGACY = {
    "Firewall status collection is unsupported": ("SA-FW-UNSUPPORTED", "firewall", "gap"),
    "Firewall status could not be verified": ("SA-FW-UNVERIFIED", "firewall", "gap"),
    "Firewall may be disabled": ("SA-FW-DISABLED", "firewall", "risk"),
    "Firewall status collected": ("SA-FW-COLLECTED", "firewall", "observation"),
    "Listening port data could not be collected": ("SA-NET-UNVERIFIED", "network", "gap"),
    "No high-risk listening ports detected": ("SA-NET-NO-MATCH", "network", "observation"),
    "No configured port rules matched": ("SA-NET-NO-MATCH", "network", "observation"),
    "Process auditing not supported on this platform": ("SA-PROC-UNSUPPORTED", "processes", "gap"),
    "Process information could not be collected": ("SA-PROC-UNVERIFIED", "processes", "gap"),
    "Process information is incomplete": ("SA-PROC-UNVERIFIED", "processes", "gap"),
    "Disk encryption status collection not supported": ("SA-DISK-UNSUPPORTED", "disk", "gap"),
    "Disk encryption status could not be verified": ("SA-DISK-UNVERIFIED", "disk", "gap"),
    "Disk encryption is not enabled": ("SA-DISK-NOT-ENCRYPTED", "disk", "risk"),
    "Disk encryption is active": ("SA-DISK-ENCRYPTED", "disk", "observation"),
}


def normalize_findings(findings):
    result = deepcopy(findings)
    for finding in result:
        if finding.get("id"):
            continue
        title = finding.get("title", "")
        identity = LEGACY.get(title)
        port = re.match(r"Risky port open: (\d+)/", title)
        if port:
            identity = (f"SA-NET-PORT-{int(port[1])}", "network", "risk")
        elif title.startswith("High number of privileged processes detected ("):
            identity = ("SA-PROC-HIGH-COUNT", "processes", "risk")
        elif title.startswith("Privileged process audit completed ("):
            identity = ("SA-PROC-COUNT", "processes", "observation")
        if identity:
            finding["id"], finding["collector"], finding["kind"] = identity
            finding["identity_source"] = "legacy-adapter"
        else:
            finding["id"] = "LEGACY-" + hashlib.sha256(title.encode()).hexdigest()[:20]
            finding["collector"] = "unknown"
            finding["kind"] = "unknown"
            finding["identity_source"] = "legacy-title"
    return result
