def analyze_disk_encryption_status(disk_encryption: dict) -> list[dict]:
    findings: list[dict] = []
    status = disk_encryption.get("status", "unknown")
    encrypted = disk_encryption.get("encrypted")

    if status == "unsupported":
        findings.append({
            "severity": "low",
            "title": "Disk encryption status collection not supported",
            "description": "SentinelAudit could not check disk encryption status on this operating system.",
            "recommendation": "Manually verify that full-disk encryption is enabled using platform-specific tooling.",
        })
        return findings

    if status == "error":
        findings.append({
            "severity": "medium",
            "title": "Disk encryption status could not be verified",
            "description": "SentinelAudit encountered an error while checking disk encryption status.",
            "recommendation": (
                "Verify disk encryption manually. On Windows use manage-bde, "
                "on macOS use fdesetup, on Linux check lsblk for LUKS volumes."
            ),
        })
        return findings

    if encrypted is False:
        findings.append({
            "severity": "high",
            "title": "Disk encryption is not enabled",
            "description": "Full-disk encryption was not detected on this host.",
            "recommendation": (
                "Enable full-disk encryption immediately. Use BitLocker on Windows, "
                "FileVault on macOS, or LUKS on Linux to protect data at rest."
            ),
        })
    else:
        findings.append({
            "severity": "informational",
            "title": "Disk encryption is active",
            "description": "Full-disk encryption is enabled on this host.",
            "recommendation": "Ensure encryption keys are securely managed and recovery keys are stored safely.",
        })

    return findings
