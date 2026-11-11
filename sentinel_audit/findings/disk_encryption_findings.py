def analyze_disk_encryption_status(disk_encryption: dict) -> list[dict]:
    findings = []

    def add(rule, severity, title, description, recommendation, kind):
        findings.append({
            "id": "SA-DISK-" + rule, "collector": "disk", "kind": kind,
            "severity": severity, "title": title, "description": description,
            "recommendation": recommendation,
        })

    status = disk_encryption.get("status", "unknown")
    encrypted = disk_encryption.get("encrypted")
    if status == "unsupported":
        add("UNSUPPORTED", "low", "Disk encryption status collection not supported",
            "This platform's encryption state was not collected.",
            "Verify encryption using native OS tools.", "gap")
        return findings
    if status in {"error", "unknown"} or encrypted is None:
        add("UNVERIFIED", "medium", "Disk encryption status could not be verified",
            "Reported volume encryption is unknown or incomplete.",
            "Verify each volume with native OS encryption tools and appropriate permissions.", "gap")
    elif encrypted is False:
        add("NOT-ENCRYPTED", "high", "Disk encryption is not enabled",
            "The reported volumes are not encrypted.",
            "Enable encryption and securely retain recovery information.", "risk")
    else:
        add("ENCRYPTED", "informational", "Disk data is encrypted",
            "Reported volume data is encrypted. Encryption alone does not establish that key protection is enabled.",
            "Verify active protection and securely retain recovery information.", "observation")

    if disk_encryption.get("provider") == "bitlocker" or "protection_active" in disk_encryption:
        protection = disk_encryption.get("protection_active")
        if protection is False:
            add("PROTECTION-OFF", "high", "BitLocker protection is off or suspended",
                "At least one reported volume has Protection Off. Data may remain encrypted while key protection is disabled.",
                "Review suspension and maintenance requirements, then resume BitLocker protection when appropriate.", "risk")
        elif protection is None:
            add("PROTECTION-UNKNOWN", "medium", "BitLocker protection could not be verified",
                "Active protection was not verified for every reported volume.",
                "Check Protection Status for each volume. Do not infer protection from encryption percentage.", "gap")
        else:
            add("PROTECTION-ON", "informational", "BitLocker protection is enabled",
                "Protection On was reported for every listed volume.",
                "Keep recovery information secure and review protection after maintenance.", "observation")
    return findings
