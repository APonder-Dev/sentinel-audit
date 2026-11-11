# SentinelAudit v0.5.0

## Local Dashboard

- Launch scans, follow collector progress, and browse persistent SQLite scan history.
- Search and filter findings, inspect host details, and browse structured TCP listener and UDP socket inventories with process and service hints.
- See collection gaps, partial process ownership, and access-denied results separately from security findings. Raw diagnostics are tucked into expandable technical details.
- The dashboard/API binds to loopback and uses locally served assets. Existing CLI scanning remains available.

## Windows Deep Scans

- Request administrator access through Windows UAC for a separate privileged scan worker; the dashboard remains unelevated.
- Denying or cancelling approval stops the scan with a clear message, without silently falling back to a standard scan.
- Recognize BitLocker Used Space Only Encrypted correctly and report encrypted data separately from active key protection, including per-volume evidence.
- Unknown protection states remain unknown; encrypted data with protection off produces an independent warning.

## Report Exports

- Download completed stored scans as HTML, JSON, or Markdown without rerunning collectors.
- Sanitization is enabled by default and removes known host/user identifiers, addresses, and raw diagnostics. Review reports before sharing; sanitization is not an anonymity guarantee.
- Original stored reports are unchanged. Unsanitized exports may contain sensitive local evidence.

## Scan Comparison

- Stable finding IDs support comparisons across scans, with a read-only adapter for legacy reports.
- Compare new, resolved, changed, unchanged, newly observed, no longer observed, and unverified findings.
- Resolution requires an explicit risk finding, compatible host/mode/rules/analysis version, and complete relevant collector coverage in both scans.
- Disappearing informational observations are classified as No longer observed, not fixed risks. Missing evidence remains unverified; resolution is not proof of remediation.

## Getting Started

```sh
python -m pip install -r requirements.txt
python -m sentinel_audit.main --serve
```

Open http://127.0.0.1:8765. Use `--port` for another local port and `--config` for custom TOML port rules. Deep scan with UAC is Windows-only.

## Validation and Limits

- Automated backend and Chromium dashboard tests cover scan lifecycle, approval denial, storage, exports, comparison, and responsive views.
- Real Windows UAC-approved scans verified encryption/protection fields and matching-version comparison.
- Port matches are local observations, not verified vulnerabilities or remote-reachability tests. A complete scan is not a security guarantee.
- Historical reports are preserved; run a new scan to collect newly introduced fields. No local reports or scan databases are distributed.

Full changes: https://github.com/APonder-Dev/sentinel-audit/compare/v0.4.0...v0.5.0
