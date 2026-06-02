# SentinelAudit

SentinelAudit is a cross-platform endpoint security auditing and assessment tool designed to collect host posture telemetry, identify hardening gaps, and generate structured defensive security reports.

The project focuses on practical defensive security engineering, operational visibility, and incremental tooling maturity.

---

# Why This Project Exists

SentinelAudit was created as part of a cybersecurity and software development portfolio centered around:

- Defensive security tooling
- Infrastructure visibility
- Host auditing
- Security automation
- Structured engineering workflows
- Documentation-driven development

The goal is to build a legitimate operational utility instead of a generic beginner project.

SentinelAudit is intentionally designed to evolve incrementally through realistic engineering practices including:

- Feature branching
- Pull requests
- Semantic versioning
- CI/CD validation
- Automated testing
- Structured reporting
- Security findings analysis

---

# Current Version

## v0.3.0

SentinelAudit v0.3.0 expands the findings engine and telemetry coverage significantly, adding open port risk analysis, privileged process auditing, disk encryption status checking, and a risk score system.

---

# Features

## Telemetry Collection

- Collect system information
- Collect hostname and current user
- Collect operating system details
- Collect architecture and processor information
- Collect local IP address
- Collect listening network ports
- Collect firewall status (Windows and Linux)
- Collect running process list with privilege context
- Collect disk encryption status (BitLocker, FileVault, LUKS)

---

## Security Findings Engine

- Analyze firewall telemetry
- Analyze listening ports against a known risky port database
- Analyze privileged process counts (SYSTEM/root)
- Analyze disk encryption status across platforms
- Generate severity-based findings (high, medium, low, informational)
- Generate defensive recommendations per finding
- Produce assessment-oriented reporting
- Identify unsupported or failed telemetry collection states

### Risky Port Detection

The findings engine flags the following ports when found listening:

| Port | Service | Severity |
| --- | --- | --- |
| 21 | FTP | High |
| 23 | Telnet | High |
| 3389 | RDP | High |
| 4444 | Unknown (Metasploit default) | High |
| 5900 | VNC | High |
| 135 | MS-RPC | Medium |
| 139 | NetBIOS | Medium |
| 445 | SMB | Medium |
| 1433 | MSSQL | Medium |
| 1521 | Oracle DB | Medium |
| 3306 | MySQL | Medium |
| 5432 | PostgreSQL | Medium |
| 6379 | Redis | Medium |
| 27017 | MongoDB | Medium |

---

## Risk Scoring

SentinelAudit calculates a risk score for each audit run based on the severity of all findings generated.

| Severity | Penalty |
| --- | --- |
| High | -20 |
| Medium | -10 |
| Low | -5 |
| Informational | 0 |

Score ratings:

| Score Range | Rating |
| --- | --- |
| 90 – 100 | Low Risk |
| 70 – 89 | Moderate Risk |
| 50 – 69 | Elevated Risk |
| 0 – 49 | High Risk |

The risk score is printed to the console after each audit and included in both JSON and Markdown report outputs.

---

## Reporting

- Export JSON reports
- Export Markdown reports
- Generate structured report output
- Generate findings-oriented assessments
- Include risk score summary in all report formats
- Include process audit results in all report formats
- Include disk encryption status in all report formats
- Support custom report output paths
- Support sanitized report generation
- Redact sensitive host information from exported reports

---

## CLI Features

- Select report output formats
- Generate JSON-only reports
- Generate Markdown-only reports
- Generate both report formats simultaneously
- Specify custom output paths
- Display version information from CLI
- Generate sanitized reports using --sanitize

---

# Tech Stack

- Python 3.12+
- Python standard library
- Rich CLI output
- Pytest
- Ruff
- GitHub Actions CI/CD

---

# Project Structure

```text
sentinel-audit/
├── .github/
│   └── workflows/
│       └── python-ci.yml
│
├── sentinel_audit/
│   ├── collectors/
│   │   ├── system_info.py
│   │   ├── network.py
│   │   ├── firewall.py
│   │   ├── processes.py
│   │   └── disk_encryption.py
│   ├── findings/
│   │   ├── firewall_findings.py
│   │   ├── network_findings.py
│   │   ├── process_findings.py
│   │   └── disk_encryption_findings.py
│   ├── reporting/
│   │   ├── json_report.py
│   │   └── markdown_report.py
│   ├── cli.py
│   ├── main.py
│   ├── sanitizer.py
│   └── scoring.py
│
├── reports/
├── tests/
├── requirements.txt
└── README.md
```

---

# Installation

## Clone Repository

```bash
git clone https://github.com/APonder-Dev/sentinel-audit.git
cd sentinel-audit
```

---

## Create Virtual Environment

```bash
python -m venv .venv
```

---

## Windows Setup

```bash
.venv\Scripts\activate
pip install -r requirements.txt
```

---

## Linux/macOS Setup

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

---

# Usage

## Default Execution

```bash
python -m sentinel_audit.main
```

---

## Generate JSON Report Only

```bash
python -m sentinel_audit.main --format json
```

---

## Generate Markdown Report Only

```bash
python -m sentinel_audit.main --format markdown
```

---

## Generate Both Report Formats

```bash
python -m sentinel_audit.main --format both
```

---

## Custom Output Path

```bash
python -m sentinel_audit.main --output reports/custom-audit
```

---

## Show Version

```bash
python -m sentinel_audit.main --version
```

---

## Generate Sanitized Reports

```bash
python -m sentinel_audit.main --sanitize
```

Sanitized reports redact sensitive information including:

- Hostname
- Current user
- Local IP address

---

# Example Output Files

Generated reports are saved to:

```text
reports/sentinel-audit-report.json
reports/sentinel-audit-report.md
```

Custom output example:

```text
reports/custom-audit.json
reports/custom-audit.md
```

---

# Example Security Findings

### Risky Port Finding

```json
{
  "severity": "high",
  "title": "Risky port open: 3389/RDP",
  "description": "Port 3389 (RDP) is listening on this host.",
  "recommendation": "Restrict RDP access to VPN or jump hosts and enable NLA."
}
```

### Disk Encryption Finding

```json
{
  "severity": "high",
  "title": "Disk encryption is not enabled",
  "description": "Full-disk encryption was not detected on this host.",
  "recommendation": "Enable full-disk encryption immediately. Use BitLocker on Windows, FileVault on macOS, or LUKS on Linux to protect data at rest."
}
```

### Risk Score Output

```json
{
  "risk_score": {
    "score": 60,
    "label": "Elevated Risk"
  }
}
```

### Sanitized Output

```json
{
  "hostname": "[REDACTED]",
  "current_user": "[REDACTED]",
  "ip_address": "[REDACTED]"
}
```

---

# Testing

## Run Ruff Linting

```bash
python -m ruff check .
```

---

## Run Automated Tests

```bash
python -m pytest
```

29 tests across findings analysis, CLI parsing, sanitization, and risk scoring.

---

# CI/CD

SentinelAudit includes GitHub Actions CI validation for:

- Ruff linting
- Pytest execution
- Multi-version Python validation (3.11, 3.12, 3.13)
- Pull request validation

---

# Security Considerations

SentinelAudit performs read-only local system checks only.

The project:

- Does not exploit systems
- Does not attack networks
- Does not modify firewall rules
- Does not perform offensive actions

Some collectors may require elevated permissions depending on the operating system and available system utilities. For example, BitLocker status on Windows may require administrator privileges.

---

# Roadmap

## Planned Improvements

- Add HTML report format with visual findings dashboard
- Add Windows security policy auditing
- Add Linux hardening analysis (CIS benchmark checks)
- Add scan timestamps and unique scan IDs
- Add export filtering controls
- Add Docker-based testing environments
- Add release validation workflows
- Add plugin-based collector architecture
- Add macOS firewall (pf) support

---

# Project Status

**Maturity:** Early active development

**Release:** v0.3.0

Added open port risk analysis, privileged process auditing, disk encryption status checking, and a 0-100 risk scoring system across all platforms.

---

# License

MIT License
