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

## v0.5.0

SentinelAudit v0.5.0 adds a local web dashboard with scan launch, progress,
history, findings, and structured ports/services views. Windows Deep scans use
UAC approval and a separate privileged worker while the dashboard stays unelevated.

Download stored reports as sanitized-by-default HTML, JSON, or Markdown. Compare
scans using stable finding IDs and coverage-aware changes. Disk encryption and
active BitLocker protection are reported separately; unknowns remain explicit.

Start with `python -m sentinel_audit.main --serve` and open
http://127.0.0.1:8765. Use `--port` to change the local port and `--config` to
select port rules. Existing CLI scan and export commands remain supported.

See the [v0.5.0 GitHub release](https://github.com/APonder-Dev/sentinel-audit/releases/tag/v0.5.0)
and [dashboard/API documentation](docs/backend-v0.5.0.md).

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
- Run all five collectors concurrently using `asyncio.gather` and worker threads

---

## Security Findings Engine

- Analyze firewall telemetry
- Analyze listening ports against built-in or custom TOML port rules
- Analyze privileged process counts (SYSTEM/root)
- Analyze disk encryption status across platforms
- Generate severity-based findings (high, medium, low, informational)
- Generate defensive recommendations per finding
- Produce assessment-oriented reporting
- Identify unsupported or failed telemetry collection states

### Risky Port Detection

The built-in rules flag the following ports when found listening. Custom TOML rules can replace this set (see [Custom Port Rules](#custom-port-rules)).

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

The risk score is printed to the console after each audit and included in JSON, Markdown, and HTML report outputs.

---

## Reporting

- Export JSON reports
- Export Markdown reports
- Export self-contained HTML reports with styled risk scores, severity badges, and summary cards
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
- Generate HTML-only reports
- Generate all three report formats simultaneously (the default)
- Load custom port rules using `--config PATH`
- Specify custom output paths
- Display version information from CLI
- Generate sanitized reports using `--sanitize`

---

# Tech Stack

- Python 3.11+
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
│   │   ├── html_report.py
│   │   └── markdown_report.py
│   ├── cli.py
│   ├── config.py
│   ├── main.py
│   ├── sanitizer.py
│   └── scoring.py
│
├── reports/
├── tests/
├── requirements.txt
├── sentinel_audit_config.toml
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

## CLI Options

| Option | Behavior | Default |
| --- | --- | --- |
| `--format {json,markdown,html,all}` | Select report formats | `all` |
| `--output PATH` | Base output path without an extension | `reports/sentinel-audit-report` |
| `--config PATH` | Load port rules from a TOML file | `sentinel_audit_config.toml` in the current working directory |
| `--sanitize` | Redact sensitive host information in exported reports | Off |
| `--version` | Show the version and exit | Off |
| `-h`, `--help` | Show CLI help and exit | Off |

**Upgrading from v0.3.0:** `--format both` is no longer supported. Use `--format all` to generate JSON, Markdown, and HTML, or select one format explicitly.

## Default Execution

```bash
python -m sentinel_audit.main
```

Generates JSON, Markdown, and HTML reports. Open the generated `.html` file in a browser to view the report.

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

## Generate HTML Report Only

```bash
python -m sentinel_audit.main --format html
```

---

## Generate All Report Formats

```bash
python -m sentinel_audit.main --format all
```

---

## Custom Port Rules

Use the included `sentinel_audit_config.toml` as a baseline, or specify another TOML file:

```bash
python -m sentinel_audit.main --config path/to/port-rules.toml
```

Example rule:

```toml
[ports.3389]
severity = "high"
service = "RDP"
recommendation = "Restrict RDP access to VPN or jump hosts and enable NLA."
```

Without `--config`, SentinelAudit looks for `sentinel_audit_config.toml` in the current working directory. Built-in rules are used when the file is missing, cannot be read or parsed, or contains no usable port rules.

Custom rules **replace**, rather than extend, the built-in rule set. Keep all ports you want checked in your configuration. Use `high`, `medium`, `low`, or `informational` for severity.

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
reports/sentinel-audit-report.html
```

Custom output example:

```text
reports/custom-audit.json
reports/custom-audit.md
reports/custom-audit.html
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

60 tests across findings analysis, CLI parsing, sanitization, risk scoring, collector error handling, and configuration fallbacks.

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

**Release:** [v0.5.0](https://github.com/APonder-Dev/sentinel-audit/releases/tag/v0.5.0)

Added the local dashboard, UAC-approved Deep scans, stored-report exports,
stable finding IDs, and conservative scan comparison alongside existing CLI auditing.

---

# License

MIT License
