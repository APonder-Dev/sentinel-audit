# SentinelAudit

SentinelAudit is a cross-platform endpoint security auditing and assessment tool designed to collect host posture telemetry, identify basic hardening gaps, and generate structured defensive security reports.

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

## v0.2.1

SentinelAudit v0.2.1 introduces sanitized reporting support for safer report sharing and improved operational security.

---

# Features

## Telemetry Collection

- Collect system information
- Collect hostname and current user
- Collect operating system details
- Collect architecture and processor information
- Collect local IP address
- Collect listening network ports
- Collect Windows firewall status

---

## Security Findings Engine

- Analyze firewall telemetry
- Generate severity-based findings
- Generate defensive recommendations
- Produce assessment-oriented reporting
- Identify unsupported or failed telemetry collection states

---

## Reporting

- Export JSON reports
- Export Markdown reports
- Generate structured report output
- Generate findings-oriented assessments
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
│   ├── findings/
│   ├── reporting/
│   ├── cli.py
│   └── main.py
│
├── docs/
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

Sanitized output example:

```text
reports/sentinel-audit-report.json
reports/sentinel-audit-report.md
```

---

# Example Security Finding

```json
{
  "severity": "informational",
  "title": "Firewall status collected",
  "description": "Firewall telemetry was collected successfully.",
  "recommendation": "Review collected firewall details for profile-specific configuration issues."
}
```

# Example Sanitized Output

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

---

# CI/CD

SentinelAudit includes GitHub Actions CI validation for:

- Ruff linting
- Pytest execution
- Multi-version Python validation
- Pull request validation

---

# Security Considerations

SentinelAudit currently performs read-only local system checks.

The project:

- Does not exploit systems
- Does not attack networks
- Does not modify firewall rules
- Does not perform offensive actions

Some collectors may require elevated permissions depending on the operating system and available system utilities.

---

# Roadmap

## Planned Improvements

- Expand findings engine coverage
- Add Windows security policy auditing
- Add Linux hardening analysis
- Add service risk classification
- Add scan timestamps and unique scan IDs
- Add export filtering controls
- Add Docker-based testing environments
- Add release validation workflows
- Add plugin-based collector architecture

---

# Project Status

**Maturity:** Early active development

**Release:** v0.2.1

Added sanitized reporting support, sensitive data redaction, and safer report-sharing workflows.

---

# License

MIT License