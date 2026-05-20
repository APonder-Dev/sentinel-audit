# SentinelAudit

SentinelAudit is a cross-platform endpoint security auditing tool designed to collect host posture data, identify basic hardening gaps, and generate structured reports for defensive security review.

## Why This Project Exists

This project is part of a cybersecurity and software development portfolio focused on practical defensive tooling, infrastructure visibility, and documentation-driven engineering.

SentinelAudit is intentionally built as a real utility instead of a generic beginner script. The goal is to demonstrate security-minded automation, clean project structure, and incremental engineering maturity.

## Current Version

**v0.1.2** introduces foundational host auditing and initial security findings analysis:

### Telemetry Collection

- Collect system information
- Collect hostname and current user
- Collect IP address
- Collect listening network ports
- Collect firewall status

### Reporting

- Export JSON reports
- Export Markdown reports
- Structured report generation pipeline

### Security Findings Engine

- Analyze firewall telemetry
- Generate severity-based findings
- Generate defensive recommendations
- Produce assessment-oriented output

## Tech Stack

- Python 3.12+
- Standard library collectors
- Rich for CLI output
- JSON and Markdown reporting

## Project Structure

```text
sentinel-audit/
├── sentinel_audit/
│   ├── collectors/
│   ├── reporting/
│   ├── findings/
│   └── main.py
├── docs/
├── reports/
├── tests/
├── requirements.txt
└── README.md
```

## Installation

```bash
git clone https://github.com/APonder-Dev/sentinel-audit.git
cd sentinel-audit
python -m venv .venv
```

### Windows

```bash
.venv\\Scripts\\activate
pip install -r requirements.txt
```

### Linux/macOS

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python -m sentinel_audit.main
```

Generated reports are saved to:

```text
reports/sentinel-audit-report.json
reports/sentinel-audit-report.md
```

## Security Considerations

SentinelAudit currently performs read-only local system checks. It does not exploit, modify, or attack systems. Some collectors may require elevated permissions depending on the operating system and command availability.

## Roadmap

- Expand findings engine coverage
- Add Windows-specific security policy checks
- Add Linux hardening checks
- Add service risk classification
- Add scan timestamps and unique scan IDs
- Add expanded automated test coverage
- Add report sanitization support
- Add CLI argument support
- Add Docker-based testing environment
- Add CI release validation workflows

## Project Status

**Maturity:** Early active development  
**Release:** v0.1.2 Added initial findings engine, severity classification, and assessment-oriented reporting capabilities.

## License

MIT License
