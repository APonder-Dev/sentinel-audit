# SentinelAudit

SentinelAudit is a cross-platform endpoint security auditing tool designed to collect host posture data, identify basic hardening gaps, and generate structured reports for defensive security review.

## Why This Project Exists

This project is part of a cybersecurity and software development portfolio focused on practical defensive tooling, infrastructure visibility, and documentation-driven engineering.

SentinelAudit is intentionally built as a real utility instead of a generic beginner script. The goal is to demonstrate security-minded automation, clean project structure, and incremental engineering maturity.

## Current Version

**v0.1.1** focuses on foundational host auditing:

- Collect system information
- Collect hostname and current user
- Collect IP address
- Collect listening network ports
- Collect firewall status
- Export JSON reports
- Export Markdown reports

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

- Add structured findings with severity levels
- Add Windows-specific security policy checks
- Add Linux hardening checks
- Add service risk classification
- Add report timestamps and scan IDs
- Add test coverage
- Add GitHub Actions CI
- Add Docker-based test environment

## Project Status

**Maturity:** Early active development  
**Release:** v0.1.1 Functional collector integration and report generation improvements.

## License

MIT License
