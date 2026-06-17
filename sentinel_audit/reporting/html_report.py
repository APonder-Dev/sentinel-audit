import html
from pathlib import Path


_SEVERITY_COLOR = {
    "high":          ("#c0392b", "#fdecea"),
    "medium":        ("#d68910", "#fef9e7"),
    "low":           ("#2874a6", "#eaf4fb"),
    "informational": ("#1e8449", "#eafaf1"),
}

_SCORE_COLOR = {
    "Low Risk":      "#1e8449",
    "Moderate Risk": "#d68910",
    "Elevated Risk": "#ca6f1e",
    "High Risk":     "#c0392b",
}


def _e(value: object) -> str:
    return html.escape(str(value))


def _severity_badge(severity: str) -> str:
    text_color, bg_color = _SEVERITY_COLOR.get(severity, ("#555", "#eee"))
    return (
        f'<span style="background:{bg_color};color:{text_color};'
        f'padding:2px 8px;border-radius:4px;font-size:0.8em;'
        f'font-weight:600;text-transform:uppercase;border:1px solid {text_color}22;">'
        f"{_e(severity)}</span>"
    )


def _findings_rows(findings: list[dict]) -> str:
    if not findings:
        return '<tr><td colspan="3" style="text-align:center;color:#888;">No findings generated.</td></tr>'
    rows = []
    for f in findings:
        severity = f.get("severity", "informational")
        rows.append(
            f"<tr>"
            f"<td>{_severity_badge(severity)}</td>"
            f"<td><strong>{_e(f.get('title', ''))}</strong><br>"
            f"<small style='color:#555;'>{_e(f.get('description', ''))}</small></td>"
            f"<td style='color:#333;font-size:0.9em;'>{_e(f.get('recommendation', ''))}</td>"
            f"</tr>"
        )
    return "\n".join(rows)


def _process_rows(processes: list[dict]) -> str:
    if not processes:
        return '<tr><td colspan="3" style="color:#888;">No privileged processes recorded.</td></tr>'
    rows = []
    for p in processes[:15]:
        rows.append(
            f"<tr><td>{_e(p.get('name',''))}</td>"
            f"<td>{_e(p.get('pid',''))}</td>"
            f"<td>{_e(p.get('user',''))}</td></tr>"
        )
    return "\n".join(rows)


def _listening_ports_html(ports: list[str]) -> str:
    escaped = "\n".join(_e(line) for line in ports)
    return f'<pre style="background:#1e1e1e;color:#d4d4d4;padding:12px;border-radius:6px;overflow-x:auto;font-size:0.82em;margin:0;">{escaped}</pre>'


def save_html_report(data: dict, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    system      = data.get("system_info", {})
    network     = data.get("network_info", {})
    firewall    = data.get("firewall_status", {})
    process_info = data.get("process_info", {})
    disk        = data.get("disk_encryption", {})
    findings    = data.get("findings", [])
    risk_score  = data.get("risk_score", {})

    score = risk_score.get("score", "N/A")
    label = risk_score.get("label", "Unknown")
    score_color = _SCORE_COLOR.get(label, "#555")

    encrypted_raw = disk.get("encrypted")
    encrypted_label = "Yes" if encrypted_raw is True else ("No" if encrypted_raw is False else "Unknown")
    enc_color = "#1e8449" if encrypted_raw is True else ("#c0392b" if encrypted_raw is False else "#888")

    firewall_status = firewall.get("status", "unknown")
    fw_color = "#1e8449" if firewall_status == "collected" else "#c0392b"

    high_count   = sum(1 for f in findings if f.get("severity") == "high")
    medium_count = sum(1 for f in findings if f.get("severity") == "medium")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>SentinelAudit Report — {_e(data.get('generated_at',''))}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f4f6f9; color: #1a1a2e; line-height: 1.6; }}
    header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 60%, #0f3460 100%);
              color: #fff; padding: 32px 40px; display: flex;
              justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px; }}
    header h1 {{ font-size: 1.8em; font-weight: 700; letter-spacing: -0.5px; }}
    header .meta {{ font-size: 0.85em; color: #a0aec0; margin-top: 4px; }}
    .score-badge {{ text-align: center; background: rgba(255,255,255,0.08);
                    border-radius: 12px; padding: 16px 28px; min-width: 140px; }}
    .score-badge .score-num {{ font-size: 2.8em; font-weight: 800; color: {score_color}; line-height:1; }}
    .score-badge .score-label {{ font-size: 0.85em; color: #a0aec0; margin-top: 4px; }}
    main {{ max-width: 1100px; margin: 32px auto; padding: 0 24px 48px; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                     gap: 16px; margin-bottom: 28px; }}
    .card {{ background: #fff; border-radius: 10px; padding: 20px 24px;
             box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
    .card .label {{ font-size: 0.78em; text-transform: uppercase; letter-spacing: .6px;
                    color: #718096; font-weight: 600; margin-bottom: 6px; }}
    .card .value {{ font-size: 1.5em; font-weight: 700; }}
    section {{ background: #fff; border-radius: 10px; padding: 24px 28px; margin-bottom: 20px;
               box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
    section h2 {{ font-size: 1.1em; font-weight: 700; margin-bottom: 16px;
                  padding-bottom: 10px; border-bottom: 2px solid #e2e8f0; color: #2d3748; }}
    .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 8px 24px; }}
    .info-row {{ display: flex; gap: 8px; padding: 4px 0; font-size: 0.9em; }}
    .info-row .key {{ color: #718096; min-width: 130px; font-weight: 500; }}
    .info-row .val {{ color: #2d3748; word-break: break-all; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
    th {{ background: #f7fafc; text-align: left; padding: 10px 12px; font-size: 0.78em;
          text-transform: uppercase; letter-spacing: .5px; color: #718096;
          border-bottom: 2px solid #e2e8f0; }}
    td {{ padding: 10px 12px; border-bottom: 1px solid #f0f4f8; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #f7fafc; }}
    footer {{ text-align: center; font-size: 0.8em; color: #a0aec0; padding: 16px; }}
  </style>
</head>
<body>
<header>
  <div>
    <h1>SentinelAudit Report</h1>
    <div class="meta">v{_e(data.get('version',''))} &nbsp;·&nbsp; Generated {_e(data.get('generated_at',''))}</div>
  </div>
  <div class="score-badge">
    <div class="score-num">{_e(score)}</div>
    <div style="font-size:0.7em;color:#718096;margin-top:2px;">/ 100</div>
    <div class="score-label">{_e(label)}</div>
  </div>
</header>

<main>
  <div class="summary-grid">
    <div class="card">
      <div class="label">High Findings</div>
      <div class="value" style="color:#c0392b;">{high_count}</div>
    </div>
    <div class="card">
      <div class="label">Medium Findings</div>
      <div class="value" style="color:#d68910;">{medium_count}</div>
    </div>
    <div class="card">
      <div class="label">Total Findings</div>
      <div class="value">{len(findings)}</div>
    </div>
    <div class="card">
      <div class="label">Disk Encrypted</div>
      <div class="value" style="color:{enc_color};">{encrypted_label}</div>
    </div>
    <div class="card">
      <div class="label">Firewall</div>
      <div class="value" style="color:{fw_color};">{_e(firewall_status.capitalize())}</div>
    </div>
  </div>

  <section>
    <h2>System Information</h2>
    <div class="info-grid">
      <div class="info-row"><span class="key">Hostname</span><span class="val">{_e(system.get('hostname',''))}</span></div>
      <div class="info-row"><span class="key">Current User</span><span class="val">{_e(system.get('current_user',''))}</span></div>
      <div class="info-row"><span class="key">OS</span><span class="val">{_e(system.get('os',''))}</span></div>
      <div class="info-row"><span class="key">OS Release</span><span class="val">{_e(system.get('os_release',''))}</span></div>
      <div class="info-row"><span class="key">OS Version</span><span class="val">{_e(system.get('os_version',''))}</span></div>
      <div class="info-row"><span class="key">Architecture</span><span class="val">{_e(system.get('architecture',''))}</span></div>
      <div class="info-row"><span class="key">Machine</span><span class="val">{_e(system.get('machine',''))}</span></div>
      <div class="info-row"><span class="key">Processor</span><span class="val">{_e(system.get('processor',''))}</span></div>
      <div class="info-row"><span class="key">Platform</span><span class="val">{_e(system.get('platform',''))}</span></div>
    </div>
  </section>

  <section>
    <h2>Network Information</h2>
    <div class="info-row" style="margin-bottom:12px;">
      <span class="key">IP Address</span>
      <span class="val">{_e(network.get('ip_address',''))}</span>
    </div>
    <div style="margin-top:8px;">
      <div style="font-size:0.8em;font-weight:600;color:#718096;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;">Listening Ports</div>
      {_listening_ports_html(network.get('listening_ports', []))}
    </div>
  </section>

  <section>
    <h2>Firewall Status</h2>
    <div class="info-row" style="margin-bottom:12px;">
      <span class="key">Status</span>
      <span class="val" style="color:{fw_color};font-weight:600;">{_e(firewall_status)}</span>
    </div>
    <pre style="background:#1e1e1e;color:#d4d4d4;padding:12px;border-radius:6px;overflow-x:auto;font-size:0.82em;white-space:pre-wrap;">{_e(firewall.get('details',''))}</pre>
  </section>

  <section>
    <h2>Process Audit</h2>
    <div class="info-row" style="margin-bottom:12px;">
      <span class="key">Status</span><span class="val">{_e(process_info.get('status','unknown'))}</span>
    </div>
    <div class="info-row" style="margin-bottom:16px;">
      <span class="key">Privileged Count</span>
      <span class="val" style="font-weight:600;">{_e(process_info.get('privileged_count', 0))}</span>
    </div>
    <table>
      <thead><tr><th>Process Name</th><th>PID</th><th>User</th></tr></thead>
      <tbody>{_process_rows(process_info.get('privileged_processes', []))}</tbody>
    </table>
  </section>

  <section>
    <h2>Disk Encryption</h2>
    <div class="info-row"><span class="key">Status</span><span class="val">{_e(disk.get('status','unknown'))}</span></div>
    <div class="info-row" style="margin-bottom:12px;">
      <span class="key">Encrypted</span>
      <span class="val" style="color:{enc_color};font-weight:600;">{encrypted_label}</span>
    </div>
    <pre style="background:#1e1e1e;color:#d4d4d4;padding:12px;border-radius:6px;overflow-x:auto;font-size:0.82em;white-space:pre-wrap;">{_e(disk.get('details',''))}</pre>
  </section>

  <section>
    <h2>Security Findings</h2>
    <table>
      <thead><tr><th style="width:110px;">Severity</th><th>Finding</th><th>Recommendation</th></tr></thead>
      <tbody>{_findings_rows(findings)}</tbody>
    </table>
  </section>
</main>

<footer>Generated by SentinelAudit v{_e(data.get('version',''))} &nbsp;·&nbsp; {_e(data.get('generated_at',''))}</footer>
</body>
</html>"""

    with path.open("w", encoding="utf-8") as f:
        f.write(html_content)
