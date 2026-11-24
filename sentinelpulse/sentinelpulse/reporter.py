"""Report exporters for SentinelPulse: Interactive HTML SOC Dashboard, JSON, and Markdown."""

from collections import Counter
from datetime import datetime
from html import escape
import json
from pathlib import Path

from .models import Alert, CorrelatedIncident


def export_all_reports(
    output_dir: Path,
    total_events: int,
    ssh_events: int,
    web_events: int,
    skipped_lines: int,
    alerts: list[Alert],
    incidents: list[CorrelatedIncident],
) -> dict[str, Path]:
    """Write HTML dashboard, structured JSON feed, and Markdown incident brief."""
    output_dir.mkdir(parents=True, exist_ok=True)
    html_path = output_dir / "soc_report.html"
    json_path = output_dir / "alerts.json"
    md_path = output_dir / "incident_summary.md"

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _write_json_report(json_path, generated_at, total_events, alerts, incidents)
    _write_markdown_report(md_path, generated_at, total_events, ssh_events, web_events, incidents)
    _write_html_dashboard(
        html_path,
        generated_at,
        total_events,
        ssh_events,
        web_events,
        skipped_lines,
        alerts,
        incidents,
    )

    return {"html": html_path, "json": json_path, "markdown": md_path}


def _write_json_report(
    path: Path,
    generated_at: str,
    total_events: int,
    alerts: list[Alert],
    incidents: list[CorrelatedIncident],
) -> None:
    payload = {
        "tool": "SentinelPulse",
        "generated_at": generated_at,
        "metrics": {
            "total_events_parsed": total_events,
            "total_alerts": len(alerts),
            "total_incidents": len(incidents),
            "critical_incidents": sum(1 for i in incidents if i.severity == "CRITICAL"),
        },
        "incidents": [
            {
                "incident_id": inc.incident_id,
                "title": inc.title,
                "severity": inc.severity,
                "risk_score": inc.risk_score,
                "src_ip": inc.src_ip,
                "kill_chain_stages": inc.kill_chain_stages,
                "mitre_techniques": inc.mitre_techniques,
                "threat_intel": {
                    "reputation": inc.threat_intel.reputation,
                    "confidence": inc.threat_intel.confidence,
                    "category": inc.threat_intel.category,
                    "country": inc.threat_intel.country,
                    "asn": inc.threat_intel.asn,
                    "tags": inc.threat_intel.tags,
                },
                "first_seen": inc.first_seen.isoformat(),
                "last_seen": inc.last_seen.isoformat(),
                "recommended_actions": inc.recommended_actions,
                "containment_commands": inc.containment_commands,
                "alerts": [
                    {
                        "alert_id": a.alert_id,
                        "rule_id": a.rule_id,
                        "title": a.title,
                        "severity": a.severity,
                        "source": a.source,
                        "mitre_tactic": a.mitre_tactic,
                        "mitre_technique": a.mitre_technique,
                        "event_count": a.event_count,
                        "evidence": a.evidence,
                    }
                    for a in inc.alerts
                ],
            }
            for inc in incidents
        ],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_markdown_report(
    path: Path,
    generated_at: str,
    total_events: int,
    ssh_events: int,
    web_events: int,
    incidents: list[CorrelatedIncident],
) -> None:
    lines = [
        "# SentinelPulse SOC Incident Triage Report",
        "",
        f"- **Generated:** {generated_at}",
        f"- **Total Events Analyzed:** {total_events} (SSH: {ssh_events}, Web: {web_events})",
        f"- **Correlated Incidents:** {len(incidents)}",
        "",
        "## Prioritized Incidents",
        "",
    ]
    if not incidents:
        lines.append("No malicious or anomalous activity detected.")
    for inc in incidents:
        lines.extend(
            [
                f"### [{inc.severity}] {inc.incident_id} — {inc.title} (Risk: {inc.risk_score}/100)",
                f"- **Source IP:** `{inc.src_ip}` ({inc.threat_intel.reputation} | {inc.threat_intel.country} | {inc.threat_intel.category})",
                f"- **Kill Chain Stages:** {' -> '.join(inc.kill_chain_stages)}",
                f"- **MITRE ATT&CK:** {', '.join(inc.mitre_techniques)}",
                f"- **Window:** `{inc.first_seen}` to `{inc.last_seen}`",
                "- **Recommended Actions:**",
            ]
        )
        for act in inc.recommended_actions:
            lines.append(f"  - {act}")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def _write_html_dashboard(
    path: Path,
    generated_at: str,
    total_events: int,
    ssh_events: int,
    web_events: int,
    skipped_lines: int,
    alerts: list[Alert],
    incidents: list[CorrelatedIncident],
) -> None:
    sev_counts = Counter(i.severity for i in incidents)
    mitre_counts = Counter(tech for i in incidents for tech in i.mitre_techniques)
    total_inc = max(1, len(incidents))

    sev_bars_html = ""
    for sev, color in [
        ("CRITICAL", "#ef4444"),
        ("HIGH", "#f97316"),
        ("MEDIUM", "#eab308"),
        ("LOW", "#38bdf8"),
    ]:
        cnt = sev_counts.get(sev, 0)
        pct = int((cnt / total_inc) * 100) if incidents else 0
        sev_bars_html += f"""
        <div class="bar-row">
          <span class="bar-label">{sev}</span>
          <div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{color};"></div></div>
          <span class="bar-val">{cnt}</span>
        </div>"""

    mitre_pills_html = "".join(
        f'<span class="pill">{escape(tech)} <strong>({cnt})</strong></span>'
        for tech, cnt in mitre_counts.most_common(10)
    ) or '<span class="muted">No MITRE techniques triggered</span>'

    incident_cards_html = ""
    for inc in incidents:
        sev_cls = inc.severity.lower()
        stages_html = " &rarr; ".join(
            f'<span class="stage-chip">{escape(s)}</span>' for s in inc.kill_chain_stages
        )
        tags_html = " ".join(
            f'<span class="tag-chip">{escape(t)}</span>' for t in inc.threat_intel.tags
        )
        alerts_rows = ""
        for a in inc.alerts:
            ev_lines = "\n".join(escape(e) for e in a.evidence)
            alerts_rows += f"""
            <div class="alert-item">
              <div class="alert-head">
                <span class="badge badge-{a.severity.lower()}">{escape(a.severity)}</span>
                <strong>{escape(a.rule_id)}</strong> &mdash; {escape(a.title)}
                <span class="muted">({a.source.upper()} &bull; {a.event_count} event(s) &bull; {escape(a.mitre_technique)})</span>
              </div>
              <p class="alert-desc">{escape(a.description)}</p>
              <pre class="evidence">{ev_lines}</pre>
            </div>"""

        actions_html = "".join(f"<li>{escape(act)}</li>" for act in inc.recommended_actions)
        cmds_text = "\n".join(inc.containment_commands)

        incident_cards_html += f"""
        <article class="incident-card" data-severity="{escape(inc.severity)}" data-search="{escape((inc.src_ip + ' ' + inc.title + ' ' + ' '.join(inc.mitre_techniques)).lower())}">
          <div class="card-top">
            <div>
              <span class="badge badge-{sev_cls}">{escape(inc.severity)}</span>
              <span class="inc-id">{escape(inc.incident_id)}</span>
              <h3 class="inc-title">{escape(inc.title)}</h3>
            </div>
            <div class="risk-box">
              <span class="risk-num">{inc.risk_score}</span>
              <span class="risk-label">RISK / 100</span>
            </div>
          </div>

          <p class="inc-summary">{escape(inc.summary)}</p>

          <div class="meta-grid">
            <div><strong>Source IP:</strong> <code>{escape(inc.src_ip)}</code></div>
            <div><strong>Intel:</strong> {escape(inc.threat_intel.reputation)} ({inc.threat_intel.confidence}% conf) &bull; {escape(inc.threat_intel.country)} / {escape(inc.threat_intel.asn)}</div>
            <div><strong>Timeframe:</strong> {inc.first_seen.strftime('%Y-%m-%d %H:%M:%S')} &ndash; {inc.last_seen.strftime('%H:%M:%S')}</div>
            <div><strong>Alerts Triggered:</strong> {len(inc.alerts)}</div>
          </div>

          <div class="kill-chain"><strong>Kill Chain:</strong> {stages_html}</div>
          <div class="intel-tags">{tags_html}</div>

          <details open>
            <summary>Triggered Rules &amp; Log Evidence ({len(inc.alerts)})</summary>
            {alerts_rows}
          </details>

          <details>
            <summary>SOC Playbook &amp; Containment Commands</summary>
            <div class="playbook-box">
              <ul>{actions_html}</ul>
              <div class="cmd-wrap">
                <pre class="commands">{escape(cmds_text)}</pre>
              </div>
            </div>
          </details>
        </article>"""

    if not incident_cards_html:
        incident_cards_html = '<div class="empty-state">No threats detected across analyzed logs.</div>'

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SentinelPulse — SOC Incident Triage Dashboard</title>
  <style>
    :root {{
      --bg: #0b1120;
      --panel: #111827;
      --panel-alt: #1e293b;
      --border: #334155;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #38bdf8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }}
    .container {{ max-width: 1180px; margin: 0 auto; padding: 28px 20px 60px; }}
    header {{
      display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;
      border-bottom: 1px solid var(--border); padding-bottom: 18px; margin-bottom: 24px;
    }}
    h1 {{ margin: 0; font-size: 1.7rem; letter-spacing: 0.3px; }}
    h1 span {{ color: var(--accent); }}
    .subtitle {{ color: var(--muted); font-size: 0.92rem; margin-top: 4px; }}
    .kpi-grid {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px; margin-bottom: 22px;
    }}
    .kpi {{
      background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
      padding: 16px;
    }}
    .kpi-val {{ font-size: 1.8rem; font-weight: 700; }}
    .kpi-lbl {{ color: var(--muted); font-size: 0.85rem; }}
    .split-grid {{
      display: grid; grid-template-columns: 1fr 1.4fr; gap: 16px; margin-bottom: 24px;
    }}
    @media (max-width: 820px) {{ .split-grid {{ grid-template-columns: 1fr; }} }}
    .panel {{
      background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 18px;
    }}
    .panel h2 {{ margin: 0 0 12px; font-size: 1.05rem; color: var(--accent); }}
    .bar-row {{ display: flex; align-items: center; gap: 10px; margin: 8px 0; font-size: 0.85rem; }}
    .bar-label {{ width: 76px; font-weight: 600; }}
    .bar-track {{ flex: 1; height: 10px; background: var(--panel-alt); border-radius: 99px; overflow: hidden; }}
    .bar-fill {{ height: 100%; border-radius: 99px; }}
    .bar-val {{ width: 28px; text-align: right; color: var(--muted); }}
    .pill {{
      display: inline-block; background: var(--panel-alt); border: 1px solid var(--border);
      padding: 4px 10px; border-radius: 999px; font-size: 0.8rem; margin: 4px 4px 0 0;
    }}
    .toolbar {{
      display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 18px;
    }}
    .toolbar input, .toolbar select {{
      background: var(--panel); color: var(--text); border: 1px solid var(--border);
      border-radius: 8px; padding: 9px 12px; font-size: 0.9rem;
    }}
    .toolbar input {{ flex: 1; min-width: 220px; }}
    .incident-card {{
      background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
      padding: 20px; margin-bottom: 16px;
    }}
    .card-top {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }}
    .inc-id {{ color: var(--muted); font-family: monospace; margin-left: 8px; font-size: 0.9rem; }}
    .inc-title {{ margin: 8px 0 4px; font-size: 1.15rem; }}
    .inc-summary {{ color: var(--muted); margin: 6px 0 14px; font-size: 0.93rem; }}
    .risk-box {{
      background: var(--panel-alt); border: 1px solid var(--border); border-radius: 10px;
      padding: 8px 14px; text-align: center; min-width: 90px;
    }}
    .risk-num {{ display: block; font-size: 1.45rem; font-weight: 800; color: var(--accent); }}
    .risk-label {{ font-size: 0.7rem; color: var(--muted); letter-spacing: 0.5px; }}
    .badge {{
      display: inline-block; padding: 3px 9px; border-radius: 6px; font-size: 0.75rem;
      font-weight: 700; letter-spacing: 0.4px;
    }}
    .badge-critical {{ background: rgba(239,68,68,.2); color: #fca5a5; border: 1px solid var(--critical); }}
    .badge-high {{ background: rgba(249,115,22,.2); color: #fdba74; border: 1px solid var(--high); }}
    .badge-medium {{ background: rgba(234,179,8,.18); color: #fde047; border: 1px solid var(--medium); }}
    .badge-low {{ background: rgba(56,189,248,.18); color: #7dd3fc; border: 1px solid var(--low); }}
    .meta-grid {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 8px; font-size: 0.88rem; background: var(--panel-alt); padding: 12px;
      border-radius: 8px; margin-bottom: 12px;
    }}
    .kill-chain {{ margin: 10px 0; font-size: 0.88rem; }}
    .stage-chip {{
      display: inline-block; background: rgba(56,189,248,.14); color: #bae6fd;
      border: 1px solid rgba(56,189,248,.4); padding: 2px 8px; border-radius: 6px; font-size: 0.8rem;
    }}
    .intel-tags {{ margin-bottom: 12px; }}
    .tag-chip {{
      display: inline-block; background: #1f2937; color: #cbd5e1; border: 1px solid #374151;
      padding: 2px 8px; border-radius: 99px; font-size: 0.76rem; margin-right: 6px;
    }}
    details {{ margin-top: 10px; border-top: 1px solid var(--border); padding-top: 10px; }}
    summary {{ cursor: pointer; font-weight: 600; color: var(--accent); font-size: 0.92rem; }}
    .alert-item {{
      background: #0f172a; border: 1px solid #1e293b; border-radius: 8px;
      padding: 12px; margin-top: 10px;
    }}
    .alert-head {{ font-size: 0.9rem; }}
    .alert-desc {{ margin: 6px 0; font-size: 0.85rem; color: var(--muted); }}
    pre.evidence, pre.commands {{
      background: #020617; color: #cbd5e1; padding: 10px; border-radius: 6px;
      overflow-x: auto; font-size: 0.78rem; margin: 8px 0 0; border: 1px solid #1e293b;
    }}
    .playbook-box ul {{ margin: 8px 0 10px 18px; font-size: 0.88rem; }}
    .muted {{ color: var(--muted); font-size: 0.82rem; }}
    code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; }}
    .empty-state {{ text-align: center; padding: 40px; color: var(--muted); }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>Sentinel<span>Pulse</span> SOC Dashboard</h1>
        <div class="subtitle">Multi-Source Log Correlation &bull; MITRE ATT&amp;CK Mapping &bull; Automated Triage</div>
      </div>
      <div class="subtitle">Generated: {escape(generated_at)}</div>
    </header>

    <section class="kpi-grid">
      <div class="kpi"><div class="kpi-val">{total_events}</div><div class="kpi-lbl">Events Parsed (SSH: {ssh_events}, Web: {web_events})</div></div>
      <div class="kpi"><div class="kpi-val">{len(alerts)}</div><div class="kpi-lbl">Rule Alerts Triggered</div></div>
      <div class="kpi"><div class="kpi-val">{len(incidents)}</div><div class="kpi-lbl">Correlated Incidents</div></div>
      <div class="kpi"><div class="kpi-val" style="color:var(--critical);">{sev_counts.get('CRITICAL', 0)}</div><div class="kpi-lbl">Critical Escalations</div></div>
      <div class="kpi"><div class="kpi-val">{skipped_lines}</div><div class="kpi-lbl">Non-Matching / Noise Lines</div></div>
    </section>

    <section class="split-grid">
      <div class="panel">
        <h2>Incident Severity Breakdown</h2>
        {sev_bars_html}
      </div>
      <div class="panel">
        <h2>MITRE ATT&amp;CK Techniques Observed</h2>
        {mitre_pills_html}
      </div>
    </section>

    <section class="toolbar">
      <input type="text" id="searchInput" placeholder="Filter by IP address, rule title, or MITRE ID..." oninput="filterIncidents()" />
      <select id="sevFilter" onchange="filterIncidents()">
        <option value="ALL">All Severities</option>
        <option value="CRITICAL">CRITICAL</option>
        <option value="HIGH">HIGH</option>
        <option value="MEDIUM">MEDIUM</option>
        <option value="LOW">LOW</option>
      </select>
    </section>

    <section id="incidentList">
      {incident_cards_html}
    </section>
  </div>

  <script>
    function filterIncidents() {{
      const query = document.getElementById('searchInput').value.toLowerCase();
      const sev = document.getElementById('sevFilter').value;
      document.querySelectorAll('.incident-card').forEach(card => {{
        const matchesText = card.dataset.search.includes(query);
        const matchesSev = sev === 'ALL' || card.dataset.severity === sev;
        card.style.display = (matchesText && matchesSev) ? 'block' : 'none';
      }});
    }}
  </script>
</body>
</html>
"""
    path.write_text(html_doc, encoding="utf-8")
