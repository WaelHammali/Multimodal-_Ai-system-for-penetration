"""
HTML Report Generator for Watchtower.

Produces a self-contained, single-file HTML report with:
  - Executive summary with severity breakdown
  - SVG severity distribution chart
  - Finding cards with severity badges, CVSS scores, evidence, and remediation
  - Scan metadata and timeline
  - Responsive layout with dark/light mode support
  - No external dependencies — all CSS/JS is inlined
"""
import json
import html
import logging
from typing import List, Tuple, Optional
from datetime import datetime

from watchtower.core.memory import MemoryStore

logger = logging.getLogger(__name__)

# ── Severity colors ──────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "#e74c3c",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#3498db",
    "info": "#95a5a6",
    "unknown": "#7f8c8d",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


# ── SVG chart helpers ────────────────────────────────────────────────────────

def _build_severity_donut(counts: dict) -> str:
    """Build an SVG donut chart from severity counts."""
    total = sum(counts.values())
    if total == 0:
        return '<p style="text-align:center;color:#888;">No findings to chart.</p>'

    segments = []
    cumulative = 0
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count == 0:
            continue
        pct = count / total
        start_angle = cumulative * 360
        end_angle = (cumulative + pct) * 360
        cumulative += pct

        large_arc = 1 if (end_angle - start_angle) > 180 else 0
        import math
        x1 = 50 + 40 * math.cos(math.radians(start_angle - 90))
        y1 = 50 + 40 * math.sin(math.radians(start_angle - 90))
        x2 = 50 + 40 * math.cos(math.radians(end_angle - 90))
        y2 = 50 + 40 * math.sin(math.radians(end_angle - 90))

        color = SEVERITY_COLORS.get(sev, "#7f8c8d")
        path = (
            f'<path d="M50,50 L{x1:.2f},{y1:.2f} '
            f'A40,40 0 {large_arc},1 {x2:.2f},{y2:.2f} Z" '
            f'fill="{color}" opacity="0.9">'
            f'<title>{sev.capitalize()}: {count}</title></path>'
        )
        segments.append(path)

    # Inner circle (donut hole)
    inner_circle = '<circle cx="50" cy="50" r="22" fill="var(--bg-primary)"/>'
    center_text = f'<text x="50" y="54" text-anchor="middle" font-size="12" font-weight="bold" fill="var(--text-primary)">{total}</text>'

    # Legend
    legend_items = []
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count == 0:
            continue
        color = SEVERITY_COLORS.get(sev, "#7f8c8d")
        legend_items.append(
            f'<span class="legend-item">'
            f'<span class="legend-dot" style="background:{color}"></span>'
            f'{sev.capitalize()} ({count})</span>'
        )

    return f"""
    <div class="chart-container">
        <svg viewBox="0 0 100 100" width="200" height="200">
            {''.join(segments)}
            {inner_circle}
            {center_text}
        </svg>
        <div class="chart-legend">{''.join(legend_items)}</div>
    </div>
    """


# ── Main generator ───────────────────────────────────────────────────────────

def generate_html_report(
    db_path: str,
    output_path: str,
    session_id: Optional[str] = None,
    validation_summary: str = "",
) -> None:
    """
    Generate a self-contained HTML penetration test report.

    Args:
        db_path: Path to the SQLite memory database.
        output_path: Where to write the .html file.
        session_id: Optional session to filter findings.
        validation_summary: Validator's executive summary text.
    """
    logger.info("Generating HTML report from database: %s", db_path)
    memory = MemoryStore(db_path, vector_enabled=False)
    findings = memory.get_all_findings()

    if not findings:
        logger.warning("No findings in database — HTML report will be empty.")

    # Count severities
    severity_counts: dict = {}
    finding_cards: list = []

    for idx, (target, vulnerability, details_json) in enumerate(findings, 1):
        try:
            details = json.loads(details_json)
        except (json.JSONDecodeError, TypeError):
            details = {}

        sev = details.get("severity", "Unknown").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        color = SEVERITY_COLORS.get(sev, "#7f8c8d")
        cvss = details.get("cvss_score", "N/A")
        description = html.escape(details.get("description", "No description."))
        evidence = html.escape(details.get("evidence", ""))
        remediation = html.escape(details.get("remediation", "N/A"))
        reasoning = html.escape(details.get("reasoning", ""))

        finding_cards.append(f"""
        <div class="finding-card" id="finding-{idx}">
            <div class="finding-header">
                <h3>Finding #{idx}: {html.escape(vulnerability)}</h3>
                <div class="badges">
                    <span class="severity-badge" style="background:{color}">
                        {sev.upper()}
                    </span>
                    {f'<span class="cvss-badge">CVSS {cvss}</span>' if cvss != "N/A" else ''}
                </div>
            </div>
            <div class="finding-meta">
                <span>🎯 Target: <code>{html.escape(target)}</code></span>
            </div>
            <div class="finding-body">
                <h4>Description</h4>
                <p>{description}</p>
                {'<h4>Validator Reasoning</h4><p>' + reasoning + '</p>' if reasoning else ''}
                {'<h4>Evidence</h4><pre class="evidence-block">' + evidence + '</pre>' if evidence else ''}
                {'<h4>Remediation</h4><p>' + remediation + '</p>' if remediation != 'N/A' else ''}
            </div>
        </div>
        """)

    chart_svg = _build_severity_donut(severity_counts)
    total = len(findings)
    critical_count = severity_counts.get("critical", 0)
    high_count = severity_counts.get("high", 0)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_content = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Watchtower Pentest Report</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --border: #334155;
            --accent: #3b82f6;
        }}
        [data-theme="light"] {{
            --bg-primary: #ffffff;
            --bg-secondary: #f8fafc;
            --bg-card: #ffffff;
            --text-primary: #1e293b;
            --text-secondary: #64748b;
            --border: #e2e8f0;
            --accent: #2563eb;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        header {{
            text-align: center;
            padding: 2rem 0;
            border-bottom: 2px solid var(--border);
            margin-bottom: 2rem;
        }}
        header h1 {{ font-size: 2rem; margin-bottom: 0.5rem; }}
        header .subtitle {{ color: var(--text-secondary); font-size: 0.95rem; }}
        .theme-toggle {{
            position: fixed; top: 1rem; right: 1rem;
            background: var(--bg-secondary); border: 1px solid var(--border);
            color: var(--text-primary); padding: 0.5rem 1rem;
            border-radius: 8px; cursor: pointer; font-size: 0.85rem;
        }}
        .summary-grid {{
            display: grid; grid-template-columns: 1fr 1fr; gap: 2rem;
            margin-bottom: 2rem;
        }}
        .summary-box {{
            background: var(--bg-card); border: 1px solid var(--border);
            border-radius: 12px; padding: 1.5rem;
        }}
        .summary-box h2 {{ font-size: 1.2rem; margin-bottom: 1rem; color: var(--accent); }}
        .stat-row {{ display: flex; justify-content: space-between; padding: 0.4rem 0; }}
        .stat-row .label {{ color: var(--text-secondary); }}
        .chart-container {{ text-align: center; }}
        .chart-legend {{ display: flex; flex-wrap: wrap; justify-content: center; gap: 1rem; margin-top: 1rem; }}
        .legend-item {{ display: flex; align-items: center; gap: 0.3rem; font-size: 0.85rem; color: var(--text-secondary); }}
        .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; }}
        .finding-card {{
            background: var(--bg-card); border: 1px solid var(--border);
            border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem;
            transition: border-color 0.2s;
        }}
        .finding-card:hover {{ border-color: var(--accent); }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 0.5rem; }}
        .finding-header h3 {{ font-size: 1.1rem; }}
        .badges {{ display: flex; gap: 0.5rem; }}
        .severity-badge {{
            color: #fff; padding: 0.2rem 0.7rem; border-radius: 6px;
            font-size: 0.75rem; font-weight: 700; text-transform: uppercase;
        }}
        .cvss-badge {{
            background: var(--bg-secondary); border: 1px solid var(--border);
            padding: 0.2rem 0.7rem; border-radius: 6px;
            font-size: 0.75rem; font-weight: 600;
        }}
        .finding-meta {{ color: var(--text-secondary); font-size: 0.85rem; margin: 0.75rem 0; }}
        .finding-meta code {{ background: var(--bg-secondary); padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.8rem; }}
        .finding-body h4 {{ margin: 1rem 0 0.4rem; font-size: 0.95rem; color: var(--accent); }}
        .finding-body p {{ color: var(--text-secondary); }}
        .evidence-block {{
            background: var(--bg-primary); border: 1px solid var(--border);
            border-radius: 8px; padding: 1rem; font-family: 'Courier New', monospace;
            font-size: 0.8rem; overflow-x: auto; white-space: pre-wrap;
            color: var(--text-secondary); margin-top: 0.3rem;
        }}
        .validation-summary {{
            background: var(--bg-card); border: 1px solid var(--border);
            border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem;
        }}
        .validation-summary h2 {{ color: var(--accent); margin-bottom: 0.5rem; }}
        footer {{ text-align: center; color: var(--text-secondary); padding: 2rem 0; font-size: 0.85rem; border-top: 1px solid var(--border); margin-top: 2rem; }}
        @media (max-width: 768px) {{ .summary-grid {{ grid-template-columns: 1fr; }} }}
    </style>
</head>
<body>
    <button class="theme-toggle" onclick="toggleTheme()">🌓 Toggle Theme</button>
    <div class="container">
        <header>
            <h1>🏰 Watchtower AI Pentest Report</h1>
            <p class="subtitle">Generated on {timestamp}</p>
        </header>

        <div class="summary-grid">
            <div class="summary-box">
                <h2>Executive Summary</h2>
                <div class="stat-row"><span class="label">Total Findings</span><strong>{total}</strong></div>
                <div class="stat-row"><span class="label">Critical</span><strong style="color:{SEVERITY_COLORS['critical']}">{critical_count}</strong></div>
                <div class="stat-row"><span class="label">High</span><strong style="color:{SEVERITY_COLORS['high']}">{high_count}</strong></div>
                <div class="stat-row"><span class="label">Medium</span><strong style="color:{SEVERITY_COLORS['medium']}">{severity_counts.get('medium', 0)}</strong></div>
                <div class="stat-row"><span class="label">Low</span><strong style="color:{SEVERITY_COLORS['low']}">{severity_counts.get('low', 0)}</strong></div>
                <div class="stat-row"><span class="label">Info</span><strong style="color:{SEVERITY_COLORS['info']}">{severity_counts.get('info', 0)}</strong></div>
            </div>
            <div class="summary-box">
                <h2>Severity Distribution</h2>
                {chart_svg}
            </div>
        </div>

        {'<div class="validation-summary"><h2>Validation Summary</h2><p>' + html.escape(validation_summary) + '</p></div>' if validation_summary else ''}

        <h2 style="margin-bottom:1rem;">📋 Findings</h2>
        {''.join(finding_cards) if finding_cards else '<p style="color:var(--text-secondary);">No findings to display.</p>'}

        <footer>
            <p>Report generated by Watchtower AI — Automated Penetration Testing Framework</p>
            <p>⚠️ Always manually verify automated findings before taking action.</p>
        </footer>
    </div>
    <script>
        function toggleTheme() {{
            const el = document.documentElement;
            el.dataset.theme = el.dataset.theme === 'dark' ? 'light' : 'dark';
        }}
    </script>
</body>
</html>"""

    if not output_path.endswith(".html"):
        output_path += ".html"

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    logger.info("HTML report exported to: %s", output_path)
