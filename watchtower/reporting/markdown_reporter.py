"""
Markdown Report Generator for Watchtower.

Produces a GitHub-Flavored Markdown report with:
  - Executive summary with severity table
  - Mermaid diagram of the scan flow
  - Detailed finding sections with evidence and remediation
  - Validator summary
"""
import json
import logging
from typing import List, Optional
from datetime import datetime

from watchtower.core.memory import MemoryStore

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
    "unknown": "⚫",
}


def generate_markdown_report(
    db_path: str,
    output_path: str,
    session_id: Optional[str] = None,
    validation_summary: str = "",
) -> None:
    """
    Generate a GFM Markdown penetration test report.
    """
    logger.info("Generating Markdown report from database: %s", db_path)
    memory = MemoryStore(db_path, vector_enabled=False)
    findings = memory.get_all_findings()
    observations = memory.get_all_observations()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Severity counts ──────────────────────────────────────────────
    severity_counts: dict = {}
    parsed_findings: list = []

    for target, vulnerability, details_json in findings:
        try:
            details = json.loads(details_json)
        except (json.JSONDecodeError, TypeError):
            details = {}
        sev = details.get("severity", "Unknown").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        parsed_findings.append((target, vulnerability, details, sev))

    total = len(findings)
    critical = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)

    # ── Build document ───────────────────────────────────────────────
    lines: List[str] = []

    # Header
    lines.append("# 🏰 Watchtower AI — Penetration Test Report\n")
    lines.append(f"> Generated on **{timestamp}**\n")
    lines.append("---\n")

    # Executive Summary
    lines.append("## Executive Summary\n")
    lines.append(
        f"The automated security assessment discovered **{total}** findings "
        f"({critical} Critical, {high} High).\n"
    )

    # Severity table
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["critical", "high", "medium", "low", "info"]:
        emoji = SEVERITY_EMOJI.get(sev, "⚫")
        count = severity_counts.get(sev, 0)
        lines.append(f"| {emoji} {sev.capitalize()} | {count} |")
    lines.append("")

    # Scan flow diagram
    lines.append("## Scan Flow\n")
    lines.append("```mermaid")
    lines.append("graph LR")
    lines.append('    A["Planner"] --> B["Worker"]')
    lines.append('    B --> C["Analyst"]')
    lines.append('    C --> D["Validator"]')
    lines.append('    D --> E["Logic Analysis"]')
    lines.append('    E --> A')
    lines.append('    A -->|"is_finished"| F["Report"]')
    lines.append("```\n")

    # Validation summary
    if validation_summary:
        lines.append("## Validation Summary\n")
        lines.append(f"{validation_summary}\n")

    # Findings
    lines.append("---\n")
    lines.append("## Findings\n")

    if not parsed_findings:
        lines.append("*No findings to report.*\n")
    else:
        for idx, (target, vulnerability, details, sev) in enumerate(parsed_findings, 1):
            emoji = SEVERITY_EMOJI.get(sev, "⚫")
            cvss = details.get("cvss_score", "N/A")
            description = details.get("description", "No description.")
            evidence = details.get("evidence", "")
            remediation = details.get("remediation", "")
            reasoning = details.get("reasoning", "")

            lines.append(f"### {emoji} Finding #{idx}: {vulnerability}\n")
            lines.append(f"- **Severity:** {sev.capitalize()}")
            if cvss != "N/A":
                lines.append(f"- **CVSS Score:** {cvss}")
            lines.append(f"- **Target:** `{target}`\n")

            lines.append("**Description:**\n")
            lines.append(f"{description}\n")

            if reasoning:
                lines.append("**Validator Reasoning:**\n")
                lines.append(f"{reasoning}\n")

            if evidence:
                lines.append("**Evidence:**\n")
                lines.append("```")
                lines.append(evidence)
                lines.append("```\n")

            if remediation:
                lines.append("**Remediation:**\n")
                lines.append(f"{remediation}\n")

            lines.append("---\n")

    # Tool observations summary
    if observations:
        lines.append("## Tool Execution Log\n")
        lines.append("| Tool | Output (truncated) |")
        lines.append("|------|--------------------|")
        for tool, output in observations[:20]:
            truncated = (output or "")[:100].replace("|", "\\|").replace("\n", " ")
            lines.append(f"| `{tool}` | {truncated} |")
        if len(observations) > 20:
            lines.append(f"\n*... and {len(observations) - 20} more observations.*\n")
        lines.append("")

    # Footer
    lines.append("---\n")
    lines.append(
        "*Report generated by [Watchtower AI](https://github.com/fzn0x/watchtower) "
        "— Automated Penetration Testing Framework.*\n"
    )
    lines.append("> ⚠️ Always manually verify automated findings before taking action.\n")

    # ── Write ────────────────────────────────────────────────────────
    if not output_path.endswith(".md"):
        output_path += ".md"

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    logger.info("Markdown report exported to: %s", output_path)
