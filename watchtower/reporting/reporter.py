"""
Enhanced PDF Report Generator for Watchtower.

Improvements over the original:
  - Severity breakdown summary with counts
  - CVSS score display per finding
  - Remediation section per finding
  - Validator reasoning section
  - Better formatting and page management
"""
import json
import logging
from typing import Optional
from datetime import datetime

from fpdf import FPDF
from watchtower.core.memory import MemoryStore

logger = logging.getLogger(__name__)

# ── Severity colours (RGB tuples) ────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": (231, 76, 60),
    "high": (230, 126, 34),
    "medium": (241, 196, 15),
    "low": (52, 152, 219),
    "info": (149, 165, 166),
}


class PentestReport(FPDF):
    """Custom PDF class with Watchtower branding."""

    def header(self):
        self.set_font("helvetica", "B", 16)
        self.set_text_color(44, 62, 80)
        self.cell(0, 10, "Watchtower AI — Penetration Test Report", border=False, align="C")
        self.ln(6)
        self.set_font("helvetica", "I", 9)
        self.set_text_color(128, 128, 128)
        self.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", align="C")
        self.ln(14)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}} — Watchtower AI", align="C")

    def chapter_title(self, title: str):
        self.set_font("helvetica", "B", 13)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 10, f"  {title}", border=False, fill=True)
        self.ln(12)

    def chapter_body(self, text: str):
        self.set_font("helvetica", "", 10)
        self.set_text_color(50, 50, 50)
        self.multi_cell(0, 6, text)
        self.ln(6)

    def add_finding(
        self,
        finding_num: int,
        target: str,
        title: str,
        severity: str,
        description: str,
        evidence: str = "",
        cvss_score: float = 0.0,
        remediation: str = "",
        reasoning: str = "",
    ):
        # Check if we need a new page (rough estimate)
        if self.get_y() > 230:
            self.add_page()

        color = SEVERITY_COLORS.get(severity.lower(), (128, 128, 128))

        # Title
        self.set_font("helvetica", "B", 13)
        self.set_text_color(30, 30, 30)
        self.cell(0, 10, f"Finding {finding_num}: {title}", ln=True)

        # Severity + CVSS
        self.set_font("helvetica", "B", 11)
        self.set_text_color(*color)
        severity_text = f"Severity: {severity.upper()}"
        if cvss_score > 0:
            severity_text += f"   |   CVSS: {cvss_score:.1f}"
        self.cell(0, 8, severity_text, ln=True)

        # Target
        self.set_font("helvetica", "", 10)
        self.set_text_color(80, 80, 80)
        self.cell(0, 7, f"Target: {target}", ln=True)
        self.ln(3)

        # Description
        self.set_font("helvetica", "B", 10)
        self.set_text_color(30, 30, 30)
        self.cell(0, 6, "Description:", ln=True)
        self.set_font("helvetica", "", 10)
        self.set_text_color(50, 50, 50)
        self.multi_cell(0, 5, description)
        self.ln(2)

        # Validator reasoning
        if reasoning:
            self.set_font("helvetica", "B", 10)
            self.set_text_color(30, 30, 30)
            self.cell(0, 6, "Validator Analysis:", ln=True)
            self.set_font("helvetica", "I", 9)
            self.set_text_color(80, 80, 80)
            self.multi_cell(0, 5, reasoning)
            self.ln(2)

        # Evidence
        if evidence:
            self.set_font("helvetica", "B", 10)
            self.set_text_color(30, 30, 30)
            self.cell(0, 6, "Evidence / Proof of Concept:", ln=True)
            self.set_font("courier", "", 8)
            self.set_fill_color(245, 245, 245)
            evidence_clean = str(evidence).replace("```", "")
            self.multi_cell(0, 4, evidence_clean, fill=True)
            self.ln(2)

        # Remediation
        if remediation:
            self.set_font("helvetica", "B", 10)
            self.set_text_color(30, 30, 30)
            self.cell(0, 6, "Remediation:", ln=True)
            self.set_font("helvetica", "", 10)
            self.set_text_color(34, 139, 34)  # Green text for fixes
            self.multi_cell(0, 5, remediation)

        self.ln(10)
        # Separator line
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)


def generate_pdf_report(
    db_path: str,
    output_path: str,
    session_id: Optional[str] = None,
    validation_summary: str = "",
) -> None:
    """Generate an enhanced PDF report from the memory database."""
    logger.info("Generating PDF report from database: %s", db_path)
    memory = MemoryStore(db_path, vector_enabled=False)
    findings = memory.get_all_findings()

    if not findings:
        logger.warning("No findings present in the local database to generate a report.")
        print(f"ERROR: No pentest findings were found in {db_path}.")
        return

    pdf = PentestReport()
    pdf.alias_nb_pages()
    pdf.add_page()

    # ── Executive Summary ────────────────────────────────────────────
    severity_counts: dict = {}
    for _, _, details_json in findings:
        try:
            details = json.loads(details_json)
        except (json.JSONDecodeError, TypeError):
            details = {}
        sev = details.get("severity", "Unknown").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    pdf.chapter_title("Executive Summary")
    summary_text = (
        f"This automated security assessment utilised the Watchtower AI framework.\n"
        f"The assessment discovered {len(findings)} total finding(s):\n\n"
    )
    for sev_name in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts.get(sev_name, 0)
        if count > 0:
            summary_text += f"  • {sev_name.capitalize()}: {count}\n"
    pdf.chapter_body(summary_text)

    # Validation summary
    if validation_summary:
        pdf.chapter_title("Validation Summary")
        pdf.chapter_body(validation_summary)

    # ── Findings ─────────────────────────────────────────────────────
    pdf.chapter_title("Detailed Findings")

    finding_num = 1
    for target, vulnerability, details_json in findings:
        try:
            details = json.loads(details_json)
        except (json.JSONDecodeError, TypeError):
            details = {}

        pdf.add_finding(
            finding_num=finding_num,
            target=target,
            title=vulnerability,
            severity=details.get("severity", "Unknown"),
            description=details.get("description", "No description provided."),
            evidence=details.get("evidence", ""),
            cvss_score=float(details.get("cvss_score", 0)),
            remediation=details.get("remediation", ""),
            reasoning=details.get("reasoning", ""),
        )
        finding_num += 1

    # ── Output ───────────────────────────────────────────────────────
    if not output_path.endswith(".pdf"):
        output_path += ".pdf"

    pdf.output(output_path)
    logger.info("PDF report exported to: %s", output_path)
