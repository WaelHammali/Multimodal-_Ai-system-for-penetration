"""
Analyst Agent — Extracts security findings from raw tool observations.

Enhancements:
  - Stores confirmed findings in the MemoryAgent for cross-session recall.
  - Adds a reasoning step to memory for each analysis pass.
"""
import json
import logging
from datetime import datetime, timezone
from typing import List

from pydantic import BaseModel, Field
from langchain_core.messages import HumanMessage
from langchain_core.output_parsers import PydanticOutputParser

from watchtower.core.state import AgentState
from watchtower.agents.planner import get_llm
from watchtower.core.llm_utils import invoke_with_retry

logger = logging.getLogger(__name__)


class Finding(BaseModel):
    title: str = Field(description="A concise title for the discovered vulnerability or configuration issue.")
    severity: str = Field(description="Critical, High, Medium, Low, or Info.")
    description: str = Field(description="Detailed explanation of the issue.")
    evidence: str = Field(description="The exact snippet of text from the output proving the finding.")


class AnalystOutput(BaseModel):
    findings: List[Finding] = Field(description="A list of confirmed, legitimate findings. Omit false positives.")


def analyst_node(state: AgentState) -> dict:
    """
    Analyse the latest observation and extract structured findings.

    After extraction, each finding is stored in the ``MemoryAgent`` and a
    reasoning step is logged so the Planner can recall prior analysis.
    """
    observations = state.get("observations", [])
    if not observations:
        return {"findings": []}

    memory = state.get("memory_agent")
    session_id = state.get("session_id", "")

    new_obs = observations[-1] if isinstance(observations, list) and observations else {}

    # Prefer the Cleaner's structured result — it has already stripped noise and
    # extracted key fields.  Fall back to raw output only when clean_result is absent.
    clean_result: dict = new_obs.get("clean_result", {})
    clean_summary = clean_result.get("clean_summary", "")
    structured_output = clean_result.get("structured_output", "")
    open_ports = clean_result.get("open_ports", "")
    vulnerabilities = clean_result.get("vulnerabilities", "")
    directories = clean_result.get("directories", "")

    if clean_result and (clean_summary or structured_output):
        analysis_input = (
            f"Cleaner Structured Output (primary input — noise already removed):\n"
            f"  Summary    : {clean_summary}\n"
            f"  Open Ports : {open_ports}\n"
            f"  Vulns Found: {vulnerabilities}\n"
            f"  Directories: {directories}\n"
            f"  Structured : {structured_output}\n"
        )
    else:
        raw = new_obs.get("output", "") or ""
        analysis_input = (
            f"Raw Output (fallback — Cleaner produced no structured result):\n"
            f"{raw[:3000]}"
            + ("\n...[TRUNCATED]" if len(raw) > 3000 else "")
        )

    parser = PydanticOutputParser(pydantic_object=AnalystOutput)

    prompt = f"""
You are an expert Security Analyst. Review the output from the automated security tool below.
Your goal is to identify genuine security vulnerabilities or interesting misconfigurations.

Tool Execution Details:
  Target  : {new_obs.get('target', 'Unknown')}
  Tool    : {new_obs.get('tool', 'Unknown')}

{analysis_input}

Extract any TRUE findings as structured data. If the output shows only normal behaviour, return an empty list.
NEVER fabricate findings not supported by the data above.
{parser.get_format_instructions()}
"""

    try:
        llm = get_llm()
        chain = llm | parser
        result = invoke_with_retry(chain, [HumanMessage(content=prompt)])
        new_findings = [f.model_dump() for f in result.findings]

        # ── Persist findings in MemoryAgent ───────────────────────────
        if memory and new_findings:
            for finding in new_findings:
                try:
                    memory.add_finding({
                        **finding,
                        "finding_type": finding.get("severity", "unknown"),
                        "session_id": session_id,
                        "target": new_obs.get("target", ""),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                except Exception as mem_exc:
                    logger.warning("Analyst: failed to store finding in memory: %s", mem_exc)

            try:
                memory.add_memory(
                    agent="Analyst",
                    action=f"Extracted {len(new_findings)} finding(s) from {new_obs.get('tool', '?')}",
                    details={
                        "count": len(new_findings),
                        "tool": new_obs.get("tool"),
                        "target": new_obs.get("target"),
                        "titles": [f.get("title") for f in new_findings],
                    },
                    session_id=session_id,
                )
            except Exception as mem_exc:
                logger.warning("Analyst: failed to log memory step: %s", mem_exc)

        logger.info(
            "Analyst: extracted %d finding(s) from tool '%s'",
            len(new_findings), new_obs.get("tool", "?"),
        )
        return {"findings": new_findings}

    except Exception as e:
        logger.error("Analyst execution error: %s", e)
        return {"findings": [], "error_log": [f"Analyst error: {e}"]}

