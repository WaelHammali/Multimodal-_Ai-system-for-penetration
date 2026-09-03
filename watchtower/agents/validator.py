"""
Validator Agent — cross-examines Analyst findings to eliminate false positives.

This is the 5th node in the LangGraph.  For every *new* finding produced by
the Analyst, the Validator:

  1. Re-reads the raw observation evidence.
  2. Sends a skeptical LLM prompt that asks "is this really a vulnerability?"
  3. Assigns a verdict: ``confirmed``, ``rejected``, or ``needs_retest``.
  4. Estimates a CVSS 3.1 base score and suggests remediation.

Confirmed findings go into ``validated_findings``; rejected ones into
``rejected_findings``; retest requests go into ``retest_requests`` so the
Planner can schedule follow-up scans.
"""
import json
import logging
from typing import List, Dict, Any, Optional

from pydantic import BaseModel, Field
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.output_parsers import PydanticOutputParser

from watchtower.core.state import AgentState
from watchtower.agents.planner import get_llm

logger = logging.getLogger(__name__)


# ── Pydantic schemas ────────────────────────────────────────────────────────

class ValidatedFinding(BaseModel):
    """A single finding after validation."""
    original_title: str = Field(description="The title of the original finding being validated.")
    verdict: str = Field(
        description="One of: 'confirmed', 'rejected', 'needs_retest'."
    )
    confidence: int = Field(
        description="Validator confidence 1-100 that the verdict is correct.",
        ge=1,
        le=100,
    )
    cvss_score: float = Field(
        description="Estimated CVSS 3.1 base score (0.0–10.0). Use 0.0 for Info-level or rejected.",
        ge=0.0,
        le=10.0,
    )
    severity: str = Field(
        description="Severity after validation: Critical, High, Medium, Low, or Info."
    )
    reasoning: str = Field(
        description="Why the finding was confirmed or rejected. Reference specific evidence."
    )
    remediation: str = Field(
        description="Suggested remediation steps if confirmed. 'N/A' if rejected."
    )


class ValidatorOutput(BaseModel):
    """Output from the Validator agent for a batch of findings."""
    validated: List[ValidatedFinding] = Field(
        description="List of validation results — one per input finding."
    )
    summary: str = Field(
        description="Executive summary of the validation pass."
    )


# ── System prompt ───────────────────────────────────────────────────────────

VALIDATOR_SYSTEM_PROMPT = """\
You are a Senior Penetration Testing Validator with 15+ years of experience.

Your job is to independently verify findings produced by an automated analyst.
You must be SKEPTICAL — many automated scanners produce false positives.

For each finding:
1. Cross-reference the claimed vulnerability against the raw tool output evidence.
2. Check if the evidence genuinely proves the issue, or if it is an artifact of
   normal behavior, informational output, or scanner noise.
3. Assign a verdict:
   - "confirmed"   — the evidence clearly supports the vulnerability.
   - "rejected"     — the evidence does NOT support the claim; this is a false positive.
   - "needs_retest" — the evidence is ambiguous; a follow-up scan with different
     parameters is required.
4. Estimate a CVSS 3.1 base score for confirmed findings.
5. Provide concrete remediation advice for confirmed findings.

Rules:
- NEVER confirm a finding without specific evidence from the raw output.
- If the raw output is empty or generic (e.g. only HTTP 200 OK), reject the finding.
- Be precise in your reasoning — quote exact snippets from the evidence.
- Output ONLY valid JSON matching the requested schema.\
"""


# ── Node ────────────────────────────────────────────────────────────────────

def validator_node(state: AgentState) -> dict:
    """
    Validate the latest batch of Analyst findings.

    Reads ``findings`` and ``observations`` from state.  Only processes
    findings that haven't already been validated (i.e. not in
    ``validated_findings`` or ``rejected_findings``).
    """
    from watchtower.core.config import config

    # Skip if validator is disabled
    if not config.validator_enabled:
        logger.info("Validator disabled — passing all findings through as confirmed")
        new_findings = state.get("findings", [])
        return {
            "validated_findings": new_findings,
            "validation_summary": "Validator disabled — all findings passed through.",
        }

    all_findings = state.get("findings", [])
    already_validated = {
        f.get("title", "") for f in state.get("validated_findings", [])
    }
    already_rejected = {
        f.get("title", "") for f in state.get("rejected_findings", [])
    }
    already_processed = already_validated | already_rejected

    # Only validate new findings
    new_findings = [
        f for f in all_findings
        if f.get("title", "") not in already_processed
    ]

    if not new_findings:
        return {"messages": ["Validator: No new findings to validate."]}

    # Gather recent observations for evidence cross-reference
    observations = state.get("observations", [])
    recent_obs = observations[-5:] if observations else []
    obs_text = "\n\n".join(
        f"[{o.get('tool', '?')}] {o.get('output', '')[:1000]}"
        for o in recent_obs
    )

    parser = PydanticOutputParser(pydantic_object=ValidatorOutput)

    user_prompt = f"""\
Validate the following {len(new_findings)} finding(s). For each one, cross-reference
against the raw tool observations below and assign a verdict.

--- FINDINGS TO VALIDATE ---
{json.dumps(new_findings, indent=2)}

--- RAW TOOL OBSERVATIONS (recent) ---
{obs_text}

{parser.get_format_instructions()}
"""

    messages = [
        SystemMessage(content=VALIDATOR_SYSTEM_PROMPT),
        HumanMessage(content=user_prompt),
    ]

    try:
        llm = get_llm()
        chain = llm | parser
        result: ValidatorOutput = chain.invoke(messages)

        confirmed = []
        rejected = []
        retests = []

        for vf in result.validated:
            # Find the original finding dict to enrich it
            original = next(
                (f for f in new_findings if f.get("title", "") == vf.original_title),
                {},
            )
            enriched = {
                **original,
                "title": vf.original_title,
                "verdict": vf.verdict,
                "validator_confidence": vf.confidence,
                "cvss_score": vf.cvss_score,
                "severity": vf.severity,
                "reasoning": vf.reasoning,
                "remediation": vf.remediation,
            }

            if vf.verdict == "confirmed":
                confirmed.append(enriched)
            elif vf.verdict == "rejected":
                rejected.append(enriched)
            elif vf.verdict == "needs_retest":
                retests.append(enriched)

        logger.info(
            "Validator: %d confirmed, %d rejected, %d need retest",
            len(confirmed), len(rejected), len(retests),
        )

        return {
            "validated_findings": confirmed,
            "rejected_findings": rejected,
            "retest_requests": retests,
            "validation_summary": result.summary,
            "messages": [
                f"Validator: {len(confirmed)} confirmed, "
                f"{len(rejected)} rejected, {len(retests)} need retest."
            ],
        }

    except Exception as exc:
        logger.error("Validator error: %s", exc)
        # On failure, pass findings through as unvalidated rather than losing them
        return {
            "validated_findings": new_findings,
            "validation_summary": f"Validation failed ({exc}); findings passed through unvalidated.",
            "error_log": [f"Validator error: {exc}"],
        }
