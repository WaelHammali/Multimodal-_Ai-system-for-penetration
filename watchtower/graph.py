"""
LangGraph orchestration for the 5-Agent Architecture.

Topology:
  Planner ──▶ Worker ──▶ Cleaner ──▶ Analyst ──▶ Validator ──┐
     ▲                                                         │
     │      ┌───────────────────┬───────────────────┬──────────┘
     │      ▼                   ▼                   ▼          ▼
     │  (confirmed)     (false_positive)     (inconclusive) (error)
     │      │                   │                   │          │
     │      ▼                   ▼                   ▼          │
     └── Reporter            Discard            Analyst        │
            │                   │                              │
            └───────────────────┴──────────────────────────────┘
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List
from langgraph.graph import StateGraph, END

from watchtower.core.state import AgentState
from watchtower.cleaner import CleanerAgent
from watchtower.memory import MemoryAgent
from watchtower.validator import ValidatorAgent, VerificationStatus
from watchtower.agents.planner import planner_node
from watchtower.agents.worker import worker_node
from watchtower.agents.analyst import analyst_node
from watchtower.core.config import config

logger = logging.getLogger(__name__)


def cleaner_node(state: AgentState) -> dict:
    """
    Cleaner node: Cleans and structures raw observation data from the Worker.
    """
    cleaner: CleanerAgent = state.get("cleaner_agent") or CleanerAgent()
    memory: MemoryAgent = state.get("memory_agent")
    observations = state.get("observations", [])
    session_id = state.get("session_id", "")
    target = (state.get("scope_targets") or ["unknown"])[0]

    if not observations:
        return {"clean_result": {}}

    latest_obs = observations[-1]
    tool = latest_obs.get("tool", "unknown")
    raw_output = latest_obs.get("output", "")
    command = f"{tool} {target}"

    clean_result = cleaner.clean(
        command=command,
        tool=tool,
        raw_output=raw_output,
        target=target,
        exit_code=0,
        duration=0.0,
    )

    if memory:
        memory.add_cleaned_command(
            command=command,
            tool=tool,
            target=target,
            exit_code=0,
            duration=0.0,
            clean_result=clean_result,
            session_id=session_id,
        )

    return {
        "clean_result": clean_result,
        "messages": [f"Cleaner: Processed {tool} output into structured format."],
    }


def validator_graph_node(state: AgentState) -> dict:
    """
    Validator node: Independently verifies findings from Analyst.
    """
    validator: ValidatorAgent = state.get("validator_agent") or ValidatorAgent(
        confidence_threshold=getattr(config, "validator_confidence_threshold", 70)
    )
    memory: MemoryAgent = state.get("memory_agent")
    session_id = state.get("session_id", "")
    findings = state.get("findings", [])

    already_validated = {f.get("title") for f in state.get("validated_findings", [])}
    already_rejected = {f.get("title") for f in state.get("rejected_findings", [])}
    pending = [f for f in findings if f.get("title") not in (already_validated | already_rejected)]

    if not pending:
        return {"validation_status": "confirmed"}

    validation_results = validator.validate_batch(pending)

    confirmed: List[Dict[str, Any]] = []
    rejected: List[Dict[str, Any]] = []
    inconclusive: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for f, res in zip(pending, validation_results):
        enriched = {
            **f,
            "status": res.status.value,
            "confidence": res.confidence_score,
            "evidence": res.evidence,
            "remediation": res.remediation_note,
        }

        if memory:
            memory.update_finding_validation(
                finding_id=res.finding_id,
                validated=(res.status == VerificationStatus.CONFIRMED),
                confidence=res.confidence_score,
                evidence=res.evidence,
                remediation=res.remediation_note or "",
            )

        if res.status == VerificationStatus.CONFIRMED:
            confirmed.append(enriched)
        elif res.status == VerificationStatus.FALSE_POSITIVE:
            rejected.append(enriched)
        elif res.status == VerificationStatus.INCONCLUSIVE:
            inconclusive.append(enriched)
        else:
            errors.append(enriched)

    # Determine dominant transition branch
    if errors:
        branch = "error"
    elif inconclusive and not confirmed:
        branch = "inconclusive"
    elif confirmed:
        branch = "confirmed"
    else:
        branch = "false_positive"

    return {
        "validated_findings": confirmed,
        "rejected_findings": rejected,
        "validation_status": branch,
        "messages": [
            f"Validator: {len(confirmed)} confirmed, {len(rejected)} rejected, "
            f"{len(inconclusive)} inconclusive, {len(errors)} errors."
        ],
    }


def reporter_node(state: AgentState) -> dict:
    """Reporter node: Aggregates validated findings for reporting."""
    validated = state.get("validated_findings", [])
    summary = f"Reporter: Finalized {len(validated)} validated security finding(s)."
    return {
        "validation_summary": summary,
        "messages": [summary],
    }


def discard_node(state: AgentState) -> dict:
    """Discard node: Tracks and logs rejected findings / false positives."""
    rejected = state.get("rejected_findings", [])
    return {
        "messages": [f"Discard: Suppressed {len(rejected)} false positive(s)."],
    }


def _planner_router(state: AgentState) -> str:
    """Route after Planner."""
    iteration = state.get("iteration_count", 0)
    if iteration >= getattr(config, "max_iterations", 25):
        logger.warning("Max iterations (%d) reached.", config.max_iterations)
        return END

    if state.get("is_finished"):
        return END

    return "worker"


def _validator_router(state: AgentState) -> str:
    """
    Conditional edge from Validator:
      confirmed → reporter
      false_positive → discard
      inconclusive → analyst (re-analyze)
      error → planner (re-plan)
    """
    status = state.get("validation_status", "confirmed")
    if status == "confirmed":
        return "reporter"
    elif status == "false_positive":
        return "discard"
    elif status == "inconclusive":
        return "analyst"
    elif status == "error":
        return "planner"
    return "reporter"


def create_agent_graph():
    """
    Build and compile the 5-Agent LangGraph state machine.
    """
    graph = StateGraph(AgentState)

    # Add nodes
    graph.add_node("planner", planner_node)
    graph.add_node("worker", worker_node)
    graph.add_node("cleaner", cleaner_node)
    graph.add_node("analyst", analyst_node)
    graph.add_node("validator", validator_graph_node)
    graph.add_node("reporter", reporter_node)
    graph.add_node("discard", discard_node)

    # Set entry point
    graph.set_entry_point("planner")

    # Conditional planner routing
    graph.add_conditional_edges("planner", _planner_router)

    # Worker -> Cleaner -> Analyst -> Validator pipeline
    graph.add_edge("worker", "cleaner")
    graph.add_edge("cleaner", "analyst")
    graph.add_edge("analyst", "validator")

    # Conditional validator routing
    graph.add_conditional_edges(
        "validator",
        _validator_router,
        {
            "reporter": "reporter",
            "discard": "discard",
            "analyst": "analyst",
            "planner": "planner",
        },
    )

    # Loop back to planner
    graph.add_edge("reporter", "planner")
    graph.add_edge("discard", "planner")

    return graph.compile()
