"""
LangGraph orchestration for the 6-Agent Architecture.

Topology:
  Planner ──▶ Worker ──▶ Cleaner ──▶ Analyst ──┐
     ▲                                          │
     │                           (recon tool?)  │
     │                                          ├──▶ Logic Analysis ──┐
     │                                          │                     │
     │                                          └──────────────────── ▼
     │                                                          Validator ──┐
     │      ┌──────────────────┬──────────────────┬─────────────────────────┘
     │      ▼                  ▼                  ▼                ▼
     │  (confirmed)    (false_positive)     (needs_retest)      (error)
     │      │                  │                  │                │
     │      ▼                  ▼                  ▼                │
     └── Reporter           Discard            Planner ────────────┘
            │                  │
            └──────────────────┴──▶ Planner (loop)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Set
from langgraph.graph import StateGraph, END

from watchtower.core.state import AgentState
from watchtower.cleaner import CleanerAgent
from watchtower.memory import MemoryAgent
from watchtower.agents.planner import planner_node
from watchtower.agents.worker import worker_node
from watchtower.agents.analyst import analyst_node
from watchtower.agents.validator import validator_node          # ← real validator
from watchtower.agents.logic_analysis import logic_analysis_node  # ← IDOR analysis
from watchtower.core.config import config

logger = logging.getLogger(__name__)

# Tools that trigger the IDOR / business-logic analysis step
_LOGIC_ANALYSIS_TOOLS: Set[str] = {"httpx", "kiterunner", "arjun", "gobuster", "ffuf"}


# ─────────────────────────────────────────────────────────────────────────────
# Cleaner node (lives here because it glues Worker ↔ MemoryAgent)
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# Reporter / Discard nodes
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# Conditional routers
# ─────────────────────────────────────────────────────────────────────────────

def _planner_router(state: AgentState) -> str:
    """Route after Planner."""
    iteration = state.get("iteration_count", 0)
    if iteration >= getattr(config, "max_iterations", 25):
        logger.warning("Max iterations (%d) reached.", config.max_iterations)
        return END

    if state.get("is_finished"):
        return END

    return "worker"


def _analyst_router(state: AgentState) -> str:
    """
    After Analyst: run Logic Analysis when the last tool was a recon tool
    that commonly exposes IDOR/business-logic endpoints; otherwise go
    directly to the Validator.
    """
    observations = state.get("observations", [])
    if observations:
        last_tool = observations[-1].get("tool", "")
        if last_tool in _LOGIC_ANALYSIS_TOOLS:
            logger.debug("Graph: routing Analyst → Logic Analysis (tool=%s)", last_tool)
            return "logic_analysis"
    return "validator"


def _validator_router(state: AgentState) -> str:
    """
    Conditional edge from Validator.

    The agents/validator.py node returns `retest_requests` when a finding
    needs a follow-up scan.  Derive routing from the actual state lists so
    we don't depend on a `validation_status` string being set correctly.

      confirmed    → reporter
      needs_retest → planner  (schedule follow-up)
      false_positive → discard
      error / nothing new → reporter (safe default)
    """
    validated = state.get("validated_findings", [])
    rejected = state.get("rejected_findings", [])
    retests = state.get("retest_requests", [])
    errors = state.get("error_log", [])

    # Explicit status string (backward-compat with tests)
    status = state.get("validation_status", "")
    if status == "confirmed":
        return "reporter"
    if status == "false_positive":
        return "discard"
    if status in ("inconclusive", "error"):
        return "planner"

    # Derive from state lists
    if retests:
        return "planner"
    if validated:
        return "reporter"
    if rejected and not validated:
        return "discard"
    return "reporter"


# ─────────────────────────────────────────────────────────────────────────────
# Graph factory
# ─────────────────────────────────────────────────────────────────────────────

def create_agent_graph():
    """
    Build and compile the 6-Agent LangGraph state machine.

    Agents:
      planner, worker, cleaner, analyst, logic_analysis, validator,
      reporter, discard
    """
    graph = StateGraph(AgentState)

    # ── Add nodes ────────────────────────────────────────────────────
    graph.add_node("planner", planner_node)
    graph.add_node("worker", worker_node)
    graph.add_node("cleaner", cleaner_node)
    graph.add_node("analyst", analyst_node)
    graph.add_node("logic_analysis", logic_analysis_node)   # IDOR / business logic
    graph.add_node("validator", validator_node)              # full LLM validator
    graph.add_node("reporter", reporter_node)
    graph.add_node("discard", discard_node)

    # ── Entry point ──────────────────────────────────────────────────
    graph.set_entry_point("planner")

    # ── Edges ────────────────────────────────────────────────────────
    # Planner routing (finish or continue)
    graph.add_conditional_edges("planner", _planner_router)

    # Core pipeline
    graph.add_edge("worker", "cleaner")
    graph.add_edge("cleaner", "analyst")

    # Analyst → logic_analysis (recon tools) OR directly to validator
    graph.add_conditional_edges(
        "analyst",
        _analyst_router,
        {"logic_analysis": "logic_analysis", "validator": "validator"},
    )

    # Logic analysis always feeds into the validator
    graph.add_edge("logic_analysis", "validator")

    # Validator conditional routing
    graph.add_conditional_edges(
        "validator",
        _validator_router,
        {
            "reporter": "reporter",
            "discard": "discard",
            "planner": "planner",
        },
    )

    # Loop back to planner after reporting / discarding
    graph.add_edge("reporter", "planner")
    graph.add_edge("discard", "planner")

    return graph.compile()
