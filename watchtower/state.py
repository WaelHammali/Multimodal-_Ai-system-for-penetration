"""
State definition for Watchtower 5-Agent Architecture.
"""
import operator
from typing import Annotated, Any, Dict, List, Optional, TypedDict


class PentestState(TypedDict, total=False):
    """
    Shared state schema across all 5 agents.
    """

    # ── Core target / auth ───────────────────────────────────────────
    scope_targets: List[str]
    available_tools: List[str]
    auth_metadata: Dict[str, str]

    # ── Messaging / logging ──────────────────────────────────────────
    messages: Annotated[List[str], operator.add]
    error_log: Annotated[List[str], operator.add]

    # ── Planner outputs ──────────────────────────────────────────────
    current_plan: str
    next_step: str | List[str]
    next_command: str
    current_tool: str
    done: bool

    # ── Worker / observations ────────────────────────────────────────
    observations: Annotated[List[Dict[str, Any]], operator.add]
    pending_tools: List[str]
    completed_tools: Annotated[List[str], operator.add]
    stdout: str
    stderr: str
    exit_code: int
    raw_output: str

    # ── Analyst outputs ──────────────────────────────────────────────
    findings: Annotated[List[Dict[str, Any]], operator.add]

    # ── Memory ───────────────────────────────────────────────────────
    memory_agent: Any
    session_id: str
    memory_context: str

    # ── Cleaner ──────────────────────────────────────────────────────
    cleaner_agent: Any
    clean_result: Dict[str, Any]

    # ── Validator ────────────────────────────────────────────────────
    validator_agent: Any
    validated_findings: Annotated[List[Dict[str, Any]], operator.add]
    rejected_findings: Annotated[List[Dict[str, Any]], operator.add]
    retest_requests: Annotated[List[Dict[str, Any]], operator.add]
    validator_results: Dict[str, Any]
    validation_status: str
    validation_summary: str

    # ── Cache ────────────────────────────────────────────────────────
    from_cache: bool
    cached_result: Dict[str, Any]

    # ── Phase tracking ───────────────────────────────────────────────
    current_phase: str  # recon, scan, exploit, validate, report
    phase_history: Annotated[List[Dict[str, Any]], operator.add]

    # ── Graph control ────────────────────────────────────────────────
    iteration_count: int
    is_finished: bool


# Compatibility alias
AgentState = PentestState
