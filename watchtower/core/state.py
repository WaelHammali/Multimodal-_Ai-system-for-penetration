import operator
from typing import Annotated, TypedDict, List, Dict, Any, Optional
from langchain_core.messages import BaseMessage


class AgentState(TypedDict, total=False):
    """
    Represents the shared state of the LangGraph execution.

    Fields are grouped by subsystem.  List fields annotated with
    ``operator.add`` use LangGraph's reducer semantics so that each
    node *appends* rather than overwrites.

    ``total=False`` makes every key optional so nodes only need to return
    the keys they mutate.
    """

    # ── Core target / auth ───────────────────────────────────────────
    scope_targets: List[str]                                          # Targets allowed to scan
    available_tools: List[str]                                        # Tools the user has explicitly permitted
    auth_metadata: Dict[str, str]                                     # Authentication cookies / headers

    # ── Messaging / logging ──────────────────────────────────────────
    messages: Annotated[List[str], operator.add]
    error_log: Annotated[List[str], operator.add]                     # Structured error tracking

    # ── Planner outputs ──────────────────────────────────────────────
    current_plan: str                                                 # The planner's current strategy
    next_step: str | List[str]                                        # Next tool(s) to run, or 'finish'

    # ── Worker / observations ────────────────────────────────────────
    observations: Annotated[List[Dict[str, Any]], operator.add]       # Raw logs / tool results
    pending_tools: List[str]                                          # Tools queued for parallel execution
    completed_tools: Annotated[List[str], operator.add]               # Tools finished in current batch

    # ── Analyst outputs ──────────────────────────────────────────────
    findings: Annotated[List[Dict[str, Any]], operator.add]           # Vulnerabilities from Analyst

    # ── Validator outputs ────────────────────────────────────────────
    validated_findings: Annotated[List[Dict[str, Any]], operator.add] # Confirmed by Validator
    rejected_findings: Annotated[List[Dict[str, Any]], operator.add]  # Rejected as false positives
    retest_requests: Annotated[List[Dict[str, Any]], operator.add]    # Findings needing re-verification
    validation_summary: str                                           # Validator summary for reporting

    # ── Graph control ────────────────────────────────────────────────
    iteration_count: int                                              # Current loop iteration (depth guard)
    is_finished: bool                                                 # Whether the pentest is complete

    # ── Session / memory ─────────────────────────────────────────────
    session_id: str                                                   # UUID grouping this scan run
    memory_context: str                                               # Injected context from vector memory

    # ── Agent references ─────────────────────────────────────────────
    memory_agent: Any                                                 # MemoryAgent instance
    cleaner_agent: Any                                                # CleanerAgent instance
    validator_agent: Any                                              # ValidatorAgent instance

    # ── Cleaner outputs (new) ────────────────────────────────────────
    clean_result: Dict[str, Any]                                      # Last CleanerAgent output dict
    from_cache: bool                                                  # Whether last result came from cache

    # ── Phase tracking (new) ─────────────────────────────────────────
    current_phase: str                                                # recon | scan | exploit | validate | report
    phase_history: Annotated[List[Dict[str, Any]], operator.add]      # History of phase transitions


# Alias for 5-agent architecture
PentestState = AgentState

