"""
Worker Agent — Executes security tools requested by the Planner.

Supports both sequential and **parallel** tool execution via
``concurrent.futures.ThreadPoolExecutor``.  When the Planner returns
a list of tool names in ``next_step``, they run concurrently.  Error
isolation ensures one tool's failure doesn't abort the batch.

Enhancements:
  - Checks MemoryAgent cache before executing any command.
  - Passes raw output through CleanerAgent after each tool run.
  - Stores cleaned results back into MemoryAgent for future cache hits.
"""
import importlib
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List

from watchtower.core.state import AgentState

logger = logging.getLogger(__name__)


def _run_single_tool(
    tool_name: str,
    target: str,
    auth_metadata: Dict[str, str],
    timeout: int = 300,
) -> Dict[str, Any]:
    """
    Execute one tool module and return an observation dict.

    Isolated so that exceptions in one tool don't affect others when
    running in parallel.
    """
    try:
        tool_module = importlib.import_module(f"watchtower.tools.{tool_name}")
        raw_output = tool_module.run(target, auth_metadata=auth_metadata)
    except Exception as exc:
        raw_output = f"Error running {tool_name}: {exc}"
        logger.error("Worker — tool '%s' failed: %s", tool_name, exc)

    return {
        "target": target,
        "tool": tool_name,
        "output": raw_output,
    }


def worker_node(state: AgentState) -> dict:
    """
    Worker node: runs the tool(s) specified in ``next_step``.

    Enhancements over the original:
      - Checks the ``MemoryAgent`` cache before executing a command.
      - On a cache hit, returns the stored result immediately.
      - On a cache miss, runs the tool as before and then passes the raw
        output through ``CleanerAgent`` before returning it to state.

    * If ``next_step`` is a single string → sequential execution.
    * If ``next_step`` is a list → parallel execution via ThreadPoolExecutor.
    """
    from watchtower.core.config import config

    next_step = state.get("next_step", "finish")
    available_tools = state.get("available_tools", [])
    auth_metadata = state.get("auth_metadata", {})
    max_workers = config.max_parallel_workers
    timeout = config.tool_timeout
    memory = state.get("memory_agent")
    cleaner = state.get("cleaner_agent")
    session_id = state.get("session_id", "")
    cache_enabled = getattr(config, "memory_cache_enabled", False)

    # Normalise to list
    tools_to_run: List[str] = (
        [next_step] if isinstance(next_step, str) else list(next_step)
    )

    # Filter out meta-commands and unavailable tools
    tools_to_run = [
        t for t in tools_to_run
        if t not in ("finish", "") and t in available_tools
    ]

    if not tools_to_run:
        return {"observations": [], "completed_tools": []}

    target = state["scope_targets"][0]
    observations: List[Dict[str, Any]] = []
    completed: List[str] = []
    clean_result: Dict[str, Any] = {}
    from_cache = False

    def _clean_and_cache(obs: Dict[str, Any], tool_name: str) -> Dict[str, Any]:
        """Run CleanerAgent on obs and persist result to MemoryAgent."""
        nonlocal clean_result
        raw_output = obs.get("output", "")
        command_key = f"{tool_name} {target}"

        if cleaner and getattr(config, "cleaner_enabled", True):
            try:
                cr = cleaner.clean(
                    command=command_key,
                    tool=tool_name,
                    raw_output=raw_output,
                    target=target,
                    exit_code=0,
                    duration=0.0,
                )
                obs["clean_result"] = cr
                clean_result = cr
                if memory:
                    memory.add_cleaned_command(
                        command=command_key,
                        tool=tool_name,
                        target=target,
                        exit_code=0,
                        duration=0.0,
                        clean_result=cr,
                        session_id=session_id,
                    )
            except Exception as exc:
                logger.warning("Worker: cleaner failed for '%s': %s", tool_name, exc)
        return obs

    if len(tools_to_run) == 1:
        # ── Sequential (single tool) ────────────────────────────────
        tool = tools_to_run[0]
        command_key = f"{tool} {target}"

        # Cache check
        if memory and cache_enabled:
            cached = memory.get_cached_command(command_key, session_id)
            if cached:
                logger.info("Worker — CACHE HIT for '%s'", command_key)
                obs = {
                    "target": target,
                    "tool": tool,
                    "output": cached.get("raw_output_preview", ""),
                    "clean_result": cached,
                    "from_cache": True,
                }
                return {
                    "observations": [obs],
                    "completed_tools": [tool],
                    "clean_result": cached,
                    "from_cache": True,
                    "messages": [f"Worker: CACHE HIT — {command_key[:60]}"],
                }

        logger.info("Worker — running '%s' against %s", tool, target)
        obs = _run_single_tool(tool, target, auth_metadata, timeout)
        obs = _clean_and_cache(obs, tool)
        observations.append(obs)
        completed.append(tool)
    else:
        # ── Parallel (multiple tools) ───────────────────────────────
        logger.info(
            "Worker — running %d tools in parallel (max_workers=%d): %s",
            len(tools_to_run), max_workers, tools_to_run,
        )
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_tool = {
                executor.submit(
                    _run_single_tool, tool, target, auth_metadata, timeout
                ): tool
                for tool in tools_to_run
            }
            for future in as_completed(future_to_tool):
                tool_name = future_to_tool[future]
                try:
                    obs = future.result(timeout=timeout + 30)
                    obs = _clean_and_cache(obs, tool_name)
                    observations.append(obs)
                    completed.append(tool_name)
                except Exception as exc:
                    logger.error("Worker — parallel task '%s' raised: %s", tool_name, exc)
                    observations.append({
                        "target": target,
                        "tool": tool_name,
                        "output": f"Error (parallel): {exc}",
                    })
                    completed.append(tool_name)

    logger.info("Worker — completed %d tool(s): %s", len(completed), completed)

    result: Dict[str, Any] = {
        "observations": observations,
        "completed_tools": completed,
        "from_cache": from_cache,
    }
    if clean_result:
        result["clean_result"] = clean_result
    return result
