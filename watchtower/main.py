"""
Watchtower — AI-Powered Penetration Testing Framework.

Entry point for the CLI application. Orchestrates tool selection,
agent graph execution, memory persistence, and report generation.
"""
import os
import sys

# Ensure parent directory is in sys.path for direct execution
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
import logging
import uuid
from dotenv import load_dotenv

import questionary

from watchtower.core.config import config
from watchtower.core.agent_manager import create_agent_graph
from watchtower.core.memory import MemoryStore
from watchtower.memory import MemoryAgent
from watchtower.cleaner import CleanerAgent
from watchtower.validator import ValidatorAgent
from watchtower.core.guardrails import validate_target

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Watchtower — AI-powered penetration testing automation"
    )
    parser.add_argument("-t", "--target", help="Target URL or IP", required=False)
    parser.add_argument("--skip-ask-tools", action="store_true", help="Skip tool selection")
    parser.add_argument("--provider", help="Custom LLM provider")
    parser.add_argument("--model", help="Custom model string")
    parser.add_argument(
        "--apikey",
        help="Environment variable name containing the API key (e.g. GROQ_API_KEY)",
    )
    parser.add_argument(
        "--report",
        help="Generate a report from the SQLite database (provide output filename)",
    )
    parser.add_argument(
        "--report-format",
        choices=["pdf", "html", "markdown", "all"],
        default="pdf",
        help="Report format: pdf (default), html, markdown, or all",
    )
    parser.add_argument(
        "--cookie", help="Session cookie for authenticated requests"
    )
    parser.add_argument(
        "--header",
        action="append",
        help="Custom headers (format Key:Value). Can be specified multiple times.",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        help="Override max graph iterations (default: from config / 25)",
    )
    return parser.parse_args()


def _generate_reports(db_path: str, base_path: str, fmt: str, validation_summary: str = ""):
    """Generate reports in the requested format(s)."""
    formats_to_generate = ["pdf", "html", "markdown"] if fmt == "all" else [fmt]

    for report_fmt in formats_to_generate:
        if report_fmt == "pdf":
            from watchtower.reporting.reporter import generate_pdf_report
            out = base_path if base_path.endswith(".pdf") else f"{base_path}.pdf"
            generate_pdf_report(db_path, out, validation_summary=validation_summary)

        elif report_fmt == "html":
            from watchtower.reporting.html_reporter import generate_html_report
            out = base_path if base_path.endswith(".html") else f"{base_path}.html"
            generate_html_report(db_path, out, validation_summary=validation_summary)

        elif report_fmt == "markdown":
            from watchtower.reporting.markdown_reporter import generate_markdown_report
            out = base_path if base_path.endswith(".md") else f"{base_path}.md"
            generate_markdown_report(db_path, out, validation_summary=validation_summary)

        logger.info("Report generated: %s", out)


def main():
    load_dotenv()
    args = _parse_args()

    # ── Auth metadata ────────────────────────────────────────────────
    auth_metadata = {}
    if args.cookie:
        auth_metadata["Cookie"] = args.cookie
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                auth_metadata[k.strip()] = v.strip()

    # ── Custom provider overrides ────────────────────────────────────
    if args.provider:
        os.environ["WATCHTOWER_PROVIDER"] = args.provider
    if args.model:
        os.environ["WATCHTOWER_MODEL"] = args.model
    if args.apikey:
        os.environ["WATCHTOWER_APIKEY_NAME"] = args.apikey
    if args.max_iterations is not None:
        config.max_iterations = args.max_iterations

    # ── Report-only mode ─────────────────────────────────────────────
    if args.report:
        db_path = config.memory_db_path
        _generate_reports(db_path, args.report, args.report_format)
        sys.exit(0)

    # ── Validate target ──────────────────────────────────────────────
    if not args.target:
        logger.error("The -t/--target argument is required unless generating a report.")
        sys.exit(1)

    if not validate_target(args.target):
        logger.error("Invalid target: %s — must be a valid URL or IP address.", args.target)
        sys.exit(1)

    logger.info("Initializing Watchtower AI Pentesting Framework...")

    # ── Tool selection ───────────────────────────────────────────────
    all_tools = config.all_tool_names
    installed_tools = config.get_installed_tools()
    missing_tools = config.get_missing_tools()
    selected_tools = all_tools.copy()

    if not args.skip_ask_tools:
        if missing_tools:
            logger.warning("Missing tools: %s", ", ".join(missing_tools))

        choices = [
            questionary.Choice(tool, checked=(tool in installed_tools))
            for tool in all_tools
        ]
        try:
            answers = questionary.checkbox(
                "Select which tools the AI is allowed to use for this pentest:",
                choices=choices,
            ).ask()
            if answers is not None:
                selected_tools = answers
            else:
                logger.info("Aborted.")
                return
        except Exception:
            logger.warning("Interactive prompt failed — falling back to installed tools.")
            selected_tools = installed_tools

    logger.info("Selected tools: %s", ", ".join(selected_tools))

    # ── Memory (Unified MemoryAgent) ──────────────────────────────
    session_id = str(uuid.uuid4())
    memory_agent: MemoryAgent | None = None
    if config.memory_enabled:
        memory_agent = MemoryAgent(
            db_path=config.memory_agent_db_path,
            vector_enabled=config.memory_vector_enabled,
            embed_model=config.memory_embed_model,
            cache_enabled=config.memory_cache_enabled,
            cache_ttl_seconds=config.memory_cache_ttl,
        )
        session_id = memory_agent.create_session(args.target)
        memory = memory_agent
        logger.info("MemoryAgent initialised (db: %s).", config.memory_agent_db_path)
    else:
        memory = MemoryStore(
            db_path=config.memory_db_path,
            session_id=session_id,
            vector_enabled=False,
        )

    # ── CleanerAgent ───────────────────────────────────────
    cleaner_agent: CleanerAgent | None = None
    if config.cleaner_enabled:
        cleaner_agent = CleanerAgent()
        logger.info("CleanerAgent initialised.")

    # ── ValidatorAgent ─────────────────────────────────────
    validator_agent: ValidatorAgent | None = None
    if config.validator_enabled:
        from watchtower.agents.planner import get_llm
        validator_agent = ValidatorAgent(
            confidence_threshold=getattr(config, "validator_confidence_threshold", 70),
            llm_client=get_llm(),
        )
        logger.info("ValidatorAgent initialised with LLM verification.")

    # ── Vector memory context ────────────────────────────────────────
    memory_context = memory.get_session_context(args.target)
    if memory_context:
        logger.info("Loaded prior scan context from vector memory.")

    # ── Graph ────────────────────────────────────────────────────────
    graph = create_agent_graph()
    logger.info("Multi-agent state graph compiled (5 agents: Planner → Worker → Cleaner → Analyst → Validator).")

    # ── Initial state ────────────────────────────────────────────────
    initial_state = {
        "scope_targets": [args.target],
        "available_tools": selected_tools,
        "messages": [],
        "error_log": [],
        "findings": [],
        "observations": [],
        "validated_findings": [],
        "rejected_findings": [],
        "retest_requests": [],
        "completed_tools": [],
        "current_plan": "",
        "next_step": "",
        "pending_tools": [],
        "auth_metadata": auth_metadata,
        "is_finished": False,
        "iteration_count": 0,
        "session_id": session_id,
        "memory_context": memory_context,
        "validation_summary": "",
        # New agent refs
        "memory_agent": memory_agent,
        "cleaner_agent": cleaner_agent,
        "validator_agent": validator_agent,
        "clean_result": {},
        "from_cache": False,
        "current_phase": "recon",
        "phase_history": [],
    }

    # ── Execute graph ────────────────────────────────────────────────
    logger.info("Starting agent execution against target: %s", args.target)
    logger.info("-" * 50)

    validation_summary = ""

    for event in graph.stream(initial_state, config={"recursion_limit": config.recursion_limit}):
        for node_name, state_updates in event.items():
            logger.info("==> Node Executed: [%s]", node_name.upper())

            # Persist observations to SQLite + rich vector memory
            if "observations" in state_updates:
                clean_res = state_updates.get("clean_result", {})
                for obs in state_updates["observations"]:
                    memory.log_observation(
                        obs.get("target"),
                        obs.get("tool"),
                        obs.get("output"),
                        clean_result=clean_res,
                    )

            # Persist validated findings to SQLite
            if "validated_findings" in state_updates:
                for finding in state_updates["validated_findings"]:
                    target = finding.get("target", args.target)
                    vulnerability = finding.get("title", "Unknown Finding")
                    memory.log_finding(
                        target=target,
                        vulnerability=vulnerability,
                        details=finding,
                        severity=finding.get("severity", "Unknown"),
                        cvss_score=float(finding.get("cvss_score", 0)),
                        validated=True,
                    )

            # Capture validation summary
            if "validation_summary" in state_updates and state_updates["validation_summary"]:
                validation_summary = state_updates["validation_summary"]

            # Log state updates (skip noisy keys)
            skip_keys = {"messages", "observations", "error_log", "memory_context"}
            for key, val in state_updates.items():
                if key not in skip_keys:
                    logger.info("    - Updated '%s': %s", key, val)

    logger.info("-" * 50)
    logger.info("Pentest execution loop complete (session: %s).", session_id)

    # ── Auto-generate reports ────────────────────────────────────────
    if args.report:
        _generate_reports(
            config.memory_db_path,
            args.report,
            args.report_format,
            validation_summary=validation_summary,
        )

    if memory:
        if hasattr(memory, "close_session"):
            memory.close_session(session_id)
        memory.close()


if __name__ == "__main__":
    main()
