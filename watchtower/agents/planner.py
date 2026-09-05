"""
Planner Agent — Strategises and decides the next sequence of actions.

Enhancements:
  - Injects vector memory context (prior scan knowledge) into the prompt.
  - Reads fresh context from MemoryAgent (reasoning steps + findings).
  - Tracks ``iteration_count`` for depth-guard enforcement.
  - Includes ``validated_findings`` and ``rejected_findings`` so the planner
    doesn't re-investigate already-dismissed items.
  - Supports ``retry_tool`` field for validator-requested retests.
  - Logs each planning decision to MemoryAgent for recall.
"""
import os
import json
import logging
from typing import List, Optional

from pydantic import BaseModel, Field
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.output_parsers import PydanticOutputParser

from watchtower.core.state import AgentState

logger = logging.getLogger(__name__)


# ── Pydantic output schema ──────────────────────────────────────────────────

class PlannerOutput(BaseModel):
    current_plan: str = Field(
        description="The updated strategy based on findings."
    )
    next_step: str | List[str] = Field(
        description=(
            "The exact name of the next tool(s) to run (e.g. 'nmap', 'httpx') "
            "or a list of tools for parallel execution, or 'finish'."
        )
    )
    is_finished: bool = Field(
        description="True if the pentest is complete, False otherwise."
    )
    retry_tool: Optional[str] = Field(
        default=None,
        description=(
            "If the Validator flagged a finding as 'needs_retest', specify "
            "the tool to re-run. Otherwise null."
        ),
    )


# ── LLM factory ─────────────────────────────────────────────────────────────

_llm_singleton: object | None = None  # module-level cache


def get_llm(force_new: bool = False):
    """
    Resolve the LLM instance based on environment / config.

    Priority order:
      1. WATCHTOWER_PROVIDER (custom provider string or URL)
      2. GROQ_API_KEY
      3. OPENROUTER_API_KEY
      4. OPENAI_API_KEY
      5. GEMINI_API_KEY
      6. MockLLM fallback

    The resolved client is cached as a module-level singleton so that
    every agent node reuses the same object instead of re-instantiating
    on each of the 25+ graph iterations.
    """
    global _llm_singleton
    if _llm_singleton is not None and not force_new:
        return _llm_singleton

    custom_provider = os.getenv("WATCHTOWER_PROVIDER")
    custom_model = os.getenv("WATCHTOWER_MODEL", "gpt-4-turbo")
    apikey_env_name = os.getenv("WATCHTOWER_APIKEY_NAME")

    if custom_provider:
        api_key = os.getenv(apikey_env_name) if apikey_env_name else None
        provider = custom_provider.lower()

        if provider.startswith("http"):
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(
                model=custom_model, temperature=0,
                api_key=api_key, base_url=provider,
            )
        elif provider == "openai":
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(model=custom_model, temperature=0, api_key=api_key)
        elif provider == "anthropic":
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(model_name=custom_model, temperature=0, api_key=api_key)
        elif provider == "openrouter":
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(
                model=custom_model, temperature=0,
                api_key=api_key, base_url="https://openrouter.ai/api/v1",
            )
        elif provider == "groq":
            from langchain_openai import ChatOpenAI
            groq_key = api_key or os.getenv("GROQ_API_KEY")
            groq_model = custom_model if custom_model != "gpt-4-turbo" else os.getenv("GROQ_MODEL_NAME", "llama-3.3-70b-versatile")
            return ChatOpenAI(
                model=groq_model,
                temperature=0,
                api_key=groq_key,
                base_url="https://api.groq.com/openai/v1",
            )
        elif provider == "litellm":
            from langchain_community.chat_models import ChatLiteLLM
            _llm_singleton = ChatLiteLLM(model=custom_model, temperature=0, api_key=api_key)
        else:
            try:
                from langchain.chat_models import init_chat_model
                _llm_singleton = init_chat_model(
                    custom_model, model_provider=provider,
                    temperature=0, api_key=api_key,
                )
            except Exception:
                from langchain_community.chat_models import ChatLiteLLM
                _llm_singleton = ChatLiteLLM(model=custom_model, temperature=0, api_key=api_key)
        return _llm_singleton

    if os.getenv("GROQ_API_KEY"):
        from langchain_openai import ChatOpenAI
        model_name = os.getenv("GROQ_MODEL_NAME", "llama-3.3-70b-versatile")
        _llm_singleton = ChatOpenAI(
            model=model_name,
            temperature=0,
            api_key=os.getenv("GROQ_API_KEY"),
            base_url="https://api.groq.com/openai/v1",
        )
    elif os.getenv("OPENROUTER_API_KEY"):
        from langchain_openai import ChatOpenAI
        model_name = os.getenv("OPENROUTER_MODEL_NAME", "anthropic/claude-3-opus")
        _llm_singleton = ChatOpenAI(
            model=model_name, temperature=0,
            api_key=os.getenv("OPENROUTER_API_KEY"),
            base_url="https://openrouter.ai/api/v1",
        )
    elif os.getenv("OPENAI_API_KEY"):
        from langchain_openai import ChatOpenAI
        model_name = os.getenv("OPENAI_MODEL_NAME", "gpt-4-turbo")
        _llm_singleton = ChatOpenAI(model=model_name, temperature=0)
    elif os.getenv("GEMINI_API_KEY"):
        from langchain_google_genai import ChatGoogleGenerativeAI
        model_name = os.getenv("GEMINI_MODEL_NAME", "gemini-1.5-pro")
        _llm_singleton = ChatGoogleGenerativeAI(model=model_name, temperature=0)
    else:
        # ── Mock fallback (no API key configured) ────────────────────
        class MockLLM:
            def with_structured_output(self, schema):
                class MockInvoker:
                    def invoke(self, msgs):
                        if schema.__name__ == "PlannerOutput":
                            return schema(
                                current_plan="Mock fallback: Run nmap",
                                next_step="finish",
                                is_finished=True,
                            )
                        elif schema.__name__ == "AnalystOutput":
                            return schema(findings=[])
                        elif schema.__name__ == "ValidatorOutput":
                            return schema(validated=[], summary="Mock validator")
                        return schema()
                return MockInvoker()
        _llm_singleton = MockLLM()
    return _llm_singleton


# ── Planner node ─────────────────────────────────────────────────────────────

def planner_node(state: AgentState) -> dict:
    """
    Analyse the current state and decide the next action.

    Injects:
      - Available tools list
      - Current findings and observations
      - Validated / rejected findings (so we don't repeat work)
      - Retest requests from the Validator
      - Vector memory context from prior scans
      - Fresh MemoryAgent context (reasoning steps)
    """
    findings = state.get("findings", [])
    observations = state.get("observations", [])
    available_tools = state.get("available_tools", [])
    validated = state.get("validated_findings", [])
    rejected = state.get("rejected_findings", [])
    retests = state.get("retest_requests", [])
    memory_context = state.get("memory_context", "")
    iteration = state.get("iteration_count", 0)

    # ── Refresh context from MemoryAgent ─────────────────────────────
    memory = state.get("memory_agent")
    session_id = state.get("session_id", "")
    agent_memory_context = ""
    if memory and session_id:
        try:
            agent_memory_context = memory.get_memory_context(session_id, limit=20)
        except Exception as mem_exc:
            logger.warning("Planner: failed to load memory context: %s", mem_exc)

    tool_list_str = "\n".join([f"- `{t}`" for t in available_tools])

    # Build the rejected titles so the LLM doesn't re-investigate them
    rejected_titles = [f.get("title", "") for f in rejected]
    rejected_section = ""
    if rejected_titles:
        rejected_section = (
            "\n\nREJECTED findings (do NOT re-investigate these):\n"
            + "\n".join(f"- {t}" for t in rejected_titles)
        )

    # Retest section
    retest_section = ""
    if retests:
        retest_section = (
            "\n\nFindings flagged for RETEST by the Validator:\n"
            + json.dumps(retests[-3:], indent=2)
            + "\nConsider re-running the relevant tool with different parameters."
        )

    # Memory context injection (vector + agent memory)
    memory_section = ""
    if memory_context:
        memory_section = f"\n\n{memory_context}"
    if agent_memory_context:
        memory_section += f"\n\n{agent_memory_context}"

    parser = PydanticOutputParser(pydantic_object=PlannerOutput)

    prompt = f"""\
You are an expert autonomous pentesting planner.
Your goal is to strategize the next sequence of actions based on current findings.

Iteration: {iteration + 1}

Available tools you can specify in next_step (Do NOT hallucinate tools outside this list!!):
{tool_list_str}
- `finish` (If no further testing is needed)

Current Confirmed Findings ({len(validated)} validated):
{json.dumps(validated[-5:], indent=2) if validated else "None yet."}

Recent Observations:
{json.dumps(observations[-3:] if observations else [], indent=2)}
{rejected_section}
{retest_section}
{memory_section}

Decide the next logical step. You can specify a single tool name (string) or a \
list of tool names for parallel execution (e.g., during the reconnaissance phase). \
Do not repeat tools unnecessarily. Ensure parallel tools don't conflict.

{parser.get_format_instructions()}
"""

    llm = get_llm()
    try:
        chain = llm | parser
        result = chain.invoke([HumanMessage(content=prompt)])

        chosen_step = result.retry_tool if result.retry_tool else result.next_step

        # ── RAG Fallback if no action planned ────────────────────────
        if (not chosen_step or chosen_step == "finish") and not result.is_finished and memory:
            last_finding = findings[-1] if findings else None
            if last_finding:
                rag_query = last_finding.get("type") or last_finding.get("title") or ""
                rag_results = memory.semantic_search(rag_query, limit=3)
                if rag_results:
                    rag_details = rag_results[0].get("details")
                    if isinstance(rag_details, str):
                        try:
                            rag_details = json.loads(rag_details)
                        except Exception:
                            rag_details = {}
                    if isinstance(rag_details, dict):
                        rag_cmd = rag_details.get("command") or rag_details.get("tool")
                        if rag_cmd:
                            chosen_step = rag_cmd

        # ── Log planning decision to MemoryAgent ──────────────────────
        if memory and session_id:
            try:
                memory.add_memory(
                    agent="Planner",
                    action=f"Decided next_step='{chosen_step}' (iter {iteration + 1})",
                    details={
                        "plan": result.current_plan[:200],
                        "next_step": chosen_step,
                        "is_finished": result.is_finished,
                    },
                    session_id=session_id,
                )
            except Exception as mem_exc:
                logger.warning("Planner: failed to log memory step: %s", mem_exc)

        return {
            "current_plan": result.current_plan,
            "next_step": chosen_step,
            "is_finished": result.is_finished,
            "iteration_count": iteration + 1,
        }
    except Exception as e:
        logger.error("Planner error: %s", e)
        return {
            "current_plan": f"Error: {e}",
            "next_step": "finish",
            "is_finished": True,
            "iteration_count": iteration + 1,
            "error_log": [f"Planner error: {e}"],
        }
