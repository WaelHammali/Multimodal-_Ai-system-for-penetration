"""
Centralized configuration management for Watchtower.

Provides a singleton Config object that reads from .env and environment
variables, discovers installed security tools, and exposes typed properties
for every subsystem (LLM, validator, memory, graph, parallel execution).
"""
import os
import shutil
import logging
from typing import Dict, Optional, List
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class Config:
    """Configuration singleton for the Watchtower framework."""

    _instance: Optional["Config"] = None

    def __new__(cls) -> "Config":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        # ── LLM Configuration ────────────────────────────────────────────
        self.groq_api_key: str = os.getenv("GROQ_API_KEY", "")
        self.groq_model: str = os.getenv("GROQ_MODEL_NAME", "llama-3.3-70b-versatile")
        self.openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
        self.openai_model: str = os.getenv("OPENAI_MODEL_NAME", "gpt-4-turbo")
        self.gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
        self.gemini_model: str = os.getenv("GEMINI_MODEL_NAME", "gemini-1.5-pro")
        self.openrouter_api_key: str = os.getenv("OPENROUTER_API_KEY", "")
        self.openrouter_model: str = os.getenv("OPENROUTER_MODEL_NAME", "anthropic/claude-3-opus")

        # Custom provider overrides
        self.custom_provider: str = os.getenv("WATCHTOWER_PROVIDER", "")
        self.custom_model: str = os.getenv("WATCHTOWER_MODEL", "gpt-4-turbo")
        self.custom_apikey_name: str = os.getenv("WATCHTOWER_APIKEY_NAME", "")

        # ── Validator Configuration ──────────────────────────────────────
        self.validator_enabled: bool = os.getenv("VALIDATOR_ENABLED", "true").lower() == "true"
        self.validator_timeout: int = int(os.getenv("VALIDATOR_TIMEOUT", "120"))
        self.validator_max_retries: int = int(os.getenv("VALIDATOR_MAX_RETRIES", "1"))
        self.validator_confidence_threshold: int = int(
            os.getenv("VALIDATOR_CONFIDENCE_THRESHOLD", "70")
        )

        # ── Memory Configuration ─────────────────────────────────────────
        self.memory_enabled: bool = os.getenv("MEMORY_ENABLED", "true").lower() == "true"
        self.memory_db_path: str = os.getenv("MEMORY_DB_PATH", "pentest_memory.db")
        self.memory_vector_enabled: bool = os.getenv("MEMORY_VECTOR_ENABLED", "true").lower() == "true"
        self.memory_vector_db_path: str = os.getenv("MEMORY_VECTOR_DB_PATH", "watchtower_vectordb")
        self.memory_agent_db_path: str = os.getenv(
            "MEMORY_AGENT_DB_PATH", "watchtower_memory.db"
        )
        self.memory_cache_enabled: bool = (
            os.getenv("MEMORY_CACHE_ENABLED", "true").lower() == "true"
        )
        self.memory_cache_ttl: int = int(os.getenv("MEMORY_CACHE_TTL", "86400"))
        self.memory_embed_model: str = os.getenv(
            "MEMORY_EMBED_MODEL", "all-MiniLM-L6-v2"
        )

        # ── Cleaner Configuration ────────────────────────────────────────
        self.cleaner_enabled: bool = os.getenv("CLEANER_ENABLED", "true").lower() == "true"
        self.cleaner_use_llm: bool = os.getenv("CLEANER_USE_LLM", "true").lower() == "true"
        self.cleaner_store_raw: bool = (
            os.getenv("CLEANER_STORE_RAW", "false").lower() == "true"
        )

        # ── Graph / Execution Configuration ──────────────────────────────
        self.max_iterations: int = int(os.getenv("MAX_ITERATIONS", "25"))
        self.recursion_limit: int = int(os.getenv("RECURSION_LIMIT", "100"))
        self.max_parallel_workers: int = int(os.getenv("MAX_PARALLEL_WORKERS", "4"))
        self.tool_timeout: int = int(os.getenv("TOOL_TIMEOUT", "300"))

        # ── Tool Discovery ───────────────────────────────────────────────
        self._all_tool_names: List[str] = [
            "nmap", "masscan", "httpx", "whatweb", "wafw00f",
            "subfinder", "amass", "dnsrecon", "nuclei", "nikto",
            "sqlmap", "wpscan", "testssl", "sslyze", "gobuster",
            "ffuf", "arjun", "xsstrike", "gitleaks", "cmseek",
            "retire", "dalfox", "kiterunner",
        ]
        self.tool_paths: Dict[str, Optional[str]] = {}
        self._discover_tools()

    # ── Tool Discovery ───────────────────────────────────────────────────

    def _discover_tools(self) -> None:
        """Discover installed security tools on the system PATH."""
        for tool in self._all_tool_names:
            # Check for env-overridden paths first
            env_path = os.getenv(f"{tool.upper()}_PATH")
            if env_path and shutil.which(env_path):
                self.tool_paths[tool] = env_path
                continue

            # Special-case: testssl binary is testssl.sh
            if tool == "testssl":
                path = shutil.which("testssl") or shutil.which("testssl.sh")
            else:
                path = shutil.which(tool)

            self.tool_paths[tool] = path

    def get_tool_path(self, name: str) -> Optional[str]:
        """Return the resolved binary path for a tool, or None if missing."""
        return self.tool_paths.get(name)

    def get_installed_tools(self) -> List[str]:
        """Return names of all tools detected on the system."""
        return [t for t, p in self.tool_paths.items() if p is not None]

    def get_missing_tools(self) -> List[str]:
        """Return names of tools NOT found on the system."""
        return [t for t, p in self.tool_paths.items() if p is None]

    @property
    def all_tool_names(self) -> List[str]:
        """Full canonical list of supported tool names."""
        return list(self._all_tool_names)

    # ── Convenience ──────────────────────────────────────────────────────

    def get(self, key: str, default=None):
        """Get a configuration value by attribute name."""
        return getattr(self, key, default)

    def __repr__(self) -> str:
        installed = len(self.get_installed_tools())
        total = len(self._all_tool_names)
        return (
            f"<Config tools={installed}/{total} "
            f"validator={'ON' if self.validator_enabled else 'OFF'} "
            f"vector_memory={'ON' if self.memory_vector_enabled else 'OFF'} "
            f"max_iter={self.max_iterations}>"
        )


# ── Singleton instance ───────────────────────────────────────────────────
config = Config()
