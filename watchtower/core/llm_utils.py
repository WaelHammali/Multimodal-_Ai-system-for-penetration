"""
LLM invocation utility with exponential backoff retry.

Wraps chain.invoke() so that transient errors (rate limits 429, 503,
connection timeouts) are retried up to 3 times before propagating.

Usage:
    from watchtower.core.llm_utils import invoke_with_retry
    result = invoke_with_retry(chain, messages)
"""
from __future__ import annotations

import logging
from typing import Any, Sequence

logger = logging.getLogger(__name__)

try:
    from tenacity import (
        retry,
        stop_after_attempt,
        wait_exponential,
        retry_if_exception_type,
        before_sleep_log,
    )
    _TENACITY_AVAILABLE = True
except ImportError:
    _TENACITY_AVAILABLE = False
    logger.warning(
        "tenacity not installed — LLM calls will NOT be retried on rate-limit errors. "
        "Run: pip install tenacity>=8.2.0"
    )


def invoke_with_retry(chain: Any, input_data: Any, max_attempts: int = 3) -> Any:
    """
    Invoke a LangChain runnable / chain / LLM with automatic exponential-backoff retries.

    Retries on any transient exception (including 429 rate limits, 503 overloads,
    connection errors). Gives up after `max_attempts` and re-raises the
    last exception so callers can handle it.

    Args:
        chain:        A LangChain Runnable (e.g. ``llm | parser``, ``llm``).
        input_data:   The input to pass to ``chain.invoke()`` (messages, dict, or str).
        max_attempts: Maximum total attempts before giving up (default 3).

    Returns:
        The result of ``chain.invoke(input_data)``.
    """
    if _TENACITY_AVAILABLE:
        @retry(
            stop=stop_after_attempt(max_attempts),
            wait=wait_exponential(multiplier=1, min=2, max=30),
            retry=retry_if_exception_type(Exception),
            before_sleep=before_sleep_log(logger, logging.WARNING),
            reraise=True,
        )
        def _invoke() -> Any:
            return chain.invoke(input_data)

        return _invoke()
    else:
        # Simple manual retry without tenacity
        last_exc: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                return chain.invoke(input_data)
            except Exception as exc:
                last_exc = exc
                if attempt < max_attempts:
                    import time
                    wait = 2 ** attempt
                    logger.warning(
                        "LLM invoke failed (attempt %d/%d): %s — retrying in %ds",
                        attempt, max_attempts, exc, wait,
                    )
                    time.sleep(wait)
                else:
                    logger.error(
                        "LLM invoke failed after %d attempts: %s", max_attempts, exc
                    )
        raise last_exc  # type: ignore[misc]
