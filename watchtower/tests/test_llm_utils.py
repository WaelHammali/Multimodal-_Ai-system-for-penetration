"""
Unit tests for watchtower.core.llm_utils.invoke_with_retry.
"""
import pytest
from unittest.mock import MagicMock
from watchtower.core.llm_utils import invoke_with_retry


class TransientFailingChain:
    def __init__(self, failures_before_success: int):
        self.call_count = 0
        self.failures_before_success = failures_before_success

    def invoke(self, input_data):
        self.call_count += 1
        if self.call_count <= self.failures_before_success:
            raise ConnectionError(f"Temporary 429 / connection error (call {self.call_count})")
        return {"result": "success", "calls": self.call_count}


def test_invoke_with_retry_success():
    mock_chain = MagicMock()
    mock_chain.invoke.return_value = {"answer": 42}

    res = invoke_with_retry(mock_chain, "hello", max_attempts=3)
    assert res == {"answer": 42}
    assert mock_chain.invoke.call_count == 1


def test_invoke_with_retry_transient_recovery():
    chain = TransientFailingChain(failures_before_success=2)
    res = invoke_with_retry(chain, "prompt", max_attempts=3)
    assert res["result"] == "success"
    assert res["calls"] == 3


def test_invoke_with_retry_max_attempts_exceeded():
    chain = TransientFailingChain(failures_before_success=5)
    with pytest.raises(ConnectionError):
        invoke_with_retry(chain, "prompt", max_attempts=2)
    assert chain.call_count == 2
