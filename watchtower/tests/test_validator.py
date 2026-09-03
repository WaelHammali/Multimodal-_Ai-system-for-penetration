"""
Unit tests for ValidatorAgent and validator_node.
"""
from unittest.mock import MagicMock, patch
import pytest

from watchtower.validator import (
    ValidatorAgent,
    VerificationStatus,
    ValidationResult,
)
from watchtower.agents.validator import validator_node


@pytest.fixture
def validator_agent() -> ValidatorAgent:
    return ValidatorAgent(confidence_threshold=70)


# ── ValidatorAgent unit tests ───────────────────────────────────────────────

def test_validate_confirmed_finding(validator_agent: ValidatorAgent) -> None:
    finding = {
        "id": "f-1",
        "title": "SQL Injection in login endpoint",
        "type": "sql",
        "evidence": "parameter id appears to be boolean-based blind injectable",
        "description": "SQL injection discovered",
    }
    result = validator_agent.validate(finding)
    assert isinstance(result, ValidationResult)
    assert result.finding_id == "f-1"
    assert result.status == VerificationStatus.CONFIRMED
    assert result.confidence_score >= 70
    assert result.remediation_note is not None
    assert "parameterized" in result.remediation_note.lower()


def test_validate_false_positive_sql_syntax(validator_agent: ValidatorAgent) -> None:
    finding = {
        "id": "f-fp-1",
        "title": "SQL Injection error",
        "type": "sql",
        "evidence": "Server returned error in your SQL syntax near line 1",
    }
    result = validator_agent.validate(finding)
    assert result.status == VerificationStatus.FALSE_POSITIVE
    assert result.confidence_score < 50
    assert "error in your sql syntax" in result.evidence.lower()


def test_validate_false_positive_directory(validator_agent: ValidatorAgent) -> None:
    finding = {
        "id": "f-fp-2",
        "title": "Exposed admin backup file",
        "type": "directory",
        "evidence": "Requested /admin.bak resulted in 404 file not found",
    }
    result = validator_agent.validate(finding)
    assert result.status == VerificationStatus.FALSE_POSITIVE


def test_validate_false_positive_xss_encoded(validator_agent: ValidatorAgent) -> None:
    finding = {
        "id": "f-fp-3",
        "title": "Reflected XSS",
        "type": "xss",
        "evidence": "Output was safely converted to HTML entities and encoded",
    }
    result = validator_agent.validate(finding)
    assert result.status == VerificationStatus.FALSE_POSITIVE


def test_validate_inconclusive_empty_evidence(validator_agent: ValidatorAgent) -> None:
    finding = {
        "id": "f-inc-1",
        "title": "Possible Information Disclosure",
        "type": "info",
        "evidence": "",
    }
    result = validator_agent.validate(finding)
    assert result.status == VerificationStatus.INCONCLUSIVE


def test_validate_batch(validator_agent: ValidatorAgent) -> None:
    findings = [
        {
            "id": "b-1",
            "title": "Command Injection in ping tool",
            "type": "command",
            "evidence": "uid=0(root) gid=0(root) returned in response",
        },
        {
            "id": "b-2",
            "title": "Missing File",
            "type": "directory",
            "evidence": "HTTP 404 No such file",
        },
    ]
    results = validator_agent.validate_batch(findings)
    assert len(results) == 2
    assert results[0].status == VerificationStatus.CONFIRMED
    assert results[1].status == VerificationStatus.FALSE_POSITIVE


def test_validate_with_mock_llm() -> None:
    mock_llm = MagicMock()
    mock_llm.invoke.return_value = MagicMock(content="CONFIRMED: Vulnerability confirmed via proof-of-concept.")

    agent = ValidatorAgent(llm_client=mock_llm)
    finding = {
        "id": "llm-1",
        "title": "Server Side Template Injection",
        "evidence": "7777777 returned after input {{7*1111111}}",
    }
    result = agent.validate(finding)
    assert result.status == VerificationStatus.CONFIRMED
    assert result.confidence_score >= 80


# ── validator_node integration tests ─────────────────────────────────────────

def test_validator_node_pass_through_when_disabled() -> None:
    from watchtower.core.config import config
    orig = config.validator_enabled
    config.validator_enabled = False
    try:
        state = {
            "findings": [{"title": "Vuln A"}, {"title": "Vuln B"}],
            "validated_findings": [],
            "rejected_findings": [],
            "observations": [],
        }
        res = validator_node(state)
        assert len(res["validated_findings"]) == 2
    finally:
        config.validator_enabled = orig
