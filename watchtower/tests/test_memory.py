"""
Unit tests for MemoryAgent.

Uses an in-memory SQLite database so tests are fast, isolated, and leave
no files on disk.  sentence-transformers is mocked so tests pass even
when the library is not installed.
"""
import json
import time
from unittest.mock import MagicMock, patch

import pytest

from watchtower.core.memory_agent import MemoryAgent


@pytest.fixture
def mem() -> MemoryAgent:
    """Fresh in-memory MemoryAgent instance for each test."""
    return MemoryAgent(db_path=":memory:", vector_enabled=False, cache_enabled=True, cache_ttl_seconds=3600)


# ── Session lifecycle ─────────────────────────────────────────────────────────

def test_create_session_returns_uuid(mem: MemoryAgent) -> None:
    sid = mem.create_session("192.168.1.1")
    assert isinstance(sid, str)
    assert len(sid) == 36  # UUID4


def test_get_session_summary(mem: MemoryAgent) -> None:
    sid = mem.create_session("10.0.0.1")
    summary = mem.get_session_summary(sid)
    assert summary["id"] == sid
    assert summary["target"] == "10.0.0.1"
    assert summary["status"] == "active"


def test_close_session(mem: MemoryAgent) -> None:
    sid = mem.create_session("10.0.0.1")
    mem.close_session(sid)
    summary = mem.get_session_summary(sid)
    assert summary["status"] == "closed"
    assert summary["end_time"] is not None


def test_get_nonexistent_session(mem: MemoryAgent) -> None:
    result = mem.get_session_summary("nonexistent-uuid")
    assert result == {}


# ── Cleaned-command cache ─────────────────────────────────────────────────────

SAMPLE_CLEAN_RESULT = {
    "structured_output": '{"open_ports": [{"port": "22/tcp", "service": "ssh"}]}',
    "clean_summary": "Found 1 open port: 22/tcp/ssh",
    "open_ports": "22",
    "vulnerabilities": "",
    "directories": "",
    "raw_output_preview": "Starting Nmap...",
}


def test_add_and_get_cached_command(mem: MemoryAgent) -> None:
    sid = mem.create_session("192.168.1.1")
    mem.add_cleaned_command(
        command="nmap -sV 192.168.1.1",
        tool="nmap",
        target="192.168.1.1",
        exit_code=0,
        duration=5.0,
        clean_result=SAMPLE_CLEAN_RESULT,
        session_id=sid,
    )
    cached = mem.get_cached_command("nmap -sV 192.168.1.1", sid)
    assert cached is not None
    assert cached["from_cache"] is True
    assert cached["tool"] == "nmap"


def test_cache_miss_returns_none(mem: MemoryAgent) -> None:
    result = mem.get_cached_command("nmap -sV 10.0.0.99", "no-session")
    assert result is None


def test_cache_ttl_expired() -> None:
    """Cached result older than TTL should not be returned."""
    import time

    mem_short = MemoryAgent(
        db_path=":memory:", vector_enabled=False, cache_enabled=True, cache_ttl_seconds=1
    )
    sid = mem_short.create_session("192.168.1.2")
    mem_short.add_cleaned_command(
        command="nmap -sV 192.168.1.2",
        tool="nmap",
        target="192.168.1.2",
        exit_code=0,
        duration=1.0,
        clean_result=SAMPLE_CLEAN_RESULT,
        session_id=sid,
    )
    time.sleep(2)  # Wait for TTL to expire
    cached = mem_short.get_cached_command("nmap -sV 192.168.1.2", sid)
    assert cached is None


def test_cache_disabled_returns_none() -> None:
    mem_no_cache = MemoryAgent(db_path=":memory:", vector_enabled=False, cache_enabled=False)
    sid = mem_no_cache.create_session("10.0.0.5")
    mem_no_cache.add_cleaned_command(
        command="nmap 10.0.0.5",
        tool="nmap",
        target="10.0.0.5",
        exit_code=0,
        duration=1.0,
        clean_result=SAMPLE_CLEAN_RESULT,
        session_id=sid,
    )
    result = mem_no_cache.get_cached_command("nmap 10.0.0.5", sid)
    assert result is None


def test_session_command_counter(mem: MemoryAgent) -> None:
    sid = mem.create_session("192.168.1.3")
    for i in range(3):
        mem.add_cleaned_command(
            command=f"nmap -p {i} 192.168.1.3",
            tool="nmap",
            target="192.168.1.3",
            exit_code=0,
            duration=1.0,
            clean_result=SAMPLE_CLEAN_RESULT,
            session_id=sid,
        )
    summary = mem.get_session_summary(sid)
    assert summary["total_commands"] == 3


# ── Findings ─────────────────────────────────────────────────────────────────

def test_add_finding_and_retrieve(mem: MemoryAgent) -> None:
    sid = mem.create_session("192.168.1.1")
    finding = {
        "finding_type": "High",
        "target": "192.168.1.1",
        "session_id": sid,
        "title": "Open SSH",
    }
    fid = mem.add_finding(finding)
    assert isinstance(fid, str)
    findings = mem.get_findings_summary(sid, only_validated=False)
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "High"


def test_update_finding_validation(mem: MemoryAgent) -> None:
    sid = mem.create_session("192.168.1.1")
    fid = mem.add_finding({
        "finding_type": "Medium",
        "target": "192.168.1.1",
        "session_id": sid,
    })
    mem.update_finding_validation(
        finding_id=fid,
        validated=True,
        confidence=85,
        evidence="Port 22 clearly open in nmap output",
        remediation="Restrict SSH to trusted IPs",
    )
    validated = mem.get_findings_summary(sid, only_validated=True)
    assert len(validated) == 1
    assert validated[0]["confidence"] == 85
    assert validated[0]["validated"] == 1


def test_get_findings_only_validated(mem: MemoryAgent) -> None:
    sid = mem.create_session("10.0.0.2")
    fid1 = mem.add_finding({"finding_type": "High", "target": "10.0.0.2", "session_id": sid})
    fid2 = mem.add_finding({"finding_type": "Low", "target": "10.0.0.2", "session_id": sid})
    mem.update_finding_validation(fid1, True, 90, "evidence", "fix it")
    # fid2 stays unvalidated
    only_validated = mem.get_findings_summary(sid, only_validated=True)
    assert len(only_validated) == 1


# ── Reasoning memory ──────────────────────────────────────────────────────────

def test_add_memory_and_get_context(mem: MemoryAgent) -> None:
    sid = mem.create_session("10.0.0.3")
    mem.add_memory("Planner", "Decided next_step='nmap'", {"step": "nmap"}, session_id=sid)
    mem.add_memory("Analyst", "Extracted 2 findings", {"count": 2}, session_id=sid)
    context = mem.get_memory_context(sid, limit=10)
    assert "Planner" in context
    assert "Analyst" in context


def test_get_memory_context_empty(mem: MemoryAgent) -> None:
    sid = mem.create_session("10.0.0.4")
    context = mem.get_memory_context(sid, limit=10)
    assert context == ""


def test_add_reasoning_step(mem: MemoryAgent) -> None:
    sid = mem.create_session("10.0.0.5")
    mid = mem.add_reasoning_step("Validator", "Confirmed finding", "Evidence text", session_id=sid)
    assert isinstance(mid, str)
    context = mem.get_memory_context(sid)
    assert "Validator" in context


def test_memory_parent_id(mem: MemoryAgent) -> None:
    sid = mem.create_session("10.0.0.6")
    parent = mem.add_memory("Planner", "Step 1", "start", session_id=sid)
    child = mem.add_memory("Worker", "Step 2", "execute", session_id=sid, parent_id=parent)
    assert child != parent


# ── Semantic search (keyword fallback) ───────────────────────────────────────

def test_semantic_search_keyword_fallback(mem: MemoryAgent) -> None:
    sid = mem.create_session("10.0.0.7")
    mem.add_memory("Analyst", "Found SQL injection", {"type": "sqli"}, session_id=sid)
    mem.add_memory("Planner", "Decided nmap scan", {"tool": "nmap"}, session_id=sid)
    results = mem.semantic_search("SQL injection", limit=5)
    assert any("SQL" in r.get("action", "") for r in results)


def test_semantic_search_no_results_returns_empty(mem: MemoryAgent) -> None:
    mem2 = MemoryAgent(db_path=":memory:", vector_enabled=False, cache_enabled=False)
    results = mem2.semantic_search("unlikely query XYZ123", limit=5)
    assert isinstance(results, list)


# ── Vector search with mocked embedder ───────────────────────────────────────

def test_semantic_search_with_mock_embedder(mem: MemoryAgent) -> None:
    """Test vector-based search path with a mocked SentenceTransformer."""
    import numpy as np

    mock_embedder = MagicMock()
    mock_embedder.encode.return_value = np.ones(384, dtype=np.float32)
    mem._embedder = mock_embedder

    sid = mem.create_session("10.0.0.8")
    mem.add_memory("Worker", "Ran nmap scan", {"tool": "nmap"}, session_id=sid)

    # Embedder should have been called during add_memory
    assert mock_embedder.encode.call_count >= 1

    # search — embedder returns same vector for query
    results = mem.semantic_search("nmap scan", limit=5)
    assert isinstance(results, list)


# ── Close ─────────────────────────────────────────────────────────────────────

def test_close_does_not_raise(mem: MemoryAgent) -> None:
    mem.close()  # Should not raise


def test_repr(mem: MemoryAgent) -> None:
    r = repr(mem)
    assert "MemoryAgent" in r
