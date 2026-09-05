"""
Unit tests for guardrails target validation and sanitization.
"""
import pytest
from watchtower.core.guardrails import validate_target, sanitize_target


def test_validate_target_valid():
    assert validate_target("http://example.com") is True
    assert validate_target("https://target.local:8080/path") is True
    assert validate_target("192.168.1.1") is True
    assert validate_target("subdomain.example.co.uk") is True
    assert validate_target("10.0.0.1:8080") is True


def test_validate_target_dangerous_chars():
    assert validate_target("http://example.com; rm -rf /") is False
    assert validate_target("http://example.com | cat /etc/passwd") is False
    assert validate_target("http://example.com`id`") is False
    assert validate_target("http://example.com$(whoami)") is False
    assert validate_target("http://example.com\x00") is False


def test_sanitize_target_valid():
    cleaned = sanitize_target("  https://target.local  ")
    assert cleaned == "https://target.local"


def test_sanitize_target_rejects_injection():
    with pytest.raises(ValueError, match="Prohibited character"):
        sanitize_target("http://target.local; cat /etc/shadow")

    with pytest.raises(ValueError, match="Prohibited character"):
        sanitize_target("target.local & touch pwned")

    with pytest.raises(ValueError, match="Target cannot be empty"):
        sanitize_target("")
