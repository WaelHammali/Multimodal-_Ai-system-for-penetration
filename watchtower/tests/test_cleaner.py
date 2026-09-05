"""
Unit tests for CleanerAgent.

Tests are fully self-contained and require no external services.
"""
import json
import pytest

from watchtower.core.cleaner import CleanerAgent


@pytest.fixture
def cleaner() -> CleanerAgent:
    return CleanerAgent()


# ── nmap ──────────────────────────────────────────────────────────────────────

NMAP_OUTPUT = """\
Starting Nmap 7.93 ( https://nmap.org )
Nmap scan report for 192.168.1.1
Host is up (0.0012s latency).
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu
80/tcp   open  http     Apache httpd 2.4.41
443/tcp  open  ssl/http Apache httpd 2.4.41
OS details: Linux 4.15 - 5.6
Nmap done: 1 IP address (1 host up)
"""


def test_parse_nmap_open_ports(cleaner: CleanerAgent) -> None:
    result = cleaner._parse_nmap(NMAP_OUTPUT, "192.168.1.1")
    assert result["host_up"] is True
    assert result["total_open"] == 3
    ports = {p["port"] for p in result["open_ports"]}
    assert "22/tcp" in ports
    assert "80/tcp" in ports
    assert "443/tcp" in ports


def test_parse_nmap_os_guess(cleaner: CleanerAgent) -> None:
    result = cleaner._parse_nmap(NMAP_OUTPUT, "192.168.1.1")
    assert result["os_guess"] is not None
    assert "Linux" in result["os_guess"]


def test_parse_nmap_host_down(cleaner: CleanerAgent) -> None:
    output = "Nmap scan report for 10.0.0.1\nHost seems down."
    result = cleaner._parse_nmap(output, "10.0.0.1")
    assert result["host_up"] is False
    assert result["total_open"] == 0


def test_clean_nmap_returns_expected_keys(cleaner: CleanerAgent) -> None:
    result = cleaner.clean(
        command="nmap -sV -p- 192.168.1.1",
        tool="nmap",
        raw_output=NMAP_OUTPUT,
        target="192.168.1.1",
        exit_code=0,
        duration=12.34,
    )
    expected_keys = {
        "command", "tool", "target", "exit_code", "duration",
        "structured_output", "clean_summary", "open_ports",
        "vulnerabilities", "directories", "raw_output_preview",
    }
    assert expected_keys <= result.keys()
    assert result["tool"] == "nmap"
    assert result["exit_code"] == 0
    assert "22" in result["open_ports"]
    assert "80" in result["open_ports"]
    assert "443" in result["open_ports"]


def test_clean_nmap_summary(cleaner: CleanerAgent) -> None:
    result = cleaner.clean(
        command="nmap -sV 192.168.1.1",
        tool="nmap",
        raw_output=NMAP_OUTPUT,
        target="192.168.1.1",
        exit_code=0,
        duration=5.0,
    )
    assert "3" in result["clean_summary"]
    assert "open" in result["clean_summary"].lower() or "port" in result["clean_summary"].lower()


# ── gobuster ──────────────────────────────────────────────────────────────────

GOBUSTER_OUTPUT = """\
/admin                (Status: 200) [Size: 1234]
/login                (Status: 302) [Size: 0]
/static               (Status: 200) [Size: 56789]
/secret.txt           (Status: 403) [Size: 287]
"""


def test_parse_gobuster_directories(cleaner: CleanerAgent) -> None:
    result = cleaner._parse_gobuster(GOBUSTER_OUTPUT, "http://example.com")
    assert result["total_found"] == 4
    paths = {d["path"] for d in result["directories"]}
    assert "/admin" in paths
    assert "/login" in paths


def test_clean_gobuster_directories_field(cleaner: CleanerAgent) -> None:
    result = cleaner.clean(
        command="gobuster dir -u http://example.com -w wordlist.txt",
        tool="gobuster",
        raw_output=GOBUSTER_OUTPUT,
        target="http://example.com",
        exit_code=0,
        duration=3.2,
    )
    assert "/admin" in result["directories"]
    assert "4" in result["clean_summary"] or "path" in result["clean_summary"].lower()


def test_clean_gobuster_no_output(cleaner: CleanerAgent) -> None:
    result = cleaner.clean(
        command="gobuster dir -u http://example.com -w small.txt",
        tool="gobuster",
        raw_output="",
        target="http://example.com",
        exit_code=0,
        duration=1.0,
    )
    assert result["directories"] == ""
    assert "no" in result["clean_summary"].lower() or "0" in result["clean_summary"]


# ── sqlmap ────────────────────────────────────────────────────────────────────

SQLMAP_VULN_OUTPUT = """\
[INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[INFO] Parameter: id (GET)
    Type: boolean-based blind
    Payload: id=1 AND 1=1--
[INFO] target URL appears to have 4 databases
[*] information_schema
[*] testdb
sql injection found
is vulnerable
"""

SQLMAP_CLEAN_OUTPUT = """\
[INFO] testing connection to target URL
[WARNING] no results found
"""


def test_parse_sqlmap_vulnerable(cleaner: CleanerAgent) -> None:
    result = cleaner._parse_sqlmap(SQLMAP_VULN_OUTPUT, "http://example.com")
    assert result["vulnerable"] is True
    assert "id" in result["vulnerable_parameters"]


def test_parse_sqlmap_not_vulnerable(cleaner: CleanerAgent) -> None:
    result = cleaner._parse_sqlmap(SQLMAP_CLEAN_OUTPUT, "http://example.com")
    assert result["vulnerable"] is False


def test_clean_sqlmap_vulnerabilities_field(cleaner: CleanerAgent) -> None:
    result = cleaner.clean(
        command="sqlmap -u http://example.com?id=1 --batch",
        tool="sqlmap",
        raw_output=SQLMAP_VULN_OUTPUT,
        target="http://example.com",
        exit_code=0,
        duration=30.0,
    )
    assert result["vulnerabilities"] != ""
    assert "injection" in result["clean_summary"].lower()


# ── ffuf ──────────────────────────────────────────────────────────────────────

FFUF_OUTPUT = """\
admin                [Status: 200, Size: 4321, Words: 120, Lines: 50]
api                  [Status: 200, Size: 1234, Words: 30, Lines: 20]
images               [Status: 403, Size: 287, Words: 10, Lines: 5]
"""


def test_parse_ffuf_directories(cleaner: CleanerAgent) -> None:
    result = cleaner._parse_ffuf(FFUF_OUTPUT, "http://example.com")
    assert result["total_found"] == 3
    paths = {d["path"] for d in result["directories"]}
    assert "/admin" in paths
    assert "/api" in paths


def test_clean_ffuf_summary(cleaner: CleanerAgent) -> None:
    result = cleaner.clean(
        command="ffuf -w wordlist.txt -u http://example.com/FUZZ",
        tool="ffuf",
        raw_output=FFUF_OUTPUT,
        target="http://example.com",
        exit_code=0,
        duration=5.0,
    )
    assert "3" in result["clean_summary"]
    assert "/admin" in result["directories"]


# ── curl ──────────────────────────────────────────────────────────────────────

CURL_OUTPUT = """\
< HTTP/1.1 200 OK
< Content-Type: text/html; charset=UTF-8
< Content-Length: 1234
< X-Powered-By: PHP/7.4.3
<
<html><body>Hello world</body></html>
"""


def test_parse_curl_status(cleaner: CleanerAgent) -> None:
    result = cleaner._parse_curl(CURL_OUTPUT, "http://example.com")
    assert result["status_code"] == 200
    assert "text/html" in result["headers"].get("Content-Type", "")


def test_clean_curl_summary(cleaner: CleanerAgent) -> None:
    result = cleaner.clean(
        command="curl -v http://example.com",
        tool="curl",
        raw_output=CURL_OUTPUT,
        target="http://example.com",
        exit_code=0,
        duration=0.5,
    )
    assert "200" in result["clean_summary"]


# ── generic fallback ──────────────────────────────────────────────────────────

def test_clean_generic_fallback(cleaner: CleanerAgent) -> None:
    result = cleaner.clean(
        command="whatweb http://example.com",
        tool="whatweb",
        raw_output="WhatWeb report for example.com\nTitle: Example\n",
        target="http://example.com",
        exit_code=0,
        duration=1.2,
    )
    assert result["tool"] == "whatweb"
    assert "lines" in result["clean_summary"].lower() or "characters" in result["clean_summary"].lower()


# ── raw preview truncation ─────────────────────────────────────────────────────

def test_raw_preview_truncated(cleaner: CleanerAgent) -> None:
    big_output = "A" * 1000
    result = cleaner.clean(
        command="nmap -sV 10.0.0.1",
        tool="nmap",
        raw_output=big_output,
        target="10.0.0.1",
        exit_code=0,
        duration=1.0,
    )
    assert len(result["raw_output_preview"]) <= 520  # 500 + "... (truncated)"
    assert "truncated" in result["raw_output_preview"]


# ── structured_output is valid JSON ───────────────────────────────────────────

def test_structured_output_is_valid_json(cleaner: CleanerAgent) -> None:
    result = cleaner.clean(
        command="nmap -sV 192.168.1.1",
        tool="nmap",
        raw_output=NMAP_OUTPUT,
        target="192.168.1.1",
        exit_code=0,
        duration=1.0,
    )
    data = json.loads(result["structured_output"])
    assert isinstance(data, dict)
    assert "open_ports" in data


def test_cleaner_format_list() -> None:
    cleaner = CleanerAgent(use_llm=False)
    assert cleaner._format_list(["80/tcp", "443/tcp"]) == "80/tcp,443/tcp"
    assert cleaner._format_list("single_item") == "single_item"
    assert cleaner._format_list(None) == ""
    assert cleaner._format_list([]) == ""


def test_cleaner_prefilter_output() -> None:
    cleaner = CleanerAgent(use_llm=False)
    # Test gobuster output with 404 noise and 200 OK signal
    raw_gobuster = (
        "Progress: 1000/1000\n"
        "/notfound1 (Status: 404)\n"
        "/notfound2 (Status: 404)\n"
        "/admin (Status: 200) [Size: 1234]\n"
        "/login (Status: 301) [Size: 456]\n"
    )
    filtered = cleaner._prefilter_output(raw_gobuster, "gobuster")
    assert "/admin (Status: 200)" in filtered
    assert "/login (Status: 301)" in filtered
    assert "notfound" not in filtered

    # Test nmap output filtering
    raw_nmap = (
        "Starting Nmap...\n"
        "Initiating ARP Ping...\n"
        "Host is up (0.001s latency).\n"
        "22/tcp open ssh\n"
        "80/tcp open http\n"
        "999/tcp closed unknown\n"
        "Nmap done.\n"
    )
    filtered_nmap = cleaner._prefilter_output(raw_nmap, "nmap")
    assert "22/tcp open ssh" in filtered_nmap
    assert "80/tcp open http" in filtered_nmap
    assert "closed" not in filtered_nmap



# ── LLM Cleaner Tests ──────────────────────────────────────────────────────────

def test_cleaner_llm_mock_extraction(monkeypatch) -> None:
    """Test that CleanerAgent properly uses LLM clean response when available."""
    pytest.importorskip("langchain_core")
    cleaner = CleanerAgent(use_llm=True)

    class MockResponse:
        content = json.dumps({
            "summary": "Discovered critical CVE-2021-41773 path traversal on Apache 2.4.49",
            "open_ports": ["80/http", "443/https"],
            "vulnerabilities": ["CVE-2021-41773"],
            "directories": ["/cgi-bin/.%2e/.%2e/bin/sh"],
            "key_data": {"severity": "critical", "service": "apache"}
        })

    class FakeLLM:
        def invoke(self, messages):
            return MockResponse()

    monkeypatch.setattr("watchtower.agents.planner.get_llm", lambda: FakeLLM())

    result = cleaner.clean(
        command="nuclei -t cves/ -u http://target.local",
        tool="nuclei",
        raw_output="[CVE-2021-41773] [http] [critical] http://target.local/cgi-bin/.%2e/.%2e/bin/sh",
        target="http://target.local",
        exit_code=0,
        duration=2.5,
    )

    assert "CVE-2021-41773" in result["clean_summary"]
    assert "80/http" in result["open_ports"]
    assert "CVE-2021-41773" in result["vulnerabilities"]
    assert "/cgi-bin/.%2e/.%2e/bin/sh" in result["directories"]


def test_cleaner_llm_fallback_on_error(monkeypatch) -> None:
    """Test that CleanerAgent cleanly falls back to generic parser if LLM fails."""
    pytest.importorskip("langchain_core")
    cleaner = CleanerAgent(use_llm=True)

    class ErrorLLM:
        def invoke(self, messages):
            raise RuntimeError("API timeout")

    monkeypatch.setattr("watchtower.agents.planner.get_llm", lambda: ErrorLLM())

    result = cleaner.clean(
        command="whatweb http://example.com",
        tool="whatweb",
        raw_output="WhatWeb report for http://example.com\nTitle: Example Domain\n",
        target="http://example.com",
        exit_code=0,
        duration=1.0,
    )

    # Should fall back to generic parser gracefully
    assert result["tool"] == "whatweb"
    assert "lines" in result["clean_summary"].lower()


def test_get_llm_groq_provider(monkeypatch) -> None:
    """Test that get_llm correctly initializes Groq with GROQ_API_KEY."""
    pytest.importorskip("langchain_core")
    pytest.importorskip("langchain_openai")
    from watchtower.agents.planner import get_llm

    monkeypatch.setenv("GROQ_API_KEY", "gsk_test_mock_key_12345")
    monkeypatch.setenv("GROQ_MODEL_NAME", "llama-3.3-70b-versatile")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("WATCHTOWER_PROVIDER", raising=False)

    llm = get_llm()
    assert llm.__class__.__name__ == "ChatOpenAI"
    assert "groq.com" in str(getattr(llm, "openai_api_base", ""))
    assert getattr(llm, "model_name", "") == "llama-3.3-70b-versatile"

