![Watchtower Banner](assets/imgs/watchtower.png)

<div align="center">

# 🏰 Watchtower
### AI-Powered Penetration Testing Automation Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-brightgreen.svg?style=flat-square&logo=python)](https://www.python.org/downloads/)
[![LangGraph](https://img.shields.io/badge/Orchestration-LangGraph-orange.svg?style=flat-square)](https://langchain-ai.github.io/langgraph/)
[![Groq](https://img.shields.io/badge/Brain-Groq%20%7C%20OpenAI%20%7C%20Gemini-purple.svg?style=flat-square)]()
[![ChromaDB](https://img.shields.io/badge/Memory-ChromaDB%20HNSW-teal.svg?style=flat-square)]()

**Watchtower** is a multi-agent AI framework that automates the full penetration testing lifecycle — from initial reconnaissance to validated vulnerability reports — using a team of five specialized agents orchestrated by LangGraph.

> ⚠️ **For authorized security testing and educational use only.** You are responsible for obtaining explicit written permission before testing any system.

</div>

---

## 📖 Table of Contents

- [How It Works](#-how-it-works)
- [Agent Architecture](#-agent-architecture)
- [Tool Arsenal](#-tool-arsenal)
- [Memory & RAG System](#-memory--rag-system)
- [Quick Start](#-quick-start)
- [Configuration Reference](#️-configuration-reference)
- [Running the Framework](#-running-the-framework)
- [Generating Reports](#-generating-reports)
- [LLM Providers](#-llm-providers)
- [Roadmap](#️-roadmap)
- [FAQ & Troubleshooting](#-faq--troubleshooting)
- [Legal Disclaimer](#-legal-disclaimer)

---

## ⚙️ How It Works

Watchtower models a penetration test as a **state machine**. Each scan session moves through a pipeline of five specialized agents. Every observation, cleaned output, and validated finding is stored in a persistent SQLite database and indexed in a ChromaDB vector store — enabling semantic search across previous scans (RAG).

```
    ┌────────────────────────────────────────────────────────────┐
    │                   Target URL / IP                          │
    └────────────────────────┬───────────────────────────────────┘
                             ▼
                       ┌──────────┐
                       │ Planner  │◄──────────────────────┐
                       └────┬─────┘                       │
                            │ strategy + tool list        │
                            ▼                             │
                       ┌──────────┐                       │
                       │  Worker  │  (runs CLI tools)     │
                       └────┬─────┘                       │
                            │ raw stdout / stderr         │
                            ▼                             │
                       ┌──────────┐                       │
                       │ Cleaner  │  (LLM + regex)        │
                       └────┬─────┘                       │
                            │ structured JSON             │
                            ▼                             │
                       ┌──────────┐                       │
                       │ Analyst  │  (finds vulns)        │
                       └────┬─────┘                       │
                            │ findings list               │
                            ▼                             │
                       ┌──────────┐                       │
                       │Validator │  (LLM verification)   │
                       └────┬─────┘                       │
              ┌─────────────┼──────────────┬──────────────┘
              ▼             ▼              ▼
          Reporter       Discard       Re-analyze
        (confirmed)  (false positive) (inconclusive)
```

---

## 🤖 Agent Architecture

Watchtower uses **five specialized agents**, each with a distinct role in the pipeline:

| Agent | Role | Key Behaviour |
|-------|------|---------------|
| **Planner** | Strategist | Analyzes target + prior memory context to decide which tools to run next and in what order |
| **Worker** | Executor | Runs CLI security tools via subprocess; captures stdout/stderr; passes raw output downstream |
| **Cleaner** | Structurer | Pre-filters noise (404 floods, banners, ANSI codes) then applies tool-specific regex parsers **and** an LLM (Groq) to produce clean structured JSON |
| **Analyst** | Analyst | Reads structured output; applies security domain knowledge to identify vulnerabilities; produces ranked finding objects |
| **Validator** | Verifier | Independently re-examines each finding using an LLM; accepts, rejects, or flags inconclusive results with a confidence score |

### Agent Flow Details

- **Planner → Worker**: The planner selects the next tool based on what's been seen so far and injects prior scan context from the RAG vector store.
- **Worker → Cleaner**: Raw terminal output is handed to the Cleaner, which strips noise with `_prefilter_output()` before parsing.
- **Cleaner → Analyst**: Structured JSON (ports, vulns, directories, key data) flows into the analyst.
- **Analyst → Validator**: Every finding is submitted to the Validator for LLM-backed second-opinion verification.
- **Validator routing**:
  - `confirmed` → Reporter (saved to DB, included in report)
  - `false_positive` → Discard (suppressed)
  - `inconclusive` → Analyst (re-analyzed)
  - `error` → Planner (re-planned)

---

## 🛠️ Tool Arsenal

Watchtower integrates **23 security tools** across 7 categories. The interactive CLI auto-detects which are installed on your `PATH` and lets you toggle them before each scan.

| Category | Tools |
|----------|-------|
| 🌐 **Network Scanning** | `nmap`, `masscan` |
| 🔍 **Web Reconnaissance** | `httpx`, `whatweb`, `wafw00f` |
| 🌍 **Subdomain Enumeration** | `subfinder`, `amass`, `dnsrecon` |
| 🐛 **Vulnerability Scanning** | `nuclei`, `nikto`, `sqlmap`, `wpscan`, `retire.js` |
| 🔐 **SSL/TLS Analysis** | `testssl.sh`, `sslyze` |
| 📁 **Content Discovery** | `gobuster`, `ffuf`, `arjun`, `kiterunner` |
| ⚔️ **Security Analysis** | `xsstrike`, `gitleaks`, `cmseek`, `dalfox` |

Install all tools at once:
```bash
chmod +x install_tools.sh && ./install_tools.sh
```

---

## 🧠 Memory & RAG System

Watchtower has a two-tier persistent memory system that grows smarter with every scan:

### SQLite (Structured Storage)
- **`sessions`** — tracks each scan session (target, timestamps, counters)
- **`observations`** — raw tool outputs per session
- **`cleaned_commands`** — cached structured results with command deduplication (TTL: 24h)
- **`findings`** — vulnerability records with validation status, confidence score, evidence, remediation
- **`memory`** — agent reasoning steps with vector embeddings (BLOB)

All tables live in a single unified database: **`watchtower_memory.db`**

### ChromaDB (Vector / Semantic Search)
- Uses **HNSW cosine similarity** for fast nearest-neighbour search across all past findings and observations.
- The Planner injects relevant prior scan context into its prompt automatically — the longer you use Watchtower, the smarter it gets.
- Observations are embedded using the **clean structured summary**, not raw noisy output.
- Falls back to `sentence-transformers` NumPy cosine, then SQLite `LIKE` keyword search if ChromaDB is unavailable.

```
Memory Search Priority:
  ChromaDB HNSW  →  sentence-transformers  →  SQLite LIKE
  (fastest, best)    (accurate, local)         (always works)
```

---

## 🚀 Quick Start

### Prerequisites

- **OS**: Linux or macOS (Windows via WSL2)
- **Python**: 3.11+
- **LLM API Key**: Groq (recommended, free tier available), OpenAI, Gemini, or OpenRouter

### 1. Clone & Install

```bash
git clone https://github.com/WaelHammali/Multimodal-_Ai-system-for-penetration.git
cd Multimodal-_Ai-system-for-penetration

python -m venv venv
source venv/bin/activate         # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### 2. Install Security Tools

```bash
chmod +x install_tools.sh && ./install_tools.sh
```

### 3. Configure Environment

```bash
cp .env.example .env
```

Open `.env` and fill in **at least one** LLM provider. **Groq is recommended** (free tier, very fast):

```env
# ── Recommended: Groq (free & fast) ───────────────────────────────
GROQ_API_KEY="gsk_your_groq_key_here"
GROQ_MODEL_NAME="llama-3.3-70b-versatile"

# ── Cleaner: use Groq LLM to clean tool output ────────────────────
CLEANER_USE_LLM=true
```

Get a free Groq API key at: https://console.groq.com

### 4. Run Your First Scan

```bash
python -m watchtower.main -t https://your-target.com
```

An interactive checkbox will appear — select which tools to allow, then press `Enter` to start.

---

## ⚙️ Configuration Reference

All settings are controlled via `.env`. Here is the full reference:

```env
# ── LLM Providers (fill at least one) ─────────────────────────────
GROQ_API_KEY=""
GROQ_MODEL_NAME="llama-3.3-70b-versatile"      # or llama-3.1-8b-instant

OPENAI_API_KEY=""
OPENAI_MODEL_NAME="gpt-4-turbo"

GEMINI_API_KEY=""
GEMINI_MODEL_NAME="gemini-1.5-pro"

OPENROUTER_API_KEY=""
OPENROUTER_MODEL_NAME="anthropic/claude-3-opus"

# ── Custom / Self-Hosted Provider ─────────────────────────────────
# WATCHTOWER_PROVIDER="https://api.custom.com/v1"
# WATCHTOWER_MODEL="custom-model-v1"
# WATCHTOWER_APIKEY_NAME="MY_CUSTOM_KEY"
# MY_CUSTOM_KEY="sk-..."

# ── Validator ──────────────────────────────────────────────────────
VALIDATOR_ENABLED=true
VALIDATOR_TIMEOUT=120
VALIDATOR_CONFIDENCE_THRESHOLD=70        # 0–100; findings below this are rejected

# ── Memory ────────────────────────────────────────────────────────
MEMORY_ENABLED=true
MEMORY_DB_PATH=watchtower_memory.db      # unified SQLite file
MEMORY_VECTOR_ENABLED=true
MEMORY_VECTOR_DB_PATH=watchtower_vectordb
MEMORY_CACHE_ENABLED=true
MEMORY_CACHE_TTL=86400                   # seconds (24h)
MEMORY_EMBED_MODEL=all-MiniLM-L6-v2

# ── Cleaner ───────────────────────────────────────────────────────
CLEANER_ENABLED=true
CLEANER_USE_LLM=true                     # use Groq/LLM for unstructured tool output
CLEANER_STORE_RAW=false
```

---

## ▶️ Running the Framework

### Standard Scan (Interactive)

```bash
python -m watchtower.main -t https://target.com
```

Use `<Space>` to toggle tools, `<Enter>` to confirm.

### Headless / CI Mode

```bash
python -m watchtower.main -t https://target.com --skip-ask-tools
```

### Authenticated Scan

```bash
# With session cookie
python -m watchtower.main -t https://target.com --cookie "session=abc123"

# With custom headers
python -m watchtower.main -t https://api.target.com \
  --cookie "session=abc123" \
  --header "X-API-Key: secret" \
  --header "Authorization: Bearer token"
```

### Custom LLM Provider (CLI override)

```bash
python -m watchtower.main -t https://target.com \
  --provider=https://api.dgrid.ai/api/v1 \
  --model=anthropic/claude-opus-4.5 \
  --apikey "DGRID_API_KEY"
```

> **Note:** `--apikey` takes the **variable name** from your `.env` file (e.g. `DGRID_API_KEY`), not the raw key value. This keeps secrets out of your bash history.

### Control Iteration Depth

```bash
python -m watchtower.main -t https://target.com --max-iterations 50
```

---

## 📊 Generating Reports

All findings are persisted automatically in `watchtower_memory.db`. Generate a professional report without re-running the scan:

```bash
# PDF report
python -m watchtower.main --report report.pdf

# HTML report
python -m watchtower.main --report report --report-format html

# Markdown report
python -m watchtower.main --report report --report-format markdown

# All formats at once
python -m watchtower.main --report report --report-format all
```

<img width="792" height="738" alt="Sample PDF Report" src="https://github.com/user-attachments/assets/7264ec48-b48f-4419-8f44-5cc7ab821aaa" />

---

## 🔌 LLM Providers

Watchtower supports virtually any LLM provider via LangChain and LiteLLM. Provider resolution order at startup:

```
Groq → OpenAI → Gemini → OpenRouter → Custom URL → (local fallback)
```

**Fully tested providers:**

| Provider | Setup Variable | Notes |
|----------|---------------|-------|
| **Groq** ⭐ | `GROQ_API_KEY` | Recommended — free tier, very fast |
| OpenAI | `OPENAI_API_KEY` | Best structured output support |
| Google Gemini | `GEMINI_API_KEY` | Good reasoning, large context |
| OpenRouter | `OPENROUTER_API_KEY` | 100+ models via one key |
| Custom HTTP | `WATCHTOWER_PROVIDER` | Any OpenAI-compatible endpoint |

**Other supported providers** (via LiteLLM): Anthropic, Amazon Bedrock, Mistral, Moonshot AI, MiniMax, and [many more](https://docs.litellm.ai/docs/providers).

---

## 🗺️ Roadmap

- [x] 5-agent LangGraph architecture (Planner, Worker, Cleaner, Analyst, Validator)
- [x] 23-tool security arsenal with auto-detection
- [x] Groq as first-class LLM brain provider
- [x] LLM-powered Cleaner Agent with structured extraction
- [x] Cleaner pre-filtering (`_prefilter_output`) — noise removal before LLM
- [x] Unified SQLite database (`watchtower_memory.db`) — no more split-brain storage
- [x] ChromaDB HNSW vector index for semantic RAG search
- [x] Rich embedding quality — embed `clean_summary + structured JSON`
- [x] ValidatorAgent with LLM-powered second-opinion verification
- [x] Multi-format reports: PDF, HTML, Markdown
- [x] Authenticated pentesting (cookies / custom headers)
- [x] Command result caching (TTL-based deduplication)
- [ ] Business logic analysis agent
- [ ] Web UI / dashboard
- [ ] Plugin system for custom tool wrappers
- [ ] GitHub Actions integration for CI/CD security scanning

---

## 📝 Important Notes

- **API Costs**: The multi-agent loop is token-intensive. Use Groq (free tier) or set `--max-iterations` to control costs.
- **False Positives**: The Validator reduces — but does not eliminate — false positives. Always manually verify critical findings before reporting them.
- **Noisy Tools**: `masscan`, `ffuf`, and `gobuster` can generate enormous output. The Cleaner's pre-filter significantly reduces what reaches the LLM, but very large scopes can still be slow.
- **Caching**: Identical commands within a 24-hour window return cached results instantly (configurable via `MEMORY_CACHE_TTL`).

---

## ❓ FAQ & Troubleshooting

### `ModuleNotFoundError: No module named 'langchain_core'`
Your virtual environment is missing LangChain. Run:
```bash
pip install -r requirements.txt
```

### `model does not support feature: structured-outputs`
Switch to a fully supported model. Recommended options:
- `GROQ_MODEL_NAME="llama-3.3-70b-versatile"` (free)
- `OPENROUTER_MODEL_NAME="anthropic/claude-3.5-sonnet"`
- `OPENAI_MODEL_NAME="gpt-4o"`

### `429 Too Many Requests`
You are on a free/rate-limited model tier. Either:
- Wait for the rate limit window to reset, or
- Switch to a different model or provider.

### ChromaDB crashes on startup
Ensure you have chromadb ≥ 0.4 installed. The old `chroma_db_impl` flag is no longer supported — Watchtower uses the modern `PersistentClient` API:
```bash
pip install --upgrade chromadb
```

### The scan finishes too quickly with no findings
Try increasing the iteration limit:
```bash
python -m watchtower.main -t https://target.com --max-iterations 50
```
Also verify that your tools are installed (`nmap --version`, `httpx --version`, etc.).

---

## ⚖️ Legal Disclaimer

**Watchtower is designed exclusively for authorized security testing and educational purposes.**

- ✅ **Legal use:** Authorized penetration testing, security research, CTF competitions, educational labs.
- ❌ **Illegal use:** Unauthorized access, malicious activities, attacking systems without explicit permission.

Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (CFAA), GDPR, and equivalent international legislation. You are fully responsible for ensuring you have explicit written permission before testing any system.

By using Watchtower, you agree to these terms. The developers assume **zero liability** for misuse of this tool.

---

## 📄 License

This project is licensed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

---

## 🙏 Acknowledgements

A sincere thank you to the open-source security community and every developer who built and maintains the underlying CLI tools that power Watchtower's worker engine. This framework would not exist without `nmap`, `nuclei`, `ffuf`, `gobuster`, `sqlmap`, and the dozens of other tools it orchestrates.

Built with ❤️ using [LangGraph](https://langchain-ai.github.io/langgraph/), [ChromaDB](https://www.trychroma.com/), [Groq](https://groq.com/), and the Python security tooling ecosystem.
