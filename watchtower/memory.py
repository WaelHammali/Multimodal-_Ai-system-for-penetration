"""
Memory Agent — Persistent storage with caching, session tracking, and RAG.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Optional sentence-transformers support
try:
    from sentence_transformers import SentenceTransformer as _ST

    _SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    _SENTENCE_TRANSFORMERS_AVAILABLE = False
    logger.debug("sentence-transformers not installed — vector search disabled")

# Optional ChromaDB support for scalable HNSW vector search
try:
    import chromadb

    _CHROMA_AVAILABLE = True
except ImportError:
    _CHROMA_AVAILABLE = False
    logger.debug("chromadb not installed — ChromaDB vector search disabled")

_DEFAULT_EMBED_MODEL = "all-MiniLM-L6-v2"

_SCHEMA_SQL = """
-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    start_time TEXT NOT NULL,
    end_time TEXT,
    target TEXT,
    total_commands INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    total_validated INTEGER DEFAULT 0,
    status TEXT DEFAULT 'active'
);

-- Observations table
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    target TEXT,
    tool TEXT,
    output TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

-- Cleaned commands table (with cache)
CREATE TABLE IF NOT EXISTS cleaned_commands (
    id TEXT PRIMARY KEY,
    command TEXT UNIQUE,
    tool TEXT,
    target TEXT,
    exit_code INTEGER,
    duration REAL,
    timestamp TEXT,
    session_id TEXT,
    structured_output TEXT,
    clean_summary TEXT,
    open_ports TEXT,
    vulnerabilities TEXT,
    directories TEXT,
    raw_output_preview TEXT,
    from_cache BOOLEAN DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_cleaned_commands_command
    ON cleaned_commands(command);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    session_id TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    target TEXT NOT NULL,
    raw_data TEXT,
    validated BOOLEAN DEFAULT 0,
    confidence INTEGER DEFAULT 0,
    evidence TEXT,
    remediation TEXT,
    status TEXT DEFAULT 'pending',
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

-- Memory (reasoning steps)
CREATE TABLE IF NOT EXISTS memory (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    session_id TEXT NOT NULL,
    agent TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    embedding BLOB,
    parent_id TEXT,
    FOREIGN KEY (parent_id) REFERENCES memory(id)
);

CREATE INDEX IF NOT EXISTS idx_memory_session
    ON memory(session_id, timestamp);
"""


class MemoryAgent:
    """
    Persistent state, command caching, and semantic search (RAG).

    Key methods:
    - create_session(target) -> str
    - close_session(session_id)
    - get_session_summary(session_id) -> Dict
    - add_cleaned_command(command, tool, target, exit_code, duration, clean_result) -> str
    - get_cached_command(command, session_id) -> Optional[Dict]
    - add_finding(finding) -> str
    - update_finding_validation(finding_id, validated, confidence, evidence, remediation)
    - add_memory(agent, action, details, parent_id=None) -> str
    - get_memory_context(session_id, limit=50) -> str
    - add_reasoning_step(agent, action, reasoning, session_id) -> str
    - semantic_search(query, limit=10) -> List[Dict] (RAG)
    - get_findings_summary(session_id, only_validated=True) -> List[Dict]
    """

    def __init__(
        self,
        db_path: str = "watchtower_memory.db",
        vector_enabled: bool = True,
        vector_db_path: str = "watchtower_vectordb",
        embed_model: str = _DEFAULT_EMBED_MODEL,
        cache_enabled: bool = True,
        cache_ttl_seconds: int = 86400,
    ) -> None:
        self.db_path = db_path
        self._vector_enabled = vector_enabled
        self._cache_enabled = cache_enabled
        self._cache_ttl = cache_ttl_seconds

        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._ensure_schema()

        self._embedder: Optional[Any] = None
        if vector_enabled and _SENTENCE_TRANSFORMERS_AVAILABLE:
            try:
                self._embedder = _ST(embed_model)
                logger.info("MemoryAgent: loaded embedding model '%s'", embed_model)
            except Exception as exc:
                logger.warning(
                    "MemoryAgent: could not load embedding model (%s) — vector search disabled",
                    exc,
                )

        # ChromaDB HNSW vector index
        self._chroma_client = None
        self._chroma_collection = None
        if vector_enabled and _CHROMA_AVAILABLE:
            try:
                self._chroma_client = chromadb.PersistentClient(path=vector_db_path)
                self._chroma_collection = self._chroma_client.get_or_create_collection(
                    name="watchtower_memories",
                    metadata={"hnsw:space": "cosine"},
                )
                logger.info("MemoryAgent: ChromaDB HNSW vector store initialised at '%s'", vector_db_path)
            except Exception as exc:
                logger.warning("MemoryAgent: ChromaDB init failed: %s", exc)

    def _ensure_schema(self) -> None:
        """Create SQLite tables."""
        self._conn.executescript(_SCHEMA_SQL)
        self._conn.commit()

    def create_session(self, target: str) -> str:
        """Create a new session record."""
        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._conn:
            self._conn.execute(
                "INSERT INTO sessions (id, start_time, target) VALUES (?, ?, ?)",
                (session_id, now, target),
            )
        logger.info("MemoryAgent: created session %s for target '%s'", session_id, target)
        return session_id

    def close_session(self, session_id: str) -> None:
        """Mark a session as completed."""
        now = datetime.now(timezone.utc).isoformat()
        with self._conn:
            self._conn.execute(
                "UPDATE sessions SET end_time = ?, status = 'closed' WHERE id = ?",
                (now, session_id),
            )
        logger.info("MemoryAgent: closed session %s", session_id)

    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """Fetch summary info for a given session."""
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
        if row is None:
            return {}
        return dict(row)

    def add_cleaned_command(
        self,
        command: str,
        tool: str,
        target: str,
        exit_code: int,
        duration: float,
        clean_result: Dict[str, Any],
        session_id: str = "",
    ) -> str:
        """Save a cleaned command to SQLite cache."""
        row_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO cleaned_commands
                  (id, command, tool, target, exit_code, duration, timestamp,
                   session_id, structured_output, clean_summary, open_ports,
                   vulnerabilities, directories, raw_output_preview, from_cache)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    row_id,
                    command,
                    tool,
                    target,
                    exit_code,
                    duration,
                    now,
                    session_id,
                    clean_result.get("structured_output", "{}"),
                    clean_result.get("clean_summary", ""),
                    clean_result.get("open_ports", ""),
                    clean_result.get("vulnerabilities", ""),
                    clean_result.get("directories", ""),
                    clean_result.get("raw_output_preview", ""),
                ),
            )
            if session_id:
                self._conn.execute(
                    "UPDATE sessions SET total_commands = total_commands + 1 WHERE id = ?",
                    (session_id,),
                )
        return row_id

    def get_cached_command(
        self,
        command: str,
        session_id: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a cached command result if available and within TTL."""
        if not self._cache_enabled:
            return None

        row = self._conn.execute(
            "SELECT * FROM cleaned_commands WHERE command = ?",
            (command,),
        ).fetchone()

        if row is None:
            return None

        if self._cache_ttl > 0:
            try:
                row_dt = datetime.fromisoformat(row["timestamp"])
                if row_dt.tzinfo is None:
                    row_dt = row_dt.replace(tzinfo=timezone.utc)
                age = (datetime.now(timezone.utc) - row_dt).total_seconds()
                if age > self._cache_ttl:
                    logger.debug("MemoryAgent: cache expired for command '%s'", command)
                    return None
            except Exception:
                pass

        logger.info("MemoryAgent: CACHE HIT for '%s'", command)
        result = dict(row)
        result["from_cache"] = True
        return result

    def add_finding(self, finding: Dict[str, Any]) -> str:
        """Store a finding in the findings table."""
        finding_id = str(uuid.uuid4())
        timestamp = finding.get("timestamp") or datetime.now(timezone.utc).isoformat()
        session_id = finding.get("session_id", "")
        finding_type = finding.get("finding_type") or finding.get("type") or "unknown"
        target = finding.get("target", "")

        with self._conn:
            self._conn.execute(
                """
                INSERT INTO findings
                  (id, timestamp, session_id, finding_type, target, raw_data, status)
                VALUES (?, ?, ?, ?, ?, ?, 'pending')
                """,
                (
                    finding_id,
                    timestamp,
                    session_id,
                    finding_type,
                    target,
                    json.dumps(finding),
                ),
            )
            if session_id:
                self._conn.execute(
                    "UPDATE sessions SET total_findings = total_findings + 1 WHERE id = ?",
                    (session_id,),
                )
        return finding_id

    def update_finding_validation(
        self,
        finding_id: str,
        validated: bool,
        confidence: int,
        evidence: str,
        remediation: str,
    ) -> None:
        """Update finding validation outcome."""
        status = "validated" if validated else "rejected"
        with self._conn:
            self._conn.execute(
                """
                UPDATE findings
                   SET validated = ?, confidence = ?, evidence = ?,
                       remediation = ?, status = ?
                 WHERE id = ?
                """,
                (int(validated), confidence, evidence, remediation, status, finding_id),
            )
            if validated:
                self._conn.execute(
                    """
                    UPDATE sessions SET total_validated = total_validated + 1
                     WHERE id = (SELECT session_id FROM findings WHERE id = ?)
                    """,
                    (finding_id,),
                )

    def get_findings_summary(
        self, session_id: str, only_validated: bool = True
    ) -> List[Dict[str, Any]]:
        """Retrieve findings for a session."""
        if only_validated:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE session_id = ? AND validated = 1 "
                "ORDER BY confidence DESC",
                (session_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE session_id = ? ORDER BY timestamp",
                (session_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def log_finding(
        self,
        target: str,
        vulnerability: str,
        details: Any,
        severity: str = "Unknown",
        cvss_score: float = 0.0,
        validated: bool = False,
    ) -> str:
        """Compatibility helper matching MemoryStore signature."""
        return self.add_finding({
            "target": target,
            "finding_type": severity,
            "title": vulnerability,
            "raw_data": json.dumps(details) if not isinstance(details, str) else details,
            "severity": severity,
            "cvss_score": cvss_score,
            "validated": validated,
            "confidence": 90 if validated else 50,
            "evidence": str(details)[:300],
            "session_id": getattr(self, "session_id", ""),
        })

    def add_memory(
        self,
        agent: str,
        action: str,
        details: Any,
        parent_id: Optional[str] = None,
        session_id: str = "",
    ) -> str:
        """Record an agent reasoning or execution step."""
        mem_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        details_str = json.dumps(details) if not isinstance(details, str) else details

        embedding_blob: Optional[bytes] = None
        if self._embedder is not None:
            try:
                text = f"{agent}: {action} — {details_str[:200]}"
                vec = self._embedder.encode(text)
                embedding_blob = vec.tobytes()
            except Exception as exc:
                logger.debug("MemoryAgent: embedding failed: %s", exc)

        with self._conn:
            self._conn.execute(
                """
                INSERT INTO memory
                  (id, timestamp, session_id, agent, action, details, embedding, parent_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mem_id,
                    now,
                    session_id,
                    agent,
                    action,
                    details_str,
                    embedding_blob,
                    parent_id,
                ),
            )

        # Store into ChromaDB for scalable HNSW vector search
        if self._chroma_collection is not None:
            try:
                self._chroma_collection.add(
                    documents=[f"{agent}: {action} — {details_str[:300]}"],
                    metadatas=[{
                        "agent": agent,
                        "action": action,
                        "session_id": session_id,
                        "timestamp": now,
                    }],
                    ids=[mem_id],
                )
            except Exception as c_exc:
                logger.debug("MemoryAgent: ChromaDB add failed: %s", c_exc)

        return mem_id

    def add_reasoning_step(
        self,
        agent: str,
        action: str,
        reasoning: str,
        session_id: str = "",
        parent_id: Optional[str] = None,
    ) -> str:
        """Helper to record agent reasoning step."""
        return self.add_memory(
            agent=agent,
            action=action,
            details={"reasoning": reasoning},
            parent_id=parent_id,
            session_id=session_id,
        )

    def log_observation(
        self,
        target: Optional[str],
        tool: Optional[str],
        output: Optional[str],
        clean_result: Optional[Dict[str, Any]] = None,
        embedding_text: Optional[str] = None,
    ) -> None:
        """Log an observation to SQLite and vector store."""
        now = datetime.now(timezone.utc).isoformat()
        with self._conn:
            self._conn.execute(
                "INSERT INTO observations (session_id, target, tool, output, created_at) VALUES (?, ?, ?, ?, ?)",
                (getattr(self, "session_id", ""), target, tool, output, now),
            )

        if self._chroma_collection is not None:
            text_to_embed = ""
            if embedding_text:
                text_to_embed = embedding_text
            elif clean_result:
                summary = clean_result.get("clean_summary", "")
                structured = clean_result.get("structured_output", "")
                text_to_embed = f"{summary} {structured}".strip()
            elif output:
                text_to_embed = output[:1000]

            if text_to_embed:
                try:
                    self._chroma_collection.add(
                        documents=[text_to_embed],
                        metadatas=[{"target": target or "", "tool": tool or "", "type": "observation"}],
                        ids=[str(uuid.uuid4())],
                    )
                except Exception as exc:
                    logger.debug("MemoryAgent: ChromaDB log_observation failed: %s", exc)

    def get_all_observations(self) -> List[Tuple]:
        """Fetch all observations ordered by created_at."""
        rows = self._conn.execute("SELECT tool, output FROM observations ORDER BY created_at").fetchall()
        return [tuple(r) for r in rows]

    def get_all_findings(self) -> List[Tuple]:
        """Fetch all findings ordered by timestamp."""
        rows = self._conn.execute("SELECT target, finding_type, raw_data FROM findings ORDER BY timestamp").fetchall()
        return [tuple(r) for r in rows]

    def get_validated_findings(self) -> List[Tuple]:
        """Fetch confirmed validated findings."""
        rows = self._conn.execute(
            "SELECT target, finding_type, raw_data, confidence FROM findings WHERE validated = 1 ORDER BY confidence DESC"
        ).fetchall()
        return [tuple(r) for r in rows]

    def get_memory_context(
        self,
        session_id: str,
        limit: int = 50,
    ) -> str:
        """Generate textual memory context for LLM prompt injection."""
        rows = self._conn.execute(
            """
            SELECT agent, action, details, timestamp
              FROM memory
             WHERE session_id = ?
             ORDER BY timestamp DESC
             LIMIT ?
            """,
            (session_id, limit),
        ).fetchall()

        if not rows:
            return ""

        lines = ["## Agent Memory Context (most recent first)"]
        for row in rows:
            detail_str = str(row["details"] or "")
            if len(detail_str) > 120:
                detail_str = detail_str[:120] + "…"
            lines.append(
                f"[{str(row['timestamp'])[:19]}] {row['agent']}: {row['action']} — {detail_str}"
            )
        return "\n".join(lines)

    def get_session_context(self, target: str, top_k: int = 5) -> str:
        """
        Build a textual context block of prior findings/observations related to target
        for injection into the Planner prompt.
        """
        results = self.semantic_search(f"pentest findings for {target}", limit=top_k)
        if not results:
            return ""
        lines = ["## Prior Scan Context (from vector memory)"]
        for r in results:
            tool = r.get("action") or r.get("agent") or "?"
            details = r.get("details", "")
            lines.append(f"- [{tool}] {str(details)[:200]}")
        return "\n".join(lines)

    def semantic_search(
        self,
        query: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Semantic RAG search over memory items.
        Queries ChromaDB HNSW vector index first for speed, with NumPy and keyword fallbacks.
        """
        # 1. High-speed ChromaDB HNSW query
        if self._chroma_collection is not None:
            try:
                res = self._chroma_collection.query(
                    query_texts=[query],
                    n_results=limit,
                )
                docs = res.get("documents", [[]])[0]
                metas = res.get("metadatas", [[]])[0]
                distances = res.get("distances", [[]])[0]
                ids = res.get("ids", [[]])[0]

                results = []
                for doc_id, doc, meta, dist in zip(ids, docs, metas, distances):
                    similarity = round(1.0 - float(dist), 4) if dist is not None else 1.0
                    results.append({
                        "id": doc_id,
                        "agent": (meta or {}).get("agent", "Agent"),
                        "action": (meta or {}).get("action", ""),
                        "details": doc,
                        "timestamp": (meta or {}).get("timestamp", ""),
                        "score": similarity,
                    })
                if results:
                    return results
            except Exception as c_exc:
                logger.debug("MemoryAgent: ChromaDB query failed (%s), falling back to embedder", c_exc)

        # 2. Local sentence-transformers + NumPy cosine similarity fallback
        if self._embedder is not None:
            try:
                import numpy as np

                query_vec = self._embedder.encode(query)
                rows = self._conn.execute(
                    "SELECT id, agent, action, details, timestamp, embedding FROM memory "
                    "WHERE embedding IS NOT NULL"
                ).fetchall()

                scored: List[Tuple[float, Dict[str, Any]]] = []
                for row in rows:
                    blob = row["embedding"]
                    if not blob:
                        continue
                    vec = np.frombuffer(blob, dtype=np.float32)
                    if vec.shape != query_vec.shape:
                        continue
                    denom = (np.linalg.norm(query_vec) * np.linalg.norm(vec) + 1e-10)
                    score = float(np.dot(query_vec, vec) / denom)
                    scored.append((score, dict(row)))

                scored.sort(key=lambda x: x[0], reverse=True)
                results = []
                for score, d in scored[:limit]:
                    d["score"] = score
                    d.pop("embedding", None)
                    results.append(d)
                return results
            except Exception as exc:
                logger.warning("MemoryAgent: vector search error (%s), fallback to keyword", exc)

        # 3. Keyword LIKE search fallback
        pattern = f"%{query}%"
        rows = self._conn.execute(
            """
            SELECT agent, action, details, timestamp
              FROM memory
             WHERE details LIKE ? OR action LIKE ?
             ORDER BY timestamp DESC
             LIMIT ?
            """,
            (pattern, pattern, limit),
        ).fetchall()
        return [{**dict(r), "score": 0.0} for r in rows]

    def close(self) -> None:
        """Close SQLite connection."""
        self._conn.close()

    def __repr__(self) -> str:
        return (
            f"<MemoryAgent db='{self.db_path}' "
            f"vector={'on' if self._embedder else 'off'} "
            f"cache={'on' if self._cache_enabled else 'off'}>"
        )
