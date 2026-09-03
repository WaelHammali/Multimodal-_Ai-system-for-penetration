"""
Enhanced MemoryAgent — persistent SQLite storage with optional sentence-transformer
RAG embeddings.

Provides:
  - Session lifecycle management.
  - Cleaned-command caching (exact-match TTL-aware).
  - Structured findings storage with validation state.
  - Agent reasoning memory with optional vector embeddings.
  - Semantic search (RAG) over stored memory entries.

This is a NEW, richer class that sits alongside the existing ``MemoryStore``
in ``watchtower.core.memory``.  ``MemoryStore`` continues to handle raw
observations for backward compatibility; ``MemoryAgent`` handles the new
structured pipeline data.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Optional: sentence-transformers for embeddings ────────────────────────────
try:
    from sentence_transformers import SentenceTransformer as _ST

    _SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    _SENTENCE_TRANSFORMERS_AVAILABLE = False
    logger.debug("sentence-transformers not installed — vector search disabled")

# Default embedding model
_DEFAULT_EMBED_MODEL = "all-MiniLM-L6-v2"


# ─────────────────────────────────────────────────────────────────────────────
# DDL
# ─────────────────────────────────────────────────────────────────────────────

_SCHEMA_SQL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS sessions (
    id                TEXT PRIMARY KEY,
    start_time        TEXT NOT NULL,
    end_time          TEXT,
    target            TEXT,
    total_commands    INTEGER DEFAULT 0,
    total_findings    INTEGER DEFAULT 0,
    total_validated   INTEGER DEFAULT 0,
    status            TEXT DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS cleaned_commands (
    id                  TEXT PRIMARY KEY,
    command             TEXT UNIQUE,
    tool                TEXT,
    target              TEXT,
    exit_code           INTEGER,
    duration            REAL,
    timestamp           TEXT,
    session_id          TEXT,
    structured_output   TEXT,
    clean_summary       TEXT,
    open_ports          TEXT,
    vulnerabilities     TEXT,
    directories         TEXT,
    raw_output_preview  TEXT,
    from_cache          INTEGER DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_cleaned_commands_command
    ON cleaned_commands(command);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    session_id      TEXT NOT NULL,
    finding_type    TEXT NOT NULL,
    target          TEXT NOT NULL,
    raw_data        TEXT,
    validated       INTEGER DEFAULT 0,
    confidence      INTEGER DEFAULT 0,
    evidence        TEXT,
    remediation     TEXT,
    status          TEXT DEFAULT 'pending',
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS memory (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    session_id  TEXT NOT NULL,
    agent       TEXT NOT NULL,
    action      TEXT NOT NULL,
    details     TEXT,
    embedding   BLOB,
    parent_id   TEXT,
    FOREIGN KEY (parent_id) REFERENCES memory(id)
);

CREATE INDEX IF NOT EXISTS idx_memory_session
    ON memory(session_id, timestamp);
"""


# ─────────────────────────────────────────────────────────────────────────────
# MemoryAgent
# ─────────────────────────────────────────────────────────────────────────────


class MemoryAgent:
    """
    Persistent, session-aware memory for the Watchtower agent pipeline.

    Parameters
    ----------
    db_path:
        Path to the SQLite database file. Use ``":memory:"`` for tests.
    vector_enabled:
        If *True* and ``sentence-transformers`` is installed, enable
        semantic search over stored memory entries.
    embed_model:
        HuggingFace model name for ``SentenceTransformer``.
    cache_enabled:
        If *True*, ``get_cached_command`` returns previous results.
    cache_ttl_seconds:
        Age (in seconds) after which a cached result is considered stale.
        Use ``0`` to disable TTL checking.
    """

    def __init__(
        self,
        db_path: str = "watchtower_memory.db",
        vector_enabled: bool = True,
        embed_model: str = _DEFAULT_EMBED_MODEL,
        cache_enabled: bool = True,
        cache_ttl_seconds: int = 86400,
    ) -> None:
        self._db_path = db_path
        self._cache_enabled = cache_enabled
        self._cache_ttl = cache_ttl_seconds

        # SQLite connection (check_same_thread=False for multi-threaded agents)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._ensure_schema()

        # Sentence-transformer embedder
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

    # ── Schema ───────────────────────────────────────────────────────────────

    def _ensure_schema(self) -> None:
        """Create tables if they don't exist (idempotent)."""
        self._conn.executescript(_SCHEMA_SQL)
        self._conn.commit()

    # ── Session lifecycle ─────────────────────────────────────────────────────

    def create_session(self, target: str) -> str:
        """
        Open a new scanning session and return its UUID.

        Parameters
        ----------
        target:
            The scan target (URL or IP).

        Returns
        -------
        str
            The new session UUID.
        """
        session_id = str(uuid.uuid4())
        now = _utcnow()
        with self._conn:
            self._conn.execute(
                "INSERT INTO sessions (id, start_time, target) VALUES (?, ?, ?)",
                (session_id, now, target),
            )
        logger.info("MemoryAgent: created session %s for target '%s'", session_id, target)
        return session_id

    def close_session(self, session_id: str) -> None:
        """
        Mark a session as closed with an end timestamp.

        Parameters
        ----------
        session_id:
            The session UUID to close.
        """
        with self._conn:
            self._conn.execute(
                "UPDATE sessions SET end_time = ?, status = 'closed' WHERE id = ?",
                (_utcnow(), session_id),
            )
        logger.info("MemoryAgent: closed session %s", session_id)

    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """
        Return a summary dict for the given session.

        Parameters
        ----------
        session_id:
            Session UUID.

        Returns
        -------
        dict
            Keys: ``id``, ``start_time``, ``end_time``, ``target``,
            ``total_commands``, ``total_findings``, ``total_validated``,
            ``status``.
        """
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
        if row is None:
            return {}
        return dict(row)

    # ── Cleaned-command cache ─────────────────────────────────────────────────

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
        """
        Persist a cleaned command result and return its UUID.

        Parameters
        ----------
        command:
            Full command string (used as cache key).
        tool:
            Tool name.
        target:
            Scan target.
        exit_code:
            Process exit code.
        duration:
            Execution time in seconds.
        clean_result:
            Dict returned by ``CleanerAgent.clean()``.
        session_id:
            Associated session UUID.

        Returns
        -------
        str
            Row UUID.
        """
        row_id = str(uuid.uuid4())
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
                    _utcnow(),
                    session_id,
                    clean_result.get("structured_output", "{}"),
                    clean_result.get("clean_summary", ""),
                    clean_result.get("open_ports", ""),
                    clean_result.get("vulnerabilities", ""),
                    clean_result.get("directories", ""),
                    clean_result.get("raw_output_preview", ""),
                ),
            )
            # Update session counter
            if session_id:
                self._conn.execute(
                    "UPDATE sessions SET total_commands = total_commands + 1 WHERE id = ?",
                    (session_id,),
                )
        logger.debug("MemoryAgent: stored cleaned command '%s...'", command[:60])
        return row_id

    def get_cached_command(
        self,
        command: str,
        session_id: str = "",
    ) -> Optional[Dict[str, Any]]:
        """
        Look up a previously executed command in the cache.

        Parameters
        ----------
        command:
            Exact command string to look up.
        session_id:
            If provided, restrict search to this session (optional).

        Returns
        -------
        dict or None
            Cached result dict if found and not stale; *None* otherwise.
        """
        if not self._cache_enabled:
            return None

        row = self._conn.execute(
            "SELECT * FROM cleaned_commands WHERE command = ?",
            (command,),
        ).fetchone()

        if row is None:
            return None

        # TTL check
        if self._cache_ttl > 0:
            row_time = _parse_utc(row["timestamp"])
            age = (_now_ts() - row_time)
            if age > self._cache_ttl:
                logger.debug("MemoryAgent: cache TTL expired for '%s...'", command[:50])
                return None

        logger.info("MemoryAgent: CACHE HIT for '%s...'", command[:60])
        result = dict(row)
        result["from_cache"] = True
        return result

    # ── Findings ─────────────────────────────────────────────────────────────

    def add_finding(self, finding: Dict[str, Any]) -> str:
        """
        Store a new finding and return its UUID.

        Parameters
        ----------
        finding:
            Dict with keys ``finding_type``, ``target``, ``session_id``,
            ``timestamp`` (optional), and any other metadata stored in
            ``raw_data``.

        Returns
        -------
        str
            Finding UUID.
        """
        finding_id = str(uuid.uuid4())
        timestamp = finding.get("timestamp") or _utcnow()
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

        logger.debug("MemoryAgent: added finding '%s' (%s)", finding_type, finding_id)
        return finding_id

    def update_finding_validation(
        self,
        finding_id: str,
        validated: bool,
        confidence: int,
        evidence: str,
        remediation: str,
    ) -> None:
        """
        Update the validation result for an existing finding.

        Parameters
        ----------
        finding_id:
            Finding UUID.
        validated:
            Whether the finding was confirmed.
        confidence:
            Confidence score 0-100.
        evidence:
            Supporting evidence text.
        remediation:
            Remediation recommendation.
        """
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
                # Try to increment session counter (session_id retrieved by sub-query)
                self._conn.execute(
                    """
                    UPDATE sessions SET total_validated = total_validated + 1
                     WHERE id = (SELECT session_id FROM findings WHERE id = ?)
                    """,
                    (finding_id,),
                )
        logger.debug(
            "MemoryAgent: updated finding %s → validated=%s confidence=%d",
            finding_id, validated, confidence,
        )

    def get_findings_summary(
        self, session_id: str, only_validated: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Return findings for a session, optionally only validated ones.

        Parameters
        ----------
        session_id:
            Session UUID to filter by.
        only_validated:
            If *True*, only return confirmed findings.

        Returns
        -------
        list[dict]
        """
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

    # ── Reasoning memory ──────────────────────────────────────────────────────

    def add_memory(
        self,
        agent: str,
        action: str,
        details: Any,
        session_id: str = "",
        parent_id: Optional[str] = None,
    ) -> str:
        """
        Store an agent reasoning/action step and return its UUID.

        Parameters
        ----------
        agent:
            Agent name (e.g. ``"Planner"``, ``"Analyst"``).
        action:
            Short description of what the agent did.
        details:
            Arbitrary data (dict, str, etc.) — will be JSON-serialised.
        session_id:
            Associated session UUID.
        parent_id:
            UUID of the parent memory entry (for chaining).

        Returns
        -------
        str
            Memory entry UUID.
        """
        mem_id = str(uuid.uuid4())
        details_str = json.dumps(details) if not isinstance(details, str) else details

        # Optionally generate embedding
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
                    _utcnow(),
                    session_id,
                    agent,
                    action,
                    details_str,
                    embedding_blob,
                    parent_id,
                ),
            )
        return mem_id

    # Convenience alias used in analyst_node
    def add_reasoning_step(
        self,
        agent: str,
        action: str,
        reasoning: str,
        session_id: str = "",
        parent_id: Optional[str] = None,
    ) -> str:
        """Convenience wrapper for :meth:`add_memory` using reasoning text."""
        return self.add_memory(
            agent=agent,
            action=action,
            details={"reasoning": reasoning},
            session_id=session_id,
            parent_id=parent_id,
        )

    def get_memory_context(
        self,
        session_id: str,
        limit: int = 50,
    ) -> str:
        """
        Return a formatted block of recent memory entries for prompt injection.

        Parameters
        ----------
        session_id:
            Session UUID to retrieve memory for.
        limit:
            Maximum number of entries to include.

        Returns
        -------
        str
            Multi-line context block suitable for LLM injection.
        """
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
            detail_preview = _truncate(row["details"] or "", 120)
            lines.append(
                f"[{row['timestamp'][:19]}] {row['agent']}: {row['action']} — {detail_preview}"
            )
        return "\n".join(lines)

    # ── Semantic search (RAG) ─────────────────────────────────────────────────

    def semantic_search(
        self,
        query: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Find memory entries semantically similar to *query*.

        Falls back to a keyword LIKE search when embedder is unavailable.

        Parameters
        ----------
        query:
            Free-text query.
        limit:
            Maximum results to return.

        Returns
        -------
        list[dict]
            Each dict has keys ``agent``, ``action``, ``details``,
            ``timestamp``, and ``score`` (cosine similarity or 0 for keyword).
        """
        if self._embedder is not None:
            return self._semantic_search_vector(query, limit)
        return self._semantic_search_keyword(query, limit)

    def _semantic_search_vector(self, query: str, limit: int) -> List[Dict[str, Any]]:
        """Vector-based semantic search using stored embeddings."""
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
                score = float(
                    np.dot(query_vec, vec)
                    / (np.linalg.norm(query_vec) * np.linalg.norm(vec) + 1e-10)
                )
                scored.append((score, dict(row)))

            scored.sort(key=lambda x: x[0], reverse=True)
            results = []
            for score, d in scored[:limit]:
                d["score"] = score
                d.pop("embedding", None)
                results.append(d)
            return results

        except Exception as exc:
            logger.warning("MemoryAgent: vector search failed (%s), falling back", exc)
            return self._semantic_search_keyword(query, limit)

    def _semantic_search_keyword(self, query: str, limit: int) -> List[Dict[str, Any]]:
        """Keyword LIKE fallback for semantic search."""
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

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<MemoryAgent db='{self._db_path}' "
            f"vector={'on' if self._embedder else 'off'} "
            f"cache={'on' if self._cache_enabled else 'off'}>"
        )


# ── Utilities ─────────────────────────────────────────────────────────────────


def _utcnow() -> str:
    """Return current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _now_ts() -> float:
    """Return current UTC time as a POSIX timestamp."""
    return datetime.now(timezone.utc).timestamp()


def _parse_utc(s: str) -> float:
    """Parse an ISO-8601 string to a POSIX timestamp (best-effort)."""
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return 0.0


def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + "…"
