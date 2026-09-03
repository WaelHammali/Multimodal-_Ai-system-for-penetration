"""
Enhanced memory store for Watchtower.

Provides two persistence layers:
  1. **SQLite** — structured storage for observations and findings (original)
  2. **ChromaDB** — vector embeddings for semantic search across scans (new)

Vector memory is opt-in: if chromadb is not installed or
``MEMORY_VECTOR_ENABLED=false``, all vector methods return empty results
and the rest of the framework operates normally.
"""
import json
import uuid
import sqlite3
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

# ── Optional ChromaDB import ────────────────────────────────────────────────
try:
    import chromadb
    from chromadb.config import Settings as ChromaSettings

    _CHROMA_AVAILABLE = True
except ImportError:
    _CHROMA_AVAILABLE = False
    logger.debug("chromadb not installed — vector memory disabled")


# ─────────────────────────────────────────────────────────────────────────────
# Vector Memory (ChromaDB)
# ─────────────────────────────────────────────────────────────────────────────

class VectorMemory:
    """
    Thin wrapper around a ChromaDB collection that stores and retrieves
    finding/observation text by semantic similarity.
    """

    def __init__(self, persist_directory: str = "watchtower_vectordb"):
        if not _CHROMA_AVAILABLE:
            self._client = None
            self._collection = None
            return

        try:
            self._client = chromadb.Client(
                ChromaSettings(
                    chroma_db_impl="duckdb+parquet",
                    persist_directory=persist_directory,
                    anonymized_telemetry=False,
                )
            )
            self._collection = self._client.get_or_create_collection(
                name="watchtower_findings",
                metadata={"hnsw:space": "cosine"},
            )
            logger.debug("ChromaDB vector memory initialised (%s)", persist_directory)
        except Exception as exc:
            logger.warning("ChromaDB init failed, falling back to no-op: %s", exc)
            self._client = None
            self._collection = None

    # ── Public API ───────────────────────────────────────────────────────

    @property
    def available(self) -> bool:
        return self._collection is not None

    def store_embedding(
        self,
        text: str,
        metadata: Optional[Dict[str, Any]] = None,
        doc_id: Optional[str] = None,
    ) -> None:
        """Store a text chunk with optional metadata."""
        if not self.available:
            return
        doc_id = doc_id or str(uuid.uuid4())
        meta = {k: str(v) for k, v in (metadata or {}).items()}
        try:
            self._collection.add(
                documents=[text],
                metadatas=[meta],
                ids=[doc_id],
            )
        except Exception as exc:
            logger.warning("Vector store_embedding failed: %s", exc)

    def search_similar(
        self, query: str, top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """Return the *top_k* most semantically similar stored documents."""
        if not self.available:
            return []
        try:
            results = self._collection.query(query_texts=[query], n_results=top_k)
            docs = results.get("documents", [[]])[0]
            metas = results.get("metadatas", [[]])[0]
            distances = results.get("distances", [[]])[0]
            return [
                {"text": d, "metadata": m, "distance": dist}
                for d, m, dist in zip(docs, metas, distances)
            ]
        except Exception as exc:
            logger.warning("Vector search_similar failed: %s", exc)
            return []

    def get_session_context(self, target: str, top_k: int = 5) -> str:
        """
        Build a textual context block of prior findings related to *target*.
        Intended for injection into the Planner prompt.
        """
        results = self.search_similar(f"pentest findings for {target}", top_k)
        if not results:
            return ""
        lines = ["## Prior Scan Context (from vector memory)"]
        for r in results:
            lines.append(f"- [{r['metadata'].get('tool', '?')}] {r['text'][:200]}")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# SQLite Memory Store (enhanced)
# ─────────────────────────────────────────────────────────────────────────────

class MemoryStore:
    """
    SQLite-backed structured memory.

    Enhancements over the original implementation:
      - Timestamps on every row (``created_at``)
      - ``session_id`` column to group scans
      - Integrated ``VectorMemory`` for semantic search
    """

    def __init__(
        self,
        db_path: str = "pentest_memory.db",
        session_id: Optional[str] = None,
        vector_enabled: bool = True,
        vector_db_path: str = "watchtower_vectordb",
    ):
        self.session_id = session_id or str(uuid.uuid4())
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._ensure_schema()

        # Initialise vector memory if requested
        if vector_enabled and _CHROMA_AVAILABLE:
            self.vector = VectorMemory(persist_directory=vector_db_path)
        else:
            self.vector = VectorMemory.__new__(VectorMemory)
            self.vector._client = None
            self.vector._collection = None

    def _ensure_schema(self) -> None:
        """Create tables with the enhanced schema (idempotent)."""
        self.cursor.executescript(
            """
            CREATE TABLE IF NOT EXISTS observations (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT,
                target      TEXT,
                tool        TEXT,
                output      TEXT,
                created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS findings (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id    TEXT,
                target        TEXT,
                vulnerability TEXT,
                details       TEXT,
                severity      TEXT,
                cvss_score    REAL,
                validated     INTEGER DEFAULT 0,
                created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        self.conn.commit()

    # ── Observations ─────────────────────────────────────────────────────

    def log_observation(
        self,
        target: Optional[str],
        tool: Optional[str],
        output: Optional[str],
    ) -> None:
        self.cursor.execute(
            "INSERT INTO observations (session_id, target, tool, output) VALUES (?, ?, ?, ?)",
            (self.session_id, target, tool, output),
        )
        self.conn.commit()

        # Also store in vector memory for cross-session search
        if self.vector.available and output:
            self.vector.store_embedding(
                text=output[:500],
                metadata={"target": target or "", "tool": tool or "", "type": "observation"},
            )

    # ── Findings ─────────────────────────────────────────────────────────

    def log_finding(
        self,
        target: str,
        vulnerability: str,
        details: Any,
        severity: str = "Unknown",
        cvss_score: float = 0.0,
        validated: bool = False,
    ) -> None:
        details_json = json.dumps(details) if not isinstance(details, str) else details
        self.cursor.execute(
            """INSERT INTO findings
               (session_id, target, vulnerability, details, severity, cvss_score, validated)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (self.session_id, target, vulnerability, details_json, severity, cvss_score, int(validated)),
        )
        self.conn.commit()

        # Vector memory
        if self.vector.available:
            summary = f"{vulnerability}: {json.dumps(details)[:300]}"
            self.vector.store_embedding(
                text=summary,
                metadata={
                    "target": target,
                    "severity": severity,
                    "type": "finding",
                    "validated": str(validated),
                },
            )

    # ── Queries ──────────────────────────────────────────────────────────

    def get_all_observations(self) -> List[Tuple]:
        self.cursor.execute("SELECT tool, output FROM observations ORDER BY created_at")
        return self.cursor.fetchall()

    def get_all_findings(self) -> List[Tuple]:
        self.cursor.execute(
            "SELECT target, vulnerability, details FROM findings ORDER BY created_at"
        )
        return self.cursor.fetchall()

    def get_validated_findings(self) -> List[Tuple]:
        self.cursor.execute(
            "SELECT target, vulnerability, details, severity, cvss_score "
            "FROM findings WHERE validated = 1 ORDER BY cvss_score DESC"
        )
        return self.cursor.fetchall()

    def get_session_findings(self, session_id: Optional[str] = None) -> List[Tuple]:
        sid = session_id or self.session_id
        self.cursor.execute(
            "SELECT target, vulnerability, details, severity, cvss_score "
            "FROM findings WHERE session_id = ? ORDER BY created_at",
            (sid,),
        )
        return self.cursor.fetchall()

    def get_session_context(self, target: str) -> str:
        """Return vector-memory context for a target (for Planner injection)."""
        return self.vector.get_session_context(target)

    def close(self) -> None:
        self.conn.close()


# Re-export MemoryAgent for convenience
from watchtower.memory import MemoryAgent  # noqa: E402

