# SPDX-License-Identifier: Apache-2.0
"""
MemoryStore — SQLite-backed agent memory with provenance metadata.

Every write carries trust tier, source, and session ID. Values written
from DELEGATED, EXTERNAL, or UNTRUSTED sources are sanitized before
storage — this is the primary defence against MINJA-style memory
poisoning attacks.
"""

import asyncio
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from kitelogik.tether.sanitizer import sanitize_tool_output

from .models import MemoryEntry, TrustTier

_CREATE_TABLE = """
                CREATE TABLE IF NOT EXISTS memory_entries
                (
                    key
                    TEXT
                    PRIMARY
                    KEY,
                    value
                    TEXT
                    NOT
                    NULL,
                    trust_tier
                    TEXT
                    NOT
                    NULL,
                    source
                    TEXT
                    NOT
                    NULL,
                    session_id
                    TEXT
                    NOT
                    NULL,
                    created_at
                    TEXT
                    NOT
                    NULL,
                    updated_at
                    TEXT
                    NOT
                    NULL,
                    sanitized
                    INTEGER
                    NOT
                    NULL
                    DEFAULT
                    0
                ) \
                """

# Tiers where values must be sanitized before storage
_SANITIZE_TIERS = {TrustTier.DELEGATED, TrustTier.EXTERNAL, TrustTier.UNTRUSTED}


def _row_to_entry(row: tuple) -> MemoryEntry:
    key, value, trust_tier, source, session_id, created_at, updated_at, sanitized = row
    return MemoryEntry(
        key=key,
        value=value,
        trust_tier=TrustTier(trust_tier),
        source=source,
        session_id=session_id,
        created_at=datetime.fromisoformat(created_at),
        updated_at=datetime.fromisoformat(updated_at),
        sanitized=bool(sanitized),
    )


class MemoryStore:
    """
    Async agent memory store with provenance tracking.

    Reads always return the entry's trust tier so the agent (and the session
    layer) can decide how much weight to give to a recalled value.

    Writes from DELEGATED/EXTERNAL/UNTRUSTED sources are sanitized automatically.

    Parameters
    ----------
    db_path : str
            Path to the SQLite database file. Defaults to ``"memory.db"``.
    """

    def __init__(self, db_path: str = "memory.db") -> None:
        self._db_path = str(Path(db_path).resolve())

    # ── sync helpers ───────────────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _sync_setup(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(_CREATE_TABLE)
            conn.commit()

    def _sync_write(
        self,
        key: str,
        value: str,
        trust_tier: TrustTier,
        source: str,
        session_id: str,
        sanitized: bool,
    ) -> MemoryEntry:
        now = datetime.now(UTC).isoformat()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT created_at FROM memory_entries WHERE key = ?", (key,)
            ).fetchone()
            created_at = existing["created_at"] if existing else now

            conn.execute(
                """
                INSERT INTO memory_entries
                    (key, value, trust_tier, source, session_id, created_at, updated_at, sanitized)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(key) DO
                UPDATE SET
                    value = excluded.value,
                    trust_tier = excluded.trust_tier,
                    source = excluded.source,
                    session_id = excluded.session_id,
                    updated_at = excluded.updated_at,
                    sanitized = excluded.sanitized
				""",
                (key, value, trust_tier.value, source, session_id, created_at, now, int(sanitized)),
            )
            conn.commit()

        return MemoryEntry(
            key=key,
            value=value,
            trust_tier=trust_tier,
            source=source,
            session_id=session_id,
            created_at=datetime.fromisoformat(created_at),
            updated_at=datetime.fromisoformat(now),
            sanitized=sanitized,
        )

    def _sync_read(self, key: str) -> MemoryEntry | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM memory_entries WHERE key = ?", (key,)).fetchone()
        return _row_to_entry(tuple(row)) if row else None

    def _sync_list_keys(self, session_id: str | None) -> list[str]:
        with self._connect() as conn:
            if session_id:
                rows = conn.execute(
                    "SELECT key FROM memory_entries WHERE session_id = ? ORDER BY updated_at DESC",
                    (session_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT key FROM memory_entries ORDER BY updated_at DESC"
                ).fetchall()
        return [r[0] for r in rows]

    # ── public async API ───────────────────────────────────────────────────

    async def setup(self) -> None:
        await asyncio.to_thread(self._sync_setup)

    async def write(
        self,
        key: str,
        value: str,
        trust_tier: TrustTier,
        source: str,
        session_id: str,
    ) -> MemoryEntry:
        """
        Write a value to memory.

        Values from DELEGATED, EXTERNAL, or UNTRUSTED tiers are sanitized
        before storage as a defence against memory poisoning.

        Parameters
        ----------
        key : str
                Unique identifier for this memory entry.
        value : str
                The value to store.
        trust_tier : ``TrustTier``
                Trust level of the data source.
        source : str
                Origin descriptor, e.g. ``"mcp:mock-server"``.
        session_id : str
                The agent session performing the write.

        Returns
        -------
        ``MemoryEntry``
                The persisted entry, including sanitization metadata.
        """
        sanitized = False
        if trust_tier in _SANITIZE_TIERS:
            result = sanitize_tool_output(value)
            value = result.content
            sanitized = result.was_modified

        return await asyncio.to_thread(
            self._sync_write, key, value, trust_tier, source, session_id, sanitized
        )

    async def read(self, key: str) -> MemoryEntry | None:
        return await asyncio.to_thread(self._sync_read, key)

    async def list_keys(self, session_id: str | None = None) -> list[str]:
        return await asyncio.to_thread(self._sync_list_keys, session_id)
