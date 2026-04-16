# SPDX-License-Identifier: Apache-2.0
"""
AuditStore — immutable, append-only audit log for every tool call.

Every tool call that passes through the policy gate is recorded with:
  - The full PolicyDecision (allow/deny/risk_tier/requires_hitl)
  - The Rego policy version evaluated (hash of the policies/ directory)
  - The SessionContext (delegation depth, token_id, user_role)
  - Any HITL action_id and who decided it

Records are structurally immutable: SQLite triggers reject UPDATE and DELETE.
The only permitted operation after write is SELECT.

Use export_session() to produce a self-contained compliance report for
a single session — every tool call, its authorization chain, and any
human approval decisions, with a SHA-256 integrity hash.
"""

import asyncio
import hashlib
import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_POLICIES_DIR = Path(__file__).parent.parent / "policies"

_CREATE_TABLE = """
                CREATE TABLE IF NOT EXISTS audit_log
                (
                    id
                    TEXT
                    PRIMARY
                    KEY,
                    session_id
                    TEXT
                    NOT
                    NULL,
                    tool_name
                    TEXT
                    NOT
                    NULL,
                    args_json
                    TEXT
                    NOT
                    NULL,
                    policy_decision_json
                    TEXT
                    NOT
                    NULL,
                    policy_version
                    TEXT,
                    hitl_action_id
                    TEXT,
                    hitl_decided_by
                    TEXT,
                    outcome
                    TEXT
                    NOT
                    NULL,
                    timestamp
                    TEXT
                    NOT
                    NULL,
                    context_json
                    TEXT
                    NOT
                    NULL
                ) \
                """

_PREVENT_UPDATE = """
                  CREATE TRIGGER IF NOT EXISTS prevent_audit_update
BEFORE
                  UPDATE ON audit_log
                  BEGIN
                  SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE is not permitted');
                  END \
                  """

_PREVENT_DELETE = """
                  CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
BEFORE
                  DELETE
                  ON audit_log
                  BEGIN
                  SELECT RAISE(ABORT, 'audit_log is append-only: DELETE is not permitted');
                  END \
                  """


def _compute_policy_version(policies_dir: Path = _POLICIES_DIR) -> str:
    """
    SHA-256 hash of every non-test Rego file in the policies directory.
    Sorted by filename for determinism. Truncated to 16 hex chars for readability.
    """
    h = hashlib.sha256()
    for path in sorted(policies_dir.glob("*.rego")):
        if "_test" in path.stem:
            continue
        h.update(path.name.encode())
        h.update(path.read_bytes())
    return h.hexdigest()[:16]


@dataclass
class AuditRecord:
    id: str
    session_id: str
    tool_name: str
    args: dict
    policy_decision: dict
    policy_version: str | None
    hitl_action_id: str | None
    hitl_decided_by: str | None
    outcome: str
    timestamp: str
    context: dict
    # Denormalised from context for easy querying — no schema change required
    parent_session_id: str = ""
    delegation_depth: int = 0


class AuditStore:
    """
      SQLite-backed, append-only audit log.

      Outcomes written per tool call:
    "allowed"       — gate allowed, tool was executed
    "blocked"       — hard deny (security or delegation policy)
    "soft_denied"   — policy did not allow but no hard block (no HITL queue)
    "hitl_queued"   — action queued for human review
    "hitl_approved" — human approved; tool was subsequently executed
    "hitl_denied"   — human denied
    "hitl_timeout"  — no decision received within the timeout window
    """

    def __init__(self, db_path: str = "audit.db") -> None:
        self._db_path = db_path
        self._policy_version = _compute_policy_version()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _sync_setup(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(_CREATE_TABLE)
            conn.execute(_PREVENT_UPDATE)
            conn.execute(_PREVENT_DELETE)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_outcome ON audit_log(outcome)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp DESC)")
            conn.commit()

    async def setup(self) -> None:
        await asyncio.to_thread(self._sync_setup)

    def _sync_record(
        self,
        session_id: str,
        tool_name: str,
        args: dict,
        decision_json: str,
        context_json: str,
        outcome: str,
        hitl_action_id: str | None,
        hitl_decided_by: str | None,
    ) -> str:
        record_id = uuid.uuid4().hex
        timestamp = datetime.now(UTC).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_log
                (id, session_id, tool_name, args_json, policy_decision_json,
                 policy_version, hitl_action_id, hitl_decided_by,
                 outcome, timestamp, context_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				""",
                (
                    record_id,
                    session_id,
                    tool_name,
                    args if isinstance(args, str) else json.dumps(args),
                    decision_json,
                    self._policy_version,
                    hitl_action_id,
                    hitl_decided_by,
                    outcome,
                    timestamp,
                    context_json,
                ),
            )
            conn.commit()
        return record_id

    async def record(
        self,
        session_id: str,
        tool_name: str,
        args: dict,
        decision,  # PolicyDecision — avoid circular import; duck-typed
        context,  # SessionContext — duck-typed
        outcome: str,
        hitl_action_id: str | None = None,
        hitl_decided_by: str | None = None,
    ) -> str:
        decision_json = json.dumps(decision.model_dump(mode="json"))
        context_json = json.dumps(context.model_dump(mode="json"))
        return await asyncio.to_thread(
            self._sync_record,
            session_id,
            tool_name,
            args,
            decision_json,
            context_json,
            outcome,
            hitl_action_id,
            hitl_decided_by,
        )

    def _sync_query(
        self,
        session_id: str | None,
        tool_name: str | None,
        outcome: str | None,
        limit: int,
    ) -> list[AuditRecord]:
        clauses: list[str] = []
        params: list = []
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if tool_name:
            clauses.append("tool_name = ?")
            params.append(tool_name)
        if outcome:
            clauses.append("outcome = ?")
            params.append(outcome)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM audit_log {where} ORDER BY timestamp DESC LIMIT ?",
                params,
            ).fetchall()

        records = []
        for row in rows:
            ctx = json.loads(row["context_json"])
            records.append(
                AuditRecord(
                    id=row["id"],
                    session_id=row["session_id"],
                    tool_name=row["tool_name"],
                    args=json.loads(row["args_json"]),
                    policy_decision=json.loads(row["policy_decision_json"]),
                    policy_version=row["policy_version"],
                    hitl_action_id=row["hitl_action_id"],
                    hitl_decided_by=row["hitl_decided_by"],
                    outcome=row["outcome"],
                    timestamp=row["timestamp"],
                    context=ctx,
                    parent_session_id=ctx.get("parent_session_id", ""),
                    delegation_depth=ctx.get("delegation_depth", 0),
                )
            )
        return records

    async def query(
        self,
        session_id: str | None = None,
        tool_name: str | None = None,
        outcome: str | None = None,
        limit: int = 50,
    ) -> list[AuditRecord]:
        return await asyncio.to_thread(self._sync_query, session_id, tool_name, outcome, limit)

    def _sync_export_session(self, session_id: str) -> dict:
        records = self._sync_query(session_id, None, None, limit=10_000)
        record_dicts = [
            {
                "id": r.id,
                "tool_name": r.tool_name,
                "args": r.args,
                "outcome": r.outcome,
                "policy_decision": r.policy_decision,
                "policy_version": r.policy_version,
                "hitl_action_id": r.hitl_action_id,
                "hitl_decided_by": r.hitl_decided_by,
                "timestamp": r.timestamp,
                "context": r.context,
            }
            for r in records
        ]
        content_bytes = json.dumps(record_dicts, sort_keys=True).encode()
        return {
            "session_id": session_id,
            "exported_at": datetime.now(UTC).isoformat(),
            "policy_version": self._policy_version,
            "record_count": len(record_dicts),
            "integrity_hash": hashlib.sha256(content_bytes).hexdigest(),
            "records": record_dicts,
        }

    async def export_session(self, session_id: str) -> dict:
        """
        Produce a self-contained compliance report for a single session.

        Includes every tool call, its policy decision, policy version, and
        any human approval decisions. The integrity_hash is a SHA-256 of the
        records list (sorted keys) so the recipient can verify no records
        were omitted or tampered with after export.
        """
        return await asyncio.to_thread(self._sync_export_session, session_id)
