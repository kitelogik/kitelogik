# SPDX-License-Identifier: Apache-2.0
"""
HITLQueue — SQLite-backed async queue for human-in-the-loop approvals.

Actions requiring human review are enqueued here. The approver API
reads from this queue; the agent polls get_status() to learn the outcome.
"""

import asyncio
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .models import ActionStatus, PendingAction


class _NullEvent:
    """No-op stand-in used when set() is called for an un-tracked action_id."""

    def set(self) -> None:
        pass


_CREATE_TABLE = """
                CREATE TABLE IF NOT EXISTS pending_actions
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
                    risk_tier
                    TEXT
                    NOT
                    NULL,
                    status
                    TEXT
                    NOT
                    NULL
                    DEFAULT
                    'PENDING',
                    created_at
                    TEXT
                    NOT
                    NULL,
                    decided_at
                    TEXT,
                    decided_by
                    TEXT,
                    denial_reason
                    TEXT
                ) \
                """


def _row_to_action(row: tuple) -> PendingAction:
    import json

    (
        action_id,
        session_id,
        tool_name,
        args_json,
        risk_tier,
        status,
        created_at,
        decided_at,
        decided_by,
        denial_reason,
    ) = row
    return PendingAction(
        id=action_id,
        session_id=session_id,
        tool_name=tool_name,
        args=json.loads(args_json),
        risk_tier=risk_tier,
        status=ActionStatus(status),
        created_at=datetime.fromisoformat(created_at),
        decided_at=datetime.fromisoformat(decided_at) if decided_at else None,
        decided_by=decided_by,
        denial_reason=denial_reason,
    )


class HITLQueue:
    """Async HITL action queue backed by SQLite.

    Thread-safety: all DB calls are dispatched via ``asyncio.to_thread`` so
    the event loop is never blocked.

    Parameters
    ----------
    db_path : str
            Path to the SQLite database file.
    """

    def __init__(self, db_path: str = "hitl.db") -> None:
        self._db_path = str(Path(db_path).resolve())
        self._events: dict[str, asyncio.Event] = {}  # action_id → decision event

    # ── internal sync helpers ──────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _sync_setup(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(_CREATE_TABLE)
            conn.commit()

    def _sync_enqueue(self, action: PendingAction) -> str:
        import json

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO pending_actions
                (id, session_id, tool_name, args_json, risk_tier,
                 status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
				""",
                (
                    action.id,
                    action.session_id,
                    action.tool_name,
                    json.dumps(action.args),
                    action.risk_tier,
                    ActionStatus.PENDING.value,
                    action.created_at.isoformat(),
                ),
            )
            conn.commit()
        return action.id

    def _sync_decide(
        self,
        action_id: str,
        status: ActionStatus,
        decided_by: str,
        denial_reason: str | None,
    ) -> bool:
        now = datetime.now(UTC).isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE pending_actions
                SET status        = ?,
                    decided_at    = ?,
                    decided_by    = ?,
                    denial_reason = ?
                WHERE id = ?
                  AND status = 'PENDING'
				""",
                (status.value, now, decided_by, denial_reason, action_id),
            )
            conn.commit()
            return cur.rowcount == 1

    def _sync_get(self, action_id: str) -> PendingAction | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM pending_actions WHERE id = ?", (action_id,)
            ).fetchone()
        return _row_to_action(tuple(row)) if row else None

    def _sync_get_pending(self) -> list[PendingAction]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM pending_actions WHERE status = 'PENDING' ORDER BY created_at"
            ).fetchall()
        return [_row_to_action(tuple(r)) for r in rows]

    def _sync_expire(self, timeout_seconds: int) -> list[str]:
        """Mark overdue PENDING actions as TIMED_OUT. Returns the IDs that were expired."""
        from datetime import timedelta

        cutoff_iso = (datetime.now(UTC) - timedelta(seconds=timeout_seconds)).isoformat()
        now = datetime.now(UTC).isoformat()
        with self._connect() as conn:
            expired_rows = conn.execute(
                "SELECT id FROM pending_actions WHERE status = 'PENDING' AND created_at < ?",
                (cutoff_iso,),
            ).fetchall()
            expired_ids = [row[0] for row in expired_rows]
            if expired_ids:
                placeholders = ",".join("?" * len(expired_ids))
                conn.execute(
                    f"UPDATE pending_actions SET status = 'TIMED_OUT', decided_at = ? "
                    f"WHERE id IN ({placeholders})",
                    [now, *expired_ids],
                )
                conn.commit()
        return expired_ids

    # ── public async API ───────────────────────────────────────────────────

    async def setup(self) -> None:
        await asyncio.to_thread(self._sync_setup)

    async def enqueue(self, action: PendingAction) -> str:
        if not action.id:
            action.id = uuid.uuid4().hex
        await asyncio.to_thread(self._sync_enqueue, action)
        self._events[action.id] = asyncio.Event()
        return action.id

    async def approve(self, action_id: str, decided_by: str = "human") -> bool:
        result = await asyncio.to_thread(
            self._sync_decide, action_id, ActionStatus.APPROVED, decided_by, None
        )
        if result:
            self._events.get(action_id, _NullEvent()).set()
        return result

    async def deny(self, action_id: str, decided_by: str = "human", reason: str = "") -> bool:
        result = await asyncio.to_thread(
            self._sync_decide, action_id, ActionStatus.DENIED, decided_by, reason
        )
        if result:
            self._events.get(action_id, _NullEvent()).set()
        return result

    async def get_status(self, action_id: str) -> PendingAction | None:
        return await asyncio.to_thread(self._sync_get, action_id)

    async def get_pending(self) -> list[PendingAction]:
        return await asyncio.to_thread(self._sync_get_pending)

    async def expire_old(self, timeout_seconds: int = 300) -> int:
        """Mark overdue PENDING actions as TIMED_OUT.

        Also sets any in-process ``asyncio.Event`` instances so
        ``wait_for_decision()`` callers wake up immediately rather than
        waiting for their own per-request timeout.

        Parameters
        ----------
        timeout_seconds : int
                Age in seconds after which a PENDING action is considered overdue.

        Returns
        -------
        int
                Count of newly expired actions.
        """
        expired_ids = await asyncio.to_thread(self._sync_expire, timeout_seconds)
        for action_id in expired_ids:
            self._events.get(action_id, _NullEvent()).set()
        return len(expired_ids)

    async def start_expiry_task(
        self,
        check_interval_seconds: float = 30.0,
        action_timeout_seconds: int = 300,
    ) -> asyncio.Task:
        """Start a background ``asyncio.Task`` that periodically calls ``expire_old()``.

        Cancel the returned task to stop it (e.g. on shutdown).

        Parameters
        ----------
        check_interval_seconds : float
                How often to check for expired actions.
        action_timeout_seconds : int
                How old a PENDING action must be to be expired.

        Returns
        -------
        asyncio.Task
                The background task. Cancel it to stop the expiry loop.
        """
        _MAX_CONSECUTIVE_FAILURES = 5

        async def _loop() -> None:
            import logging as _logging

            _log = _logging.getLogger(__name__)
            consecutive_failures = 0
            while True:
                await asyncio.sleep(check_interval_seconds)
                try:
                    count = await self.expire_old(action_timeout_seconds)
                    consecutive_failures = 0  # reset on success
                    if count:
                        _log.info("HITL expiry task: marked %d action(s) as TIMED_OUT", count)
                except sqlite3.DatabaseError:
                    consecutive_failures += 1
                    _log.exception(
                        "HITL expiry task: error during expire_old() (failure %d/%d)",
                        consecutive_failures,
                        _MAX_CONSECUTIVE_FAILURES,
                    )
                    if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                        _log.critical(
                            "HITL expiry task: %d consecutive failures — "
                            "HITL timeout enforcement is degraded. "
                            "Investigate audit store / DB connection immediately.",
                            consecutive_failures,
                        )
                        # Reset counter so critical fires again after another
                        # burst rather than only once per process lifetime.
                        consecutive_failures = 0

        task = asyncio.create_task(_loop(), name="hitl_expiry_task")

        def _on_task_done(t: asyncio.Task) -> None:
            try:
                t.result()
            except asyncio.CancelledError:
                pass  # normal shutdown
            except Exception:
                import logging as _logging

                _logging.getLogger(__name__).critical(
                    "HITL expiry task crashed unexpectedly — "
                    "HITL timeout enforcement is disabled until restart.",
                    exc_info=True,
                )

        task.add_done_callback(_on_task_done)
        return task

    async def wait_for_decision(
        self,
        action_id: str,
        timeout_seconds: float = 300.0,
    ) -> PendingAction:
        """Block until the action is approved, denied, or the timeout expires.

        Uses ``asyncio.Event`` -- ``approve()``/``deny()`` set the event
        immediately, so latency is zero rather than up to poll_interval
        seconds. On timeout, marks the action TIMED_OUT in the DB.

        Parameters
        ----------
        action_id : str
                ID of the action to wait on.
        timeout_seconds : float
                Maximum seconds to wait before marking the action TIMED_OUT.

        Returns
        -------
        PendingAction
                The action with its final status.

        Raises
        ------
        ValueError
                If the action ID is not found in the queue.
        """
        event = self._events.get(action_id)
        if event is None:
            # No event registered — action may have been decided before we started waiting
            action = await self.get_status(action_id)
            if action is None:
                raise ValueError(f"Action '{action_id}' not found in queue")
            return action

        try:
            await asyncio.wait_for(event.wait(), timeout=timeout_seconds)
        except TimeoutError:
            await asyncio.to_thread(
                self._sync_decide,
                action_id,
                ActionStatus.TIMED_OUT,
                "system",
                "Approval timeout exceeded",
            )
        finally:
            self._events.pop(action_id, None)

        action = await self.get_status(action_id)
        if action is None:
            raise ValueError(f"Action '{action_id}' not found in queue")
        return action
