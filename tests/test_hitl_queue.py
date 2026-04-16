# SPDX-License-Identifier: Apache-2.0
"""
Tests for anchor.queue.HITLQueue (in-memory SQLite via :memory:).
"""

import asyncio
from datetime import UTC, datetime

import pytest

from kitelogik.anchor.models import ActionStatus, PendingAction
from kitelogik.anchor.queue import HITLQueue


@pytest.fixture
async def queue(tmp_path):
    q = HITLQueue(db_path=str(tmp_path / "test_hitl.db"))
    await q.setup()
    return q


def _make_action(**kwargs) -> PendingAction:
    defaults = dict(
        id="",
        session_id="sess_test",
        tool_name="approve_refund",
        args={"customer_id": "cust_001", "amount": 500.0},
        risk_tier="TRANSACTIONAL_HIGH",
        status=ActionStatus.PENDING,
        created_at=datetime.now(UTC),
    )
    defaults.update(kwargs)
    return PendingAction(**defaults)


async def test_enqueue_returns_id(queue):
    action = _make_action()
    action_id = await queue.enqueue(action)
    assert action_id
    assert len(action_id) > 0


async def test_get_status_after_enqueue(queue):
    action = _make_action(id="abc123")
    await queue.enqueue(action)
    fetched = await queue.get_status("abc123")
    assert fetched is not None
    assert fetched.tool_name == "approve_refund"
    assert fetched.status == ActionStatus.PENDING


async def test_get_status_unknown_returns_none(queue):
    result = await queue.get_status("does_not_exist")
    assert result is None


async def test_approve(queue):
    action = _make_action(id="appr1")
    await queue.enqueue(action)
    ok = await queue.approve("appr1", decided_by="admin")
    assert ok is True
    fetched = await queue.get_status("appr1")
    assert fetched.status == ActionStatus.APPROVED
    assert fetched.decided_by == "admin"
    assert fetched.decided_at is not None


async def test_deny(queue):
    action = _make_action(id="deny1")
    await queue.enqueue(action)
    ok = await queue.deny("deny1", decided_by="manager", reason="Too high risk")
    assert ok is True
    fetched = await queue.get_status("deny1")
    assert fetched.status == ActionStatus.DENIED
    assert fetched.denial_reason == "Too high risk"


async def test_approve_non_pending_returns_false(queue):
    action = _make_action(id="appr2")
    await queue.enqueue(action)
    await queue.approve("appr2")
    # second approve should fail (no longer PENDING)
    ok = await queue.approve("appr2")
    assert ok is False


async def test_get_pending_only_returns_pending(queue):
    a1 = _make_action(id="p1")
    a2 = _make_action(id="p2")
    a3 = _make_action(id="p3")
    for a in [a1, a2, a3]:
        await queue.enqueue(a)
    await queue.approve("p1")

    pending = await queue.get_pending()
    ids = [a.id for a in pending]
    assert "p1" not in ids
    assert "p2" in ids
    assert "p3" in ids


async def test_auto_id_assigned_when_empty(queue):
    action = _make_action(id="")
    action_id = await queue.enqueue(action)
    assert action_id
    fetched = await queue.get_status(action_id)
    assert fetched is not None


# ── wait_for_decision (asyncio.Event) ──────────────────────────────────────


async def test_wait_for_decision_resolves_on_approve(queue):
    """Approving an action wakes wait_for_decision immediately."""
    action = _make_action(id="wfd_approve")
    await queue.enqueue(action)

    async def _approve_after():
        await asyncio.sleep(0.05)
        await queue.approve("wfd_approve", decided_by="admin")

    asyncio.create_task(_approve_after())
    decided = await queue.wait_for_decision("wfd_approve", timeout_seconds=5.0)

    assert decided.status == ActionStatus.APPROVED
    assert decided.decided_by == "admin"


async def test_wait_for_decision_resolves_on_deny(queue):
    """Denying an action wakes wait_for_decision immediately."""
    action = _make_action(id="wfd_deny")
    await queue.enqueue(action)

    async def _deny_after():
        await asyncio.sleep(0.05)
        await queue.deny("wfd_deny", decided_by="manager", reason="Too risky")

    asyncio.create_task(_deny_after())
    decided = await queue.wait_for_decision("wfd_deny", timeout_seconds=5.0)

    assert decided.status == ActionStatus.DENIED
    assert decided.denial_reason == "Too risky"


async def test_wait_for_decision_times_out(queue):
    """If no decision arrives within timeout, status becomes TIMED_OUT."""
    action = _make_action(id="wfd_timeout")
    await queue.enqueue(action)

    decided = await queue.wait_for_decision("wfd_timeout", timeout_seconds=0.1)

    assert decided.status == ActionStatus.TIMED_OUT


async def test_wait_for_decision_cleans_up_event(queue):
    """After wait completes, the event is removed from the internal dict."""
    action = _make_action(id="wfd_cleanup")
    await queue.enqueue(action)
    assert "wfd_cleanup" in queue._events

    await queue.approve("wfd_cleanup")
    await queue.wait_for_decision("wfd_cleanup", timeout_seconds=5.0)

    assert "wfd_cleanup" not in queue._events


# ── expire_old / start_expiry_task ─────────────────────────────────────────


async def test_expire_old_marks_overdue_actions(queue):
    """Actions older than timeout_seconds are marked TIMED_OUT."""
    from datetime import timedelta

    old_action = _make_action(id="exp_old", created_at=datetime.now(UTC) - timedelta(seconds=400))
    fresh_action = _make_action(id="exp_fresh")
    await queue.enqueue(old_action)
    await queue.enqueue(fresh_action)

    count = await queue.expire_old(timeout_seconds=300)

    assert count == 1
    assert (await queue.get_status("exp_old")).status == ActionStatus.TIMED_OUT
    assert (await queue.get_status("exp_fresh")).status == ActionStatus.PENDING


async def test_expire_old_wakes_waiting_event(queue):
    """expire_old() sets the event so wait_for_decision() resolves without polling."""
    from datetime import timedelta

    old_action = _make_action(id="exp_wake", created_at=datetime.now(UTC) - timedelta(seconds=400))
    await queue.enqueue(old_action)

    async def _expire():
        await asyncio.sleep(0.05)
        await queue.expire_old(timeout_seconds=300)

    asyncio.create_task(_expire())
    decided = await queue.wait_for_decision("exp_wake", timeout_seconds=5.0)

    assert decided.status == ActionStatus.TIMED_OUT


async def test_start_expiry_task_returns_cancellable_task(queue):
    """start_expiry_task() returns a running asyncio.Task that can be cancelled."""
    task = await queue.start_expiry_task(check_interval_seconds=60.0)
    assert not task.done()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert task.done()
