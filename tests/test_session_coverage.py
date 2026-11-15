# SPDX-License-Identifier: Apache-2.0
"""
Coverage tests for AgentSession paths not exercised by the feature-specific
suites: agent.spawn denied, HITL (approved/denied/timed-out), memory-tool
handling, audit-failure tolerance, soft-deny path, and the sanitize hook.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from kitelogik.agents import AgentSession
from kitelogik.agents.llm import LLMResponse, ToolCall
from kitelogik.anchor.models import ActionStatus
from kitelogik.governed import GovernanceError
from kitelogik.memory.models import TrustTier
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import PolicyDecision, RiskTier
from tests.conftest import allowed_hitl_decision_for, make_mock_llm


def _allow(reason: str = "Allowed") -> PolicyDecision:
    return PolicyDecision(
        allow=True,
        deny=False,
        risk_tier=RiskTier.INFORMATIONAL,
        requires_hitl=False,
        reason=reason,
    )


def _deny(
    reason: str = "denied",
    risk_tier: RiskTier = RiskTier.SECURITY_CRITICAL,
) -> PolicyDecision:
    return PolicyDecision(
        allow=False,
        deny=True,
        risk_tier=risk_tier,
        requires_hitl=False,
        reason=reason,
    )


def _hitl(reason: str = "needs review") -> PolicyDecision:
    return PolicyDecision(
        allow=False,
        deny=False,
        risk_tier=RiskTier.TRANSACTIONAL_HIGH,
        requires_hitl=True,
        reason=reason,
    )


def _soft_deny(reason: str = "not allowed") -> PolicyDecision:
    """Neither allow nor deny — the fall-through that the Rego `main.rego`
    soft-deny fallback would route to HITL in production."""
    return PolicyDecision(
        allow=False,
        deny=False,
        risk_tier=RiskTier.OPERATIONAL,
        requires_hitl=False,
        reason=reason,
    )


def _make_sanitizing_gate(
    spawn_decision: PolicyDecision | None = None,
    tool_decision: PolicyDecision | None = None,
) -> PolicyGate:
    g = MagicMock(spec=PolicyGate)
    g.evaluate = AsyncMock(return_value=spawn_decision or _allow())
    g.evaluate_tool_call = AsyncMock(return_value=tool_decision or _allow())
    g.sanitize_response = MagicMock(
        side_effect=lambda x: MagicMock(content=x, was_modified=False, injection_patterns_found=[])
    )
    return g


# ── agent.spawn denied ──────────────────────────────────────────────────────


async def test_agent_spawn_denied_raises_governance_error(agent_ctx):
    gate = _make_sanitizing_gate(spawn_decision=_deny(reason="role not allowed to spawn"))
    llm = make_mock_llm()
    session = AgentSession(gate=gate, context=agent_ctx, llm_client=llm)

    events: list[dict] = []
    with pytest.raises(GovernanceError, match="Agent spawn denied"):
        await session.run_async("hi", on_event=events.append)

    # The on_event emits the spawn-denied frame before the raise
    assert any(e["type"] == "agent_spawn_denied" for e in events)


async def test_agent_spawn_allowed_but_hitl_fails_closed(agent_ctx):
    """Spawn has no human-approval flow, so an allowed spawn that policy
    routes to HITL must not proceed — the model is never called."""
    gate = _make_sanitizing_gate(spawn_decision=allowed_hitl_decision_for(RiskTier.OPERATIONAL))
    llm = make_mock_llm()
    session = AgentSession(gate=gate, context=agent_ctx, llm_client=llm)

    events: list[dict] = []
    with pytest.raises(GovernanceError, match="Agent spawn denied: requires human approval"):
        await session.run_async("hi", on_event=events.append)

    llm.create_message.assert_not_called()
    assert any(e["type"] == "agent_spawn_denied" for e in events)


# ── soft-deny on a tool call ────────────────────────────────────────────────


async def test_tool_call_soft_deny_records_in_blocked(agent_ctx):
    gate = _make_sanitizing_gate(tool_decision=_soft_deny("no matching rule"))
    llm = make_mock_llm(
        responses=[
            LLMResponse(
                stop_reason="tool_use",
                tool_calls=[ToolCall(id="tc1", name="my_tool", input={})],
                raw_content="x",
            ),
            LLMResponse(stop_reason="end_turn", text_content="understood"),
        ]
    )
    session = AgentSession(gate=gate, context=agent_ctx, llm_client=llm)
    result = await session.run_async("do it")

    assert len(result.blocked_calls) == 1
    assert result.blocked_calls[0]["tool"] == "my_tool"


# ── HITL: approved / denied / timed-out ─────────────────────────────────────


async def test_hitl_approved_runs_tool(agent_ctx):
    gate = _make_sanitizing_gate(tool_decision=_hitl())

    decided = MagicMock()
    decided.status = ActionStatus.APPROVED
    decided.decided_by = "supervisor@example.com"
    decided.denial_reason = None

    hitl_queue = MagicMock()
    hitl_queue.enqueue = AsyncMock()
    hitl_queue.wait_for_decision = AsyncMock(return_value=decided)

    llm = make_mock_llm(
        responses=[
            LLMResponse(
                stop_reason="tool_use",
                tool_calls=[ToolCall(id="tc1", name="risky_tool", input={"x": 1})],
                raw_content="x",
            ),
            LLMResponse(stop_reason="end_turn", text_content="done"),
        ]
    )

    def handler(name: str, args: dict) -> str:
        return "tool_ran"

    session = AgentSession(
        gate=gate,
        context=agent_ctx,
        llm_client=llm,
        hitl_queue=hitl_queue,
        tool_handler=handler,
    )
    events: list[dict] = []
    result = await session.run_async("execute", on_event=events.append)

    assert hitl_queue.enqueue.await_count == 1
    assert any(e["type"] == "hitl_queued" for e in events)
    assert any(e["type"] == "hitl_resolved" for e in events)
    assert len(result.tool_calls) == 1


async def test_hitl_denied_surfaces_reason(agent_ctx):
    gate = _make_sanitizing_gate(tool_decision=_hitl())

    decided = MagicMock()
    decided.status = ActionStatus.DENIED
    decided.decided_by = "supervisor@example.com"
    decided.denial_reason = "outside policy envelope"

    hitl_queue = MagicMock()
    hitl_queue.enqueue = AsyncMock()
    hitl_queue.wait_for_decision = AsyncMock(return_value=decided)

    llm = make_mock_llm(
        responses=[
            LLMResponse(
                stop_reason="tool_use",
                tool_calls=[ToolCall(id="tc1", name="risky_tool", input={})],
                raw_content="x",
            ),
            LLMResponse(stop_reason="end_turn", text_content="acknowledged"),
        ]
    )

    session = AgentSession(gate=gate, context=agent_ctx, llm_client=llm, hitl_queue=hitl_queue)
    result = await session.run_async("execute")

    assert len(result.blocked_calls) == 1


async def test_hitl_timeout_surfaces_timeout(agent_ctx):
    gate = _make_sanitizing_gate(tool_decision=_hitl())

    decided = MagicMock()
    decided.status = ActionStatus.TIMED_OUT
    decided.decided_by = None
    decided.denial_reason = None

    hitl_queue = MagicMock()
    hitl_queue.enqueue = AsyncMock()
    hitl_queue.wait_for_decision = AsyncMock(return_value=decided)

    llm = make_mock_llm(
        responses=[
            LLMResponse(
                stop_reason="tool_use",
                tool_calls=[ToolCall(id="tc1", name="slow_tool", input={})],
                raw_content="x",
            ),
            LLMResponse(stop_reason="end_turn", text_content="bye"),
        ]
    )

    session = AgentSession(
        gate=gate,
        context=agent_ctx,
        llm_client=llm,
        hitl_queue=hitl_queue,
        hitl_timeout=0.1,
    )
    result = await session.run_async("execute")

    assert len(result.hitl_required) == 1


async def test_hitl_without_queue_records_pending(agent_ctx):
    """When a decision requires HITL but no queue is configured, the call
    lands in ``hitl_required`` as a pending marker — Phase 2 fallback."""
    gate = _make_sanitizing_gate(tool_decision=_hitl())
    llm = make_mock_llm(
        responses=[
            LLMResponse(
                stop_reason="tool_use",
                tool_calls=[ToolCall(id="tc1", name="any_tool", input={})],
                raw_content="x",
            ),
            LLMResponse(stop_reason="end_turn", text_content="bye"),
        ]
    )
    session = AgentSession(gate=gate, context=agent_ctx, llm_client=llm)
    result = await session.run_async("execute")
    assert len(result.hitl_required) == 1


# ── memory tools ─────────────────────────────────────────────────────────────


async def test_query_memory_returns_entry(agent_ctx):
    gate = _make_sanitizing_gate()

    entry = MagicMock()
    entry.key = "favourite_colour"
    entry.value = "blue"
    entry.trust_tier = TrustTier.INTERNAL
    entry.source = "agent"
    entry.sanitized = False

    memory = MagicMock()
    memory.read = AsyncMock(return_value=entry)

    llm = make_mock_llm(
        responses=[
            LLMResponse(
                stop_reason="tool_use",
                tool_calls=[
                    ToolCall(id="tc1", name="query_memory", input={"key": "favourite_colour"})
                ],
                raw_content="x",
            ),
            LLMResponse(stop_reason="end_turn", text_content="got it"),
        ]
    )

    session = AgentSession(gate=gate, context=agent_ctx, llm_client=llm, memory_store=memory)
    result = await session.run_async("what's the favourite colour?")
    assert result.final_response == "got it"
    memory.read.assert_awaited_once_with("favourite_colour")


async def test_query_memory_missing_key(agent_ctx):
    gate = _make_sanitizing_gate()
    memory = MagicMock()
    memory.read = AsyncMock(return_value=None)

    llm = make_mock_llm(
        responses=[
            LLMResponse(
                stop_reason="tool_use",
                tool_calls=[ToolCall(id="tc1", name="query_memory", input={"key": "absent"})],
                raw_content="x",
            ),
            LLMResponse(stop_reason="end_turn", text_content="missing acknowledged"),
        ]
    )

    session = AgentSession(gate=gate, context=agent_ctx, llm_client=llm, memory_store=memory)
    await session.run_async("read it")
    memory.read.assert_awaited_once_with("absent")


async def test_write_memory_uses_default_policy(agent_ctx):
    gate = _make_sanitizing_gate()

    captured: dict = {}

    async def _write(*, key, value, trust_tier, source, session_id):
        captured.update(key=key, value=value, trust_tier=trust_tier, source=source)
        entry = MagicMock()
        entry.key = key
        entry.trust_tier = trust_tier
        entry.sanitized = False
        return entry

    memory = MagicMock()
    memory.write = _write

    llm = make_mock_llm(
        responses=[
            LLMResponse(
                stop_reason="tool_use",
                tool_calls=[
                    ToolCall(
                        id="tc1",
                        name="write_memory",
                        input={"key": "fact", "value": "from_agent"},
                    )
                ],
                raw_content="x",
            ),
            LLMResponse(stop_reason="end_turn", text_content="stored"),
        ]
    )

    session = AgentSession(gate=gate, context=agent_ctx, llm_client=llm, memory_store=memory)
    await session.run_async("save it")
    # Primary session — default policy writes at EXTERNAL
    assert captured["trust_tier"] == TrustTier.EXTERNAL
    assert captured["source"] == "agent"


# ── _execute_tool edge cases ────────────────────────────────────────────────


async def test_no_tool_handler_surfaces_error(agent_ctx):
    """Without a tool_handler, the tool result is a JSON error string sent
    back to the LLM — the session does not crash."""
    gate = _make_sanitizing_gate()
    llm = make_mock_llm(
        responses=[
            LLMResponse(
                stop_reason="tool_use",
                tool_calls=[ToolCall(id="tc1", name="unregistered", input={})],
                raw_content="x",
            ),
            LLMResponse(stop_reason="end_turn", text_content="no handler"),
        ]
    )
    session = AgentSession(gate=gate, context=agent_ctx, llm_client=llm)
    result = await session.run_async("call unregistered")
    assert result.final_response == "no handler"


async def test_sanitize_on_event_emitted(agent_ctx):
    gate = _make_sanitizing_gate()
    llm = make_mock_llm(
        responses=[
            LLMResponse(
                stop_reason="tool_use",
                tool_calls=[ToolCall(id="tc1", name="some_tool", input={})],
                raw_content="x",
            ),
            LLMResponse(stop_reason="end_turn", text_content="done"),
        ]
    )

    def handler(name: str, args: dict) -> str:
        return "safe output"

    session = AgentSession(gate=gate, context=agent_ctx, llm_client=llm, tool_handler=handler)
    events: list[dict] = []
    await session.run_async("go", on_event=events.append)
    assert any(e["type"] == "sanitize" for e in events)


async def test_async_tool_handler_awaited(agent_ctx):
    gate = _make_sanitizing_gate()
    llm = make_mock_llm(
        responses=[
            LLMResponse(
                stop_reason="tool_use",
                tool_calls=[ToolCall(id="tc1", name="async_tool", input={})],
                raw_content="x",
            ),
            LLMResponse(stop_reason="end_turn", text_content="done"),
        ]
    )

    async def async_handler(name: str, args: dict) -> str:
        return "async result"

    session = AgentSession(gate=gate, context=agent_ctx, llm_client=llm, tool_handler=async_handler)
    result = await session.run_async("go")
    assert result.final_response == "done"


# ── _audit tolerance ────────────────────────────────────────────────────────


async def test_audit_failure_does_not_break_session(agent_ctx, caplog):
    import logging

    gate = _make_sanitizing_gate()

    audit = MagicMock()
    audit.record = AsyncMock(side_effect=RuntimeError("disk full"))

    llm = make_mock_llm(
        responses=[
            LLMResponse(
                stop_reason="tool_use",
                tool_calls=[ToolCall(id="tc1", name="ok_tool", input={})],
                raw_content="x",
            ),
            LLMResponse(stop_reason="end_turn", text_content="finished"),
        ]
    )

    def handler(name: str, args: dict) -> str:
        return "ok"

    session = AgentSession(
        gate=gate,
        context=agent_ctx,
        llm_client=llm,
        audit_store=audit,
        tool_handler=handler,
    )
    with caplog.at_level(logging.ERROR, logger="kitelogik.agents.session"):
        result = await session.run_async("go")

    # Session should complete despite audit raising on every call
    assert result.final_response == "finished"
    assert any("Audit write failed" in r.getMessage() for r in caplog.records)
