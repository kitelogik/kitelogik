# SPDX-License-Identifier: Apache-2.0
"""
Tests for :meth:`AgentSession.submit_plan` — the ``agent.plan`` governance
event wiring.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

from kitelogik.agents import AgentSession
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import GovernanceEvent, RiskTier, SessionContext
from tests.conftest import allowed_hitl_decision_for, deny_decision_for, make_mock_llm


def _session(gate: PolicyGate, ctx: SessionContext) -> AgentSession:
    return AgentSession(gate=gate, context=ctx, llm_client=make_mock_llm())


async def test_submit_plan_fires_agent_plan_event(agent_gate, agent_ctx):
    session = _session(agent_gate, agent_ctx)
    plan = [{"tool_name": "read_customer", "args": {"id": "cust_1"}}]
    decision = await session.submit_plan(plan)
    assert decision.allow

    ev: GovernanceEvent = agent_gate.evaluate.call_args.args[0]
    assert ev.event_type == "agent.plan"
    assert ev.steps == plan


async def test_submit_plan_stores_approved_plan(agent_gate, agent_ctx):
    session = _session(agent_gate, agent_ctx)
    plan = [{"tool_name": "read_customer", "args": {"id": "x"}}]
    await session.submit_plan(plan)
    assert session._approved_plan == plan


async def test_submit_plan_denied_does_not_store_plan(agent_gate, agent_ctx):
    agent_gate.evaluate = AsyncMock(return_value=deny_decision_for(reason="too many steps"))
    session = _session(agent_gate, agent_ctx)
    decision = await session.submit_plan([{"tool_name": "x"}])
    assert decision.deny
    assert session._approved_plan is None


async def test_submit_plan_allowed_but_hitl_does_not_store_plan(agent_gate, agent_ctx):
    """An allowed plan that policy routes to HITL is not an approved plan."""
    agent_gate.evaluate = AsyncMock(return_value=allowed_hitl_decision_for(RiskTier.OPERATIONAL))
    session = _session(agent_gate, agent_ctx)
    decision = await session.submit_plan([{"tool_name": "read_customer"}])
    assert decision.allow and decision.requires_hitl
    assert session._approved_plan is None


async def test_submit_plan_fires_on_event(agent_gate, agent_ctx):
    session = _session(agent_gate, agent_ctx)
    events: list[dict] = []
    await session.submit_plan([{"tool_name": "read_customer"}], on_event=events.append)
    assert any(e["type"] == "plan_decision" for e in events)
