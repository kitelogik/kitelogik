# SPDX-License-Identifier: Apache-2.0
"""
Tests for the governance event system — GovernanceEvent model,
OPAClient.evaluate_event(), PolicyGate.evaluate(), agent spawn/delegate
governance, and plan-before-execute.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from kitelogik.governed import GovernanceError, GovernedToolbox
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import (
    GovernanceEvent,
    PolicyDecision,
    RiskTier,
    SessionContext,
)
from kitelogik.tether.opa_client import OPAClient, OPAConnectionError

# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def ctx() -> SessionContext:
    return SessionContext(
        session_id="test_gov_001",
        user_role="admin",
        session_scopes=["read", "write", "approve_refund"],
        delegation_depth=0,
    )


@pytest.fixture
def ctx_with_budget() -> SessionContext:
    return SessionContext(
        session_id="test_budget_001",
        user_role="worker",
        session_scopes=["read"],
        budget_total_tokens=10000,
        budget_used_tokens=5000,
        budget_total_api_calls=100,
        budget_used_api_calls=50,
        budget_total_cost_cents=500,
        budget_used_cost_cents=200,
    )


@pytest.fixture
def allow_decision() -> PolicyDecision:
    return PolicyDecision(
        allow=True,
        deny=False,
        risk_tier=RiskTier.INFORMATIONAL,
        requires_hitl=False,
        reason="Allowed",
    )


@pytest.fixture
def deny_decision() -> PolicyDecision:
    return PolicyDecision(
        allow=False,
        deny=True,
        risk_tier=RiskTier.SECURITY_CRITICAL,
        requires_hitl=False,
        reason="Denied by policy",
    )


@pytest.fixture
def mock_opa(allow_decision) -> OPAClient:
    client = AsyncMock(spec=OPAClient)
    client.evaluate.return_value = allow_decision
    client.evaluate_event.return_value = allow_decision
    return client


@pytest.fixture
def gate(mock_opa) -> PolicyGate:
    return PolicyGate(opa_client=mock_opa)


# ── GovernanceEvent model tests ──────────────────────────────────────────────


class TestGovernanceEventModel:
    def test_construct_spawn_event(self, ctx):
        event = GovernanceEvent(
            event_type="agent.spawn",
            session_id=ctx.session_id,
            action="agent.spawn",
            context=ctx,
            requested_capabilities=["read", "write"],
        )
        assert event.event_type == "agent.spawn"
        assert event.requested_capabilities == ["read", "write"]
        assert event.steps == []
        assert event.delegation_target is None

    def test_construct_delegate_event(self, ctx):
        event = GovernanceEvent(
            event_type="agent.delegate",
            session_id=ctx.session_id,
            action="agent.delegate",
            context=ctx,
            delegation_target="summarize report",
            requested_capabilities=["read"],
        )
        assert event.event_type == "agent.delegate"
        assert event.delegation_target == "summarize report"

    def test_construct_plan_event(self, ctx):
        steps = [
            {"tool_name": "read_file", "args": {"path": "/data/report.csv"}},
            {"tool_name": "summarize", "args": {"text": "..."}},
        ]
        event = GovernanceEvent(
            event_type="agent.plan",
            session_id=ctx.session_id,
            action="agent.plan",
            context=ctx,
            steps=steps,
        )
        assert event.event_type == "agent.plan"
        assert len(event.steps) == 2

    def test_construct_budget_event(self, ctx_with_budget):
        event = GovernanceEvent(
            event_type="agent.budget",
            session_id=ctx_with_budget.session_id,
            action="agent.budget",
            context=ctx_with_budget,
        )
        assert event.context.budget_total_tokens == 10000
        assert event.context.budget_used_tokens == 5000

    def test_serialization_roundtrip(self, ctx):
        event = GovernanceEvent(
            event_type="agent.spawn",
            session_id="s1",
            action="agent.spawn",
            context=ctx,
            requested_capabilities=["read"],
            data_classification="confidential",
        )
        data = event.model_dump()
        restored = GovernanceEvent(**data)
        assert restored.event_type == "agent.spawn"
        assert restored.data_classification == "confidential"

    def test_budget_fields_default_none(self):
        ctx = SessionContext(
            session_id="s1",
            user_role="admin",
            session_scopes=[],
        )
        assert ctx.budget_total_tokens is None
        assert ctx.budget_used_tokens is None
        assert ctx.budget_total_cost_cents is None


# ── OPAClient.evaluate_event tests ──────────────────────────────────────────


class TestOPAClientEvaluateEvent:
    async def test_evaluate_event_sends_correct_input(self, ctx):
        client = OPAClient()
        client._post_to_opa = AsyncMock(
            return_value={"allow": True, "deny": False, "risk_tier": "INFORMATIONAL"}
        )

        event = GovernanceEvent(
            event_type="agent.spawn",
            session_id="s1",
            action="agent.spawn",
            context=ctx,
            requested_capabilities=["read"],
        )
        decision = await client.evaluate_event(event)

        assert decision.allow is True
        # Verify the input structure sent to OPA
        call_args = client._post_to_opa.call_args[0][0]
        assert call_args["event_type"] == "agent.spawn"
        assert call_args["requested_capabilities"] == ["read"]

    async def test_evaluate_event_opa_unreachable_raises(self, ctx):
        client = OPAClient()
        client._post_to_opa = AsyncMock(side_effect=OPAConnectionError("down"))

        event = GovernanceEvent(
            event_type="agent.spawn",
            session_id="s1",
            action="agent.spawn",
            context=ctx,
        )
        with pytest.raises(OPAConnectionError):
            await client.evaluate_event(event)

    async def test_evaluate_event_deny_result(self, ctx):
        client = OPAClient()
        client._post_to_opa = AsyncMock(
            return_value={"allow": False, "deny": True, "risk_tier": "SECURITY_CRITICAL"}
        )

        event = GovernanceEvent(
            event_type="agent.spawn",
            session_id="s1",
            action="agent.spawn",
            context=ctx,
        )
        decision = await client.evaluate_event(event)
        assert decision.deny is True
        assert decision.risk_tier == RiskTier.SECURITY_CRITICAL


# ── PolicyGate.evaluate tests ────────────────────────────────────────────────


class TestPolicyGateEvaluate:
    async def test_evaluate_allows_spawn(self, gate, mock_opa, ctx, allow_decision):
        event = GovernanceEvent(
            event_type="agent.spawn",
            session_id=ctx.session_id,
            action="agent.spawn",
            context=ctx,
        )
        decision = await gate.evaluate(event)
        assert decision.allow is True
        mock_opa.evaluate_event.assert_awaited_once()

    async def test_evaluate_denies_spawn(self, mock_opa, ctx, deny_decision):
        mock_opa.evaluate_event.return_value = deny_decision
        gate = PolicyGate(opa_client=mock_opa)

        event = GovernanceEvent(
            event_type="agent.spawn",
            session_id=ctx.session_id,
            action="agent.spawn",
            context=ctx,
        )
        decision = await gate.evaluate(event)
        assert decision.deny is True

    async def test_evaluate_fails_closed_on_opa_error(self, mock_opa, ctx):
        mock_opa.evaluate_event.side_effect = OPAConnectionError("down")
        gate = PolicyGate(opa_client=mock_opa)

        event = GovernanceEvent(
            event_type="agent.spawn",
            session_id=ctx.session_id,
            action="agent.spawn",
            context=ctx,
        )
        decision = await gate.evaluate(event)
        assert decision.allow is False
        assert decision.deny is True
        assert "unreachable" in decision.reason.lower()

    async def test_evaluate_rejects_invalid_token(self, mock_opa, ctx):
        from kitelogik.anchor.credentials import CredentialBroker

        broker = CredentialBroker()
        gate = PolicyGate(opa_client=mock_opa, credential_broker=broker)

        ctx_with_bad_token = ctx.model_copy(update={"token_id": "nonexistent_token"})
        event = GovernanceEvent(
            event_type="agent.spawn",
            session_id=ctx.session_id,
            action="agent.spawn",
            context=ctx_with_bad_token,
        )
        decision = await gate.evaluate(event)
        assert decision.deny is True
        assert "token" in decision.reason.lower()

    async def test_evaluate_hitl_decision(self, mock_opa, ctx):
        hitl = PolicyDecision(
            allow=False,
            deny=False,
            risk_tier=RiskTier.TRANSACTIONAL_HIGH,
            requires_hitl=True,
            reason="Requires human approval",
        )
        mock_opa.evaluate_event.return_value = hitl
        gate = PolicyGate(opa_client=mock_opa)

        event = GovernanceEvent(
            event_type="agent.delegate",
            session_id=ctx.session_id,
            action="agent.delegate",
            context=ctx,
        )
        decision = await gate.evaluate(event)
        assert decision.requires_hitl is True
        assert decision.allow is False


# ── PolicyGate.evaluate_plan tests ───────────────────────────────────────────


class TestEvaluatePlan:
    async def test_evaluate_plan_allowed(self, gate, mock_opa, ctx, allow_decision):
        steps = [
            {"tool_name": "read_file", "args": {"path": "/data/report.csv"}},
            {"tool_name": "summarize", "args": {}},
        ]
        decision = await gate.evaluate_plan(steps, ctx)
        assert decision.allow is True

        # Verify the event sent to OPA has correct structure
        event_arg = mock_opa.evaluate_event.call_args[0][0]
        assert event_arg.event_type == "agent.plan"
        assert len(event_arg.steps) == 2

    async def test_evaluate_plan_denied(self, mock_opa, ctx, deny_decision):
        mock_opa.evaluate_event.return_value = deny_decision
        gate = PolicyGate(opa_client=mock_opa)

        steps = [{"tool_name": "execute_shell", "args": {"cmd": "rm -rf /"}}]
        decision = await gate.evaluate_plan(steps, ctx)
        assert decision.deny is True


# ── GovernedToolbox.evaluate_plan tests ──────────────────────────────────────


class TestGovernedToolboxEvaluatePlan:
    async def test_toolbox_evaluate_plan_allowed(self, gate, ctx, allow_decision):
        toolbox = GovernedToolbox(gate=gate, context=ctx)
        decision = await toolbox.evaluate_plan([{"tool_name": "read_file", "args": {}}])
        assert decision.allow is True

    async def test_toolbox_evaluate_plan_denied_raises(self, mock_opa, ctx, deny_decision):
        mock_opa.evaluate_event.return_value = deny_decision
        gate = PolicyGate(opa_client=mock_opa)
        toolbox = GovernedToolbox(gate=gate, context=ctx)

        with pytest.raises(GovernanceError, match="Plan denied"):
            await toolbox.evaluate_plan([{"tool_name": "execute_shell", "args": {}}])


# ── Agent spawn governance tests ─────────────────────────────────────────────


class TestAgentSpawnGovernance:
    async def test_spawn_blocked_raises_governance_error(self):
        """AgentSession.run_async() raises GovernanceError when spawn is denied."""
        from kitelogik.agents.session import AgentSession

        mock_gate = MagicMock(spec=PolicyGate)
        mock_gate.evaluate = AsyncMock(
            return_value=PolicyDecision(
                allow=False,
                deny=True,
                risk_tier=RiskTier.SECURITY_CRITICAL,
                requires_hitl=False,
                reason="Spawn denied: depth exceeded",
            )
        )
        mock_gate.evaluate_tool_call = AsyncMock()

        ctx = SessionContext(
            session_id="spawn_test",
            user_role="worker",
            session_scopes=["read"],
            delegation_depth=3,
        )

        mock_llm = MagicMock()
        session = AgentSession(gate=mock_gate, context=ctx, llm_client=mock_llm)
        with pytest.raises(GovernanceError, match="spawn denied"):
            await session.run_async("test prompt")

    async def test_spawn_allowed_proceeds_normally(self):
        """AgentSession.run_async() proceeds when spawn is allowed."""
        from kitelogik.agents.session import AgentSession

        allow = PolicyDecision(
            allow=True,
            deny=False,
            risk_tier=RiskTier.INFORMATIONAL,
            requires_hitl=False,
            reason="Allowed",
        )
        mock_gate = MagicMock(spec=PolicyGate)
        mock_gate.evaluate = AsyncMock(return_value=allow)
        mock_gate.evaluate_tool_call = AsyncMock(return_value=allow)
        mock_gate.sanitize_response = MagicMock(
            return_value=MagicMock(content="ok", was_modified=False)
        )

        ctx = SessionContext(
            session_id="spawn_ok",
            user_role="admin",
            session_scopes=["read"],
        )

        from kitelogik.agents.llm import LLMResponse

        mock_llm = MagicMock()
        mock_llm.create_message = AsyncMock(
            return_value=LLMResponse(
                stop_reason="end_turn",
                text_content="Done",
                tool_calls=[],
                raw_content="raw",
            )
        )

        session = AgentSession(gate=mock_gate, context=ctx, llm_client=mock_llm)
        result = await session.run_async("say hello")

        assert result.final_response == "Done"
