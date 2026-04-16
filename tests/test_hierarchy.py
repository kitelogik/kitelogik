# SPDX-License-Identifier: Apache-2.0
"""Tests for the 2-tier policy hierarchy (global + project)."""

from unittest.mock import AsyncMock

import pytest

from kitelogik.tether.hierarchy import HierarchicalEvaluator, _higher_risk, _merge_decisions
from kitelogik.tether.models import (
    GovernanceEvent,
    PolicyDecision,
    PolicyInput,
    RiskTier,
    SessionContext,
)


def _decision(
    allow: bool = True,
    deny: bool = False,
    risk_tier: RiskTier = RiskTier.INFORMATIONAL,
    requires_hitl: bool = False,
    reason: str = "ok",
    rule_matched: str | None = None,
) -> PolicyDecision:
    return PolicyDecision(
        allow=allow,
        deny=deny,
        risk_tier=risk_tier,
        requires_hitl=requires_hitl,
        reason=reason,
        rule_matched=rule_matched,
    )


def _mock_evaluator(decision: PolicyDecision) -> AsyncMock:
    mock = AsyncMock()
    mock.evaluate.return_value = decision
    mock.evaluate_event.return_value = decision
    mock.health.return_value = True
    return mock


@pytest.fixture
def ctx() -> SessionContext:
    return SessionContext(
        session_id="hier_test",
        user_role="analyst",
        session_scopes=["read"],
    )


@pytest.fixture
def policy_input(ctx) -> PolicyInput:
    return PolicyInput(
        action="read_file",
        tool_name="read_file",
        args={"path": "/data/report.csv"},
        context=ctx,
    )


@pytest.fixture
def gov_event(ctx) -> GovernanceEvent:
    return GovernanceEvent(
        event_type="agent.spawn",
        session_id=ctx.session_id,
        action="agent.spawn",
        context=ctx,
    )


# ── _higher_risk tests ─────────────────────────────────────────────────────


class TestHigherRisk:
    def test_same_tier(self):
        assert (
            _higher_risk(RiskTier.INFORMATIONAL, RiskTier.INFORMATIONAL) == RiskTier.INFORMATIONAL
        )

    def test_first_higher(self):
        assert _higher_risk(RiskTier.DESTRUCTIVE, RiskTier.OPERATIONAL) == RiskTier.DESTRUCTIVE

    def test_second_higher(self):
        assert (
            _higher_risk(RiskTier.INFORMATIONAL, RiskTier.SECURITY_CRITICAL)
            == RiskTier.SECURITY_CRITICAL
        )


# ── _merge_decisions tests ─────────────────────────────────────────────────


class TestMergeDecisions:
    def test_both_allow(self):
        g = _decision(allow=True, reason="global allow")
        p = _decision(allow=True, reason="project allow")
        merged = _merge_decisions(g, p)

        assert merged.allow is True
        assert merged.deny is False
        assert len(merged.resolution_trace) == 2
        assert merged.resolution_trace[0].tier == "global"
        assert merged.resolution_trace[1].tier == "project"

    def test_global_deny_wins(self):
        g = _decision(allow=False, deny=True, reason="global deny")
        p = _decision(allow=True, reason="project allow")
        merged = _merge_decisions(g, p)

        assert merged.allow is False
        assert merged.deny is True
        assert "[global]" in merged.reason

    def test_project_deny_wins(self):
        g = _decision(allow=True, reason="global allow")
        p = _decision(allow=False, deny=True, reason="project deny")
        merged = _merge_decisions(g, p)

        assert merged.allow is False
        assert merged.deny is True
        assert "[project]" in merged.reason

    def test_both_deny(self):
        g = _decision(allow=False, deny=True, reason="global deny")
        p = _decision(allow=False, deny=True, reason="project deny")
        merged = _merge_decisions(g, p)

        assert merged.deny is True
        assert "[global]" in merged.reason  # global takes priority in reason

    def test_risk_tier_takes_higher(self):
        g = _decision(allow=True, risk_tier=RiskTier.INFORMATIONAL)
        p = _decision(allow=True, risk_tier=RiskTier.TRANSACTIONAL_HIGH)
        merged = _merge_decisions(g, p)

        assert merged.risk_tier == RiskTier.TRANSACTIONAL_HIGH

    def test_hitl_from_either_tier(self):
        g = _decision(allow=True, requires_hitl=False)
        p = _decision(allow=True, requires_hitl=True)
        merged = _merge_decisions(g, p)

        assert merged.requires_hitl is True

    def test_neither_allow_nor_deny(self):
        g = _decision(allow=False, deny=False, reason="no match")
        p = _decision(allow=False, deny=False, reason="no match")
        merged = _merge_decisions(g, p)

        assert merged.allow is False
        assert merged.deny is False


# ── HierarchicalEvaluator tests ────────────────────────────────────────────


class TestHierarchicalEvaluator:
    async def test_both_allow(self, policy_input):
        g = _mock_evaluator(_decision(allow=True, reason="global ok"))
        p = _mock_evaluator(_decision(allow=True, reason="project ok"))
        evaluator = HierarchicalEvaluator(global_evaluator=g, project_evaluator=p)

        result = await evaluator.evaluate(policy_input)
        assert result.allow is True
        assert len(result.resolution_trace) == 2

    async def test_global_deny_short_circuits(self, policy_input):
        g = _mock_evaluator(
            _decision(
                allow=False,
                deny=True,
                risk_tier=RiskTier.SECURITY_CRITICAL,
                reason="blocked",
            )
        )
        p = _mock_evaluator(_decision(allow=True))
        evaluator = HierarchicalEvaluator(global_evaluator=g, project_evaluator=p)

        result = await evaluator.evaluate(policy_input)
        assert result.deny is True
        assert "[global]" in result.reason
        # Project evaluator should NOT have been called
        p.evaluate.assert_not_called()
        # But trace still has both tiers (project shows "skipped")
        assert len(result.resolution_trace) == 2
        assert result.resolution_trace[1].reason == "Skipped — global deny"

    async def test_project_can_further_restrict(self, policy_input):
        g = _mock_evaluator(_decision(allow=True, reason="global ok"))
        p = _mock_evaluator(_decision(allow=False, deny=True, reason="project blocks this"))
        evaluator = HierarchicalEvaluator(global_evaluator=g, project_evaluator=p)

        result = await evaluator.evaluate(policy_input)
        assert result.deny is True
        assert "[project]" in result.reason

    async def test_evaluate_event_both_allow(self, gov_event):
        g = _mock_evaluator(_decision(allow=True))
        p = _mock_evaluator(_decision(allow=True))
        evaluator = HierarchicalEvaluator(global_evaluator=g, project_evaluator=p)

        result = await evaluator.evaluate_event(gov_event)
        assert result.allow is True

    async def test_evaluate_event_global_deny_short_circuits(self, gov_event):
        g = _mock_evaluator(_decision(allow=False, deny=True, reason="no spawn"))
        p = _mock_evaluator(_decision(allow=True))
        evaluator = HierarchicalEvaluator(global_evaluator=g, project_evaluator=p)

        result = await evaluator.evaluate_event(gov_event)
        assert result.deny is True
        p.evaluate_event.assert_not_called()

    async def test_health_both_healthy(self):
        g = _mock_evaluator(_decision())
        p = _mock_evaluator(_decision())
        evaluator = HierarchicalEvaluator(global_evaluator=g, project_evaluator=p)

        assert await evaluator.health() is True

    async def test_health_one_unhealthy(self):
        g = _mock_evaluator(_decision())
        p = _mock_evaluator(_decision())
        p.health.return_value = False
        evaluator = HierarchicalEvaluator(global_evaluator=g, project_evaluator=p)

        assert await evaluator.health() is False

    async def test_resolution_trace_serializable(self, policy_input):
        g = _mock_evaluator(_decision(allow=True, reason="global", rule_matched="g_rule"))
        p = _mock_evaluator(_decision(allow=True, reason="project", rule_matched="p_rule"))
        evaluator = HierarchicalEvaluator(global_evaluator=g, project_evaluator=p)

        result = await evaluator.evaluate(policy_input)
        data = result.model_dump()
        assert len(data["resolution_trace"]) == 2
        assert data["resolution_trace"][0]["tier"] == "global"
        assert data["resolution_trace"][0]["rule_matched"] == "g_rule"
        assert data["resolution_trace"][1]["tier"] == "project"
