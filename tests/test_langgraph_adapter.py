# SPDX-License-Identifier: Apache-2.0
"""Tests for the LangGraph adapter."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import PolicyDecision, RiskTier, SessionContext


@pytest.fixture
def ctx():
    return SessionContext(session_id="test", user_role="admin", session_scopes=["read"])


@pytest.fixture
def allow_decision():
    return PolicyDecision(
        allow=True,
        deny=False,
        risk_tier=RiskTier.INFORMATIONAL,
        requires_hitl=False,
        reason="Allowed",
    )


@pytest.fixture
def deny_decision():
    return PolicyDecision(
        allow=False,
        deny=True,
        risk_tier=RiskTier.SECURITY_CRITICAL,
        requires_hitl=False,
        reason="Denied",
    )


@pytest.fixture
def mock_gate(allow_decision):
    gate = MagicMock(spec=PolicyGate)
    gate.evaluate_tool_call = AsyncMock(return_value=allow_decision)
    gate.sanitize_response = MagicMock(return_value=MagicMock(content="result", was_modified=False))
    return gate


def test_langgraph_import_guard():
    """Import guard raises clear error when langgraph is not installed."""
    from kitelogik.adapters.langgraph import _require_langgraph

    try:
        _require_langgraph()
    except ImportError as e:
        assert "langgraph" in str(e).lower()


async def test_as_governed_node_allows(mock_gate, ctx, allow_decision):
    from kitelogik.adapters.langgraph import as_governed_node

    async def search(query: str) -> str:
        return f"found: {query}"

    node = as_governed_node("search", search, gate=mock_gate, context=ctx)
    state = {"args": {"query": "test"}}
    result = await node(state)

    assert result["blocked"] is False
    assert result["result"] == "result"  # sanitized
    mock_gate.evaluate_tool_call.assert_awaited_once()


async def test_as_governed_node_denies(mock_gate, ctx, deny_decision):
    from kitelogik.adapters.langgraph import as_governed_node

    mock_gate.evaluate_tool_call = AsyncMock(return_value=deny_decision)

    async def search(query: str) -> str:
        return f"found: {query}"

    node = as_governed_node("search", search, gate=mock_gate, context=ctx)
    state = {"args": {"query": "test"}}
    result = await node(state)

    assert result["blocked"] is True
    assert "BLOCKED" in result["result"]


async def test_as_governed_node_sync_function(mock_gate, ctx):
    from kitelogik.adapters.langgraph import as_governed_node

    def calc(x: int, y: int) -> int:
        return x + y

    node = as_governed_node("calc", calc, gate=mock_gate, context=ctx)
    state = {"args": {"x": 2, "y": 3}}
    result = await node(state)

    assert result["blocked"] is False


async def test_as_governed_node_custom_action(mock_gate, ctx):
    from kitelogik.adapters.langgraph import as_governed_node

    def noop() -> str:
        return "ok"

    node = as_governed_node("noop", noop, gate=mock_gate, context=ctx, action="custom_action")
    state = {"args": {}}
    await node(state)

    call_args = mock_gate.evaluate_tool_call.call_args[0][0]
    assert call_args.action == "custom_action"
