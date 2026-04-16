# SPDX-License-Identifier: Apache-2.0
"""Tests for the PydanticAI adapter."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import PolicyDecision, RiskTier, SessionContext


@pytest.fixture
def ctx():
    return SessionContext(session_id="test", user_role="analyst", session_scopes=["read"])


@pytest.fixture
def mock_gate():
    gate = MagicMock(spec=PolicyGate)
    gate.evaluate_tool_call = AsyncMock(
        return_value=PolicyDecision(
            allow=True,
            deny=False,
            risk_tier=RiskTier.INFORMATIONAL,
            requires_hitl=False,
            reason="Allowed",
        )
    )
    gate.sanitize_response = MagicMock(return_value=MagicMock(content="result", was_modified=False))
    return gate


@pytest.fixture
def deny_gate():
    gate = MagicMock(spec=PolicyGate)
    gate.evaluate_tool_call = AsyncMock(
        return_value=PolicyDecision(
            allow=False,
            deny=True,
            risk_tier=RiskTier.SECURITY_CRITICAL,
            requires_hitl=False,
            reason="Denied",
        )
    )
    return gate


def test_import_guard():
    """Import guard raises clear error when pydantic-ai is not installed."""
    from kitelogik.adapters.pydantic_ai import _require_pydantic_ai

    try:
        _require_pydantic_ai()
    except ImportError as e:
        assert "pydantic-ai" in str(e).lower()


def test_register_chaining(mock_gate, ctx):
    from kitelogik.adapters.pydantic_ai import PydanticAIAdapter

    adapter = PydanticAIAdapter(gate=mock_gate, context=ctx)
    result = adapter.register("tool_a", lambda: "ok", description="Test tool")
    assert result is adapter


def test_register_multiple(mock_gate, ctx):
    from kitelogik.adapters.pydantic_ai import PydanticAIAdapter

    adapter = PydanticAIAdapter(gate=mock_gate, context=ctx)
    adapter.register("a", lambda: "a").register("b", lambda: "b")
    assert len(adapter._tools) == 2


async def test_execute_allowed(mock_gate, ctx):
    from kitelogik.adapters.pydantic_ai import PydanticAIAdapter

    adapter = PydanticAIAdapter(gate=mock_gate, context=ctx)
    adapter.register("read_data", lambda customer_id: f"data_{customer_id}")

    result = await adapter.execute("read_data", {"customer_id": "cust_001"})
    assert result == "result"  # sanitized content
    mock_gate.evaluate_tool_call.assert_called_once()


async def test_execute_denied(deny_gate, ctx):
    from kitelogik.adapters.pydantic_ai import PydanticAIAdapter

    adapter = PydanticAIAdapter(gate=deny_gate, context=ctx)
    adapter.register("delete_all", lambda: "deleted")

    result = await adapter.execute("delete_all", {})
    assert result["blocked"] is True
    assert "governance" in result["reason"].lower()


async def test_execute_unknown_tool(mock_gate, ctx):
    from kitelogik.adapters.pydantic_ai import PydanticAIAdapter

    adapter = PydanticAIAdapter(gate=mock_gate, context=ctx)
    result = await adapter.execute("nonexistent", {})
    assert "error" in result


def test_pydantic_tools_output(mock_gate, ctx):
    from kitelogik.adapters.pydantic_ai import PydanticAIAdapter

    adapter = PydanticAIAdapter(gate=mock_gate, context=ctx)
    adapter.register("tool_a", lambda: "a", description="Tool A")
    adapter.register("tool_b", lambda: "b", description="Tool B")

    tools = adapter.pydantic_tools()
    assert len(tools) == 2
    assert tools[0]["name"] == "tool_a"
    assert tools[0]["description"] == "Tool A"
    assert callable(tools[0]["function"])


async def test_execute_async_fn(mock_gate, ctx):
    from kitelogik.adapters.pydantic_ai import PydanticAIAdapter

    async def async_tool(x: str) -> str:
        return f"async_{x}"

    adapter = PydanticAIAdapter(gate=mock_gate, context=ctx)
    adapter.register("async_tool", async_tool)

    result = await adapter.execute("async_tool", {"x": "test"})
    assert result == "result"  # sanitized


def test_action_override(mock_gate, ctx):
    from kitelogik.adapters.pydantic_ai import PydanticAIAdapter

    adapter = PydanticAIAdapter(gate=mock_gate, context=ctx)
    adapter.register("my_tool", lambda: "ok", action="custom_action")

    _, action_name, _ = adapter._tools["my_tool"]
    assert action_name == "custom_action"
