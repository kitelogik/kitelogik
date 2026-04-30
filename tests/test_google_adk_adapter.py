# SPDX-License-Identifier: Apache-2.0
"""Tests for the Google ADK adapter."""

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
    """Import guard raises clear error when google-adk is not installed."""
    from kitelogik.adapters.google_adk import _require_google_adk

    try:
        _require_google_adk()
    except ImportError as e:
        assert "google-adk" in str(e).lower()


def test_register_chaining(mock_gate, ctx):
    from kitelogik.adapters.google_adk import GoogleADKAdapter

    adapter = GoogleADKAdapter(gate=mock_gate, context=ctx)
    result = adapter.register("tool_a", lambda: "ok", description="Test tool")
    assert result is adapter


def test_register_multiple(mock_gate, ctx):
    from kitelogik.adapters.google_adk import GoogleADKAdapter

    adapter = GoogleADKAdapter(gate=mock_gate, context=ctx)
    adapter.register("a", lambda: "a").register("b", lambda: "b")
    assert len(adapter._tools) == 2


async def test_execute_allowed(mock_gate, ctx):
    from kitelogik.adapters.google_adk import GoogleADKAdapter

    adapter = GoogleADKAdapter(gate=mock_gate, context=ctx)
    adapter.register("read_data", lambda customer_id: f"data_{customer_id}")

    result = await adapter.execute("read_data", {"customer_id": "cust_001"})
    assert result == "result"  # sanitized content
    mock_gate.evaluate_tool_call.assert_called_once()


async def test_execute_denied(deny_gate, ctx):
    from kitelogik.adapters.google_adk import GoogleADKAdapter

    adapter = GoogleADKAdapter(gate=deny_gate, context=ctx)
    adapter.register("delete_all", lambda: "deleted")

    result = await adapter.execute("delete_all", {})
    assert result["blocked"] is True
    assert "governance" in result["reason"].lower()


async def test_execute_unknown_tool(mock_gate, ctx):
    from kitelogik.adapters.google_adk import GoogleADKAdapter

    adapter = GoogleADKAdapter(gate=mock_gate, context=ctx)
    result = await adapter.execute("nonexistent", {})
    assert "error" in result


def test_adk_tools_returns_callables_with_preserved_signatures(mock_gate, ctx):
    """ADK introspects the callable's signature to build its tool schema.
    The wrapper must therefore preserve the original function's signature
    via ``functools.wraps`` — a generic ``**kwargs`` wrapper would yield
    no parameters and an empty schema."""
    import inspect

    from kitelogik.adapters.google_adk import GoogleADKAdapter

    def get_record(customer_id: str, fields: list[str] | None = None) -> str:
        """Get a customer record."""
        return f"record:{customer_id}"

    adapter = GoogleADKAdapter(gate=mock_gate, context=ctx)
    adapter.register("get_record", get_record, description="Lookup a record")
    adapter.register("ping", lambda: "pong", description="Ping")

    tools = adapter.adk_tools()
    assert len(tools) == 2
    assert all(callable(t) for t in tools)

    # Original signature is preserved (so ADK can build the JSON schema).
    sig = inspect.signature(tools[0])
    assert "customer_id" in sig.parameters
    assert "fields" in sig.parameters
    assert tools[0].__name__ == "get_record"
    assert "Get a customer record." in (tools[0].__doc__ or "")


def test_adk_tools_plug_into_real_agent(mock_gate, ctx):
    """Integration smoke test: governed callables must be acceptable to
    ``google.adk.Agent(tools=...)``."""
    pytest.importorskip("google.adk", reason="google-adk not installed")
    from google.adk import Agent

    from kitelogik.adapters.google_adk import GoogleADKAdapter

    def lookup(key: str) -> str:
        """Look up a value by key."""
        return f"value:{key}"

    adapter = GoogleADKAdapter(gate=mock_gate, context=ctx)
    adapter.register("lookup", lookup, description="Lookup a value")

    agent = Agent(name="kl_smoke", model="gemini-2.0-flash", tools=adapter.adk_tools())
    assert len(agent.tools) == 1


async def test_execute_async_fn(mock_gate, ctx):
    from kitelogik.adapters.google_adk import GoogleADKAdapter

    async def async_tool(x: str) -> str:
        return f"async_{x}"

    adapter = GoogleADKAdapter(gate=mock_gate, context=ctx)
    adapter.register("async_tool", async_tool)

    result = await adapter.execute("async_tool", {"x": "test"})
    assert result == "result"  # sanitized


def test_action_override(mock_gate, ctx):
    from kitelogik.adapters.google_adk import GoogleADKAdapter

    adapter = GoogleADKAdapter(gate=mock_gate, context=ctx)
    adapter.register("my_tool", lambda: "ok", action="custom_action")

    _, action_name, _ = adapter._tools["my_tool"]
    assert action_name == "custom_action"
