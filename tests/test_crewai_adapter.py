# SPDX-License-Identifier: Apache-2.0
"""Tests for the CrewAI adapter.

CrewAI is not a hard dependency, so the governance-flow tests stub out
``crewai.tools.tool`` with an identity decorator via ``sys.modules``. That
is enough to drive the adapter's inner ``governed_tool`` callable and
verify the policy gate actually runs.
"""

import sys
import types
from unittest.mock import AsyncMock, MagicMock

import pytest

from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import PolicyDecision, RiskTier, SessionContext


@pytest.fixture
def ctx():
    return SessionContext(session_id="test", user_role="admin", session_scopes=["read"])


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
            reason="Denied by policy",
        )
    )
    return gate


@pytest.fixture
def stub_crewai(monkeypatch):
    """Install a minimal ``crewai.tools.tool`` stub so crewai_tools() works
    without the real dependency. The stub's ``tool(name)`` returns an identity
    decorator, which is enough to exercise the adapter's governance wrapper."""
    crewai_pkg = types.ModuleType("crewai")
    crewai_tools = types.ModuleType("crewai.tools")

    def _tool_decorator(_name):
        def _wrap(fn):
            return fn

        return _wrap

    crewai_tools.tool = _tool_decorator
    monkeypatch.setitem(sys.modules, "crewai", crewai_pkg)
    monkeypatch.setitem(sys.modules, "crewai.tools", crewai_tools)
    yield


def test_crewai_import_guard():
    """Import guard raises clear error when crewai is not installed."""
    from kitelogik.adapters.crewai import _require_crewai

    # CrewAI is likely not installed in test env
    try:
        _require_crewai()
    except ImportError as e:
        assert "crewai" in str(e).lower()


def test_crewai_adapter_register(mock_gate, ctx):
    from kitelogik.adapters.crewai import CrewAIAdapter

    adapter = CrewAIAdapter(gate=mock_gate, context=ctx)
    result = adapter.register("test_tool", lambda: "ok", description="A test tool")
    assert result is adapter  # chaining


def test_crewai_adapter_register_multiple(mock_gate, ctx):
    from kitelogik.adapters.crewai import CrewAIAdapter

    adapter = CrewAIAdapter(gate=mock_gate, context=ctx)
    adapter.register("a", lambda: "a").register("b", lambda: "b")
    assert len(adapter._tools) == 2


def test_crewai_register_raises_on_duplicate_name(mock_gate, ctx):
    """CrewAIAdapter.register raises on duplicate names."""
    from kitelogik.adapters.crewai import CrewAIAdapter

    adapter = CrewAIAdapter(gate=mock_gate, context=ctx)
    adapter.register("ping", lambda: "pong")
    with pytest.raises(ValueError, match="already registered"):
        adapter.register("ping", lambda: "twice")


# ── Governance-flow tests (use the stub_crewai fixture) ────────────────────


def test_crewai_allowed_call_runs_function_and_sanitizes(stub_crewai, mock_gate, ctx):
    """An allowed decision must let the underlying fn run and its string
    result must go through sanitize_response."""
    from kitelogik.adapters.crewai import CrewAIAdapter

    adapter = CrewAIAdapter(gate=mock_gate, context=ctx)
    adapter.register("search", lambda query: f"found:{query}", description="Search")

    [tool] = adapter.crewai_tools()
    out = tool(query="widgets")

    # sanitize_response fixture returns content="result"
    assert out == "result"
    mock_gate.evaluate_tool_call.assert_awaited_once()
    mock_gate.sanitize_response.assert_called_once()


def test_crewai_denied_call_returns_blocked_marker_and_skips_fn(stub_crewai, deny_gate, ctx):
    """A deny decision must short-circuit with a [BLOCKED] string and never
    invoke the underlying fn."""
    from kitelogik.adapters.crewai import CrewAIAdapter

    called = {"n": 0}

    def should_never_run(**_kw):
        called["n"] += 1
        return "should_not_happen"

    adapter = CrewAIAdapter(gate=deny_gate, context=ctx)
    adapter.register("delete_all", should_never_run)

    [tool] = adapter.crewai_tools()
    out = tool()

    assert isinstance(out, str)
    assert out.startswith("[BLOCKED]")
    assert called["n"] == 0


def test_crewai_async_fn_is_bridged_to_sync(stub_crewai, mock_gate, ctx):
    """CrewAI tools are called synchronously. Async tool functions must be
    bridged via _run_coroutine_sync."""
    from kitelogik.adapters.crewai import CrewAIAdapter

    async def async_fn(x):
        return f"async:{x}"

    adapter = CrewAIAdapter(gate=mock_gate, context=ctx)
    adapter.register("atool", async_fn)

    [tool] = adapter.crewai_tools()
    out = tool(x="hello")
    assert out == "result"  # sanitize_response fixture
