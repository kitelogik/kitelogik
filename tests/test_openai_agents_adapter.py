# SPDX-License-Identifier: Apache-2.0
"""Tests for the OpenAI Agents SDK adapter.

openai-agents is not a hard dependency. The governance-flow tests install a
minimal ``agents`` module stub via ``sys.modules`` with a ``FunctionTool``
class that retains the ``on_invoke_tool`` coroutine, which is enough to
drive the policy gate and assert allow/deny behavior."""

import json
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
def stub_openai_agents(monkeypatch):
    """Install a minimal ``agents.FunctionTool`` stub so agent_tools() works
    without the real openai-agents package. The stub mirrors the real
    constructor signature exactly: ``on_invoke_tool(ctx: ToolContext, input: str)``
    where ``input`` is a JSON-encoded args string."""
    agents_pkg = types.ModuleType("agents")

    class FunctionTool:  # noqa: D401 — stub mirrors the real class surface used here
        def __init__(
            self,
            name,
            description,
            params_json_schema,
            on_invoke_tool,
            strict_json_schema=True,
        ):
            self.name = name
            self.description = description
            self.params_json_schema = params_json_schema
            self.on_invoke_tool = on_invoke_tool
            self.strict_json_schema = strict_json_schema

    agents_pkg.FunctionTool = FunctionTool
    monkeypatch.setitem(sys.modules, "agents", agents_pkg)
    yield FunctionTool


def test_openai_agents_import_guard():
    """Import guard raises clear error when openai-agents is not installed."""
    from kitelogik.adapters.openai_agents import _require_openai_agents

    try:
        _require_openai_agents()
    except ImportError as e:
        assert "openai-agents" in str(e).lower()


def test_openai_agents_adapter_register(mock_gate, ctx):
    from kitelogik.adapters.openai_agents import OpenAIAgentsAdapter

    adapter = OpenAIAgentsAdapter(gate=mock_gate, context=ctx)
    result = adapter.register("search", lambda q: f"found: {q}", description="Search")
    assert result is adapter  # chaining


def test_openai_agents_adapter_register_with_params(mock_gate, ctx):
    from kitelogik.adapters.openai_agents import OpenAIAgentsAdapter

    adapter = OpenAIAgentsAdapter(gate=mock_gate, context=ctx)
    adapter.register(
        "search",
        lambda query: f"found: {query}",
        description="Search",
        params={"query": {"type": "string"}},
    )
    assert "search" in adapter._tools
    assert adapter._tools["search"][3] == {"query": {"type": "string"}}


# ── Governance-flow tests (use the stub_openai_agents fixture) ─────────────


def test_agent_tools_builds_function_tool_with_schema(stub_openai_agents, mock_gate, ctx):
    from kitelogik.adapters.openai_agents import OpenAIAgentsAdapter

    adapter = OpenAIAgentsAdapter(gate=mock_gate, context=ctx)
    adapter.register(
        "search",
        lambda query: f"found:{query}",
        description="Search docs",
        params={"query": {"type": "string"}},
    )

    [tool] = adapter.agent_tools()
    assert tool.name == "search"
    assert tool.description == "Search docs"
    assert tool.params_json_schema == {
        "type": "object",
        "properties": {"query": {"type": "string"}},
    }
    # strict_json_schema=False so register(params=...) doesn't have to
    # carry the strict-mode boilerplate.
    assert tool.strict_json_schema is False


async def test_agent_tool_allowed_call_runs_and_sanitizes(stub_openai_agents, mock_gate, ctx):
    from kitelogik.adapters.openai_agents import OpenAIAgentsAdapter

    adapter = OpenAIAgentsAdapter(gate=mock_gate, context=ctx)
    adapter.register("search", lambda query: f"found:{query}")

    [tool] = adapter.agent_tools()
    # Real Agents SDK invokes `on_invoke_tool(ctx, json_args_str)` —
    # two positional args, second is a JSON string.
    out = await tool.on_invoke_tool(None, json.dumps({"query": "widgets"}))

    assert out == "result"  # sanitize_response fixture
    mock_gate.evaluate_tool_call.assert_awaited_once()
    mock_gate.sanitize_response.assert_called_once()


async def test_agent_tool_denied_call_returns_blocked_json_and_skips_fn(
    stub_openai_agents, deny_gate, ctx
):
    from kitelogik.adapters.openai_agents import OpenAIAgentsAdapter

    called = {"n": 0}

    def should_never_run(**_kw):
        called["n"] += 1
        return "should_not_happen"

    adapter = OpenAIAgentsAdapter(gate=deny_gate, context=ctx)
    adapter.register("delete_all", should_never_run)

    [tool] = adapter.agent_tools()
    out = await tool.on_invoke_tool(None, "{}")

    payload = json.loads(out)
    assert payload["blocked"] is True
    assert "Denied by policy" in payload["reason"]
    assert called["n"] == 0


async def test_agent_tool_async_fn_is_awaited(stub_openai_agents, mock_gate, ctx):
    from kitelogik.adapters.openai_agents import OpenAIAgentsAdapter

    async def async_fn(x):
        return f"async:{x}"

    adapter = OpenAIAgentsAdapter(gate=mock_gate, context=ctx)
    adapter.register("atool", async_fn)

    [tool] = adapter.agent_tools()
    out = await tool.on_invoke_tool(None, json.dumps({"x": "hello"}))
    assert out == "result"


async def test_agent_tool_malformed_json_returns_error(stub_openai_agents, mock_gate, ctx):
    """Regression: a malformed JSON args string must surface a clean error,
    not an unhandled exception that the SDK propagates as a tool failure."""
    from kitelogik.adapters.openai_agents import OpenAIAgentsAdapter

    adapter = OpenAIAgentsAdapter(gate=mock_gate, context=ctx)
    adapter.register("search", lambda **_: "ok")

    [tool] = adapter.agent_tools()
    out = await tool.on_invoke_tool(None, "{not: valid}")
    payload = json.loads(out)
    assert "error" in payload
    assert "malformed" in payload["error"].lower()
    mock_gate.evaluate_tool_call.assert_not_awaited()


async def test_agent_tool_empty_input_treated_as_no_args(stub_openai_agents, mock_gate, ctx):
    """An empty ``input`` is a legitimate no-arg call (the SDK passes ``""``
    when the tool's params are empty); it must not raise."""
    from kitelogik.adapters.openai_agents import OpenAIAgentsAdapter

    adapter = OpenAIAgentsAdapter(gate=mock_gate, context=ctx)
    adapter.register("ping", lambda: "pong")

    [tool] = adapter.agent_tools()
    out = await tool.on_invoke_tool(None, "")
    assert out == "result"


# ── Real openai-agents integration smoke test ──────────────────────────────

agents_real = pytest.importorskip("agents", reason="openai-agents not installed")


def test_real_agents_sdk_accepts_governed_function_tools(mock_gate, ctx):
    """Smoke test against the real openai-agents package — governed
    FunctionTool instances must pass the SDK's type checks so they can
    be handed to ``Agent(tools=...)`` directly.
    """
    from agents import Agent, FunctionTool

    from kitelogik.adapters.openai_agents import OpenAIAgentsAdapter

    adapter = OpenAIAgentsAdapter(gate=mock_gate, context=ctx)
    adapter.register(
        "lookup",
        lambda key: f"value:{key}",
        description="Look up a value",
        params={"key": {"type": "string"}},
    )

    tools = adapter.agent_tools()
    assert all(isinstance(t, FunctionTool) for t in tools)

    # Constructing the Agent must not raise — this catches schema and
    # signature mismatches that plain unit tests miss.
    agent = Agent(name="kl_smoke", instructions="test", tools=tools)
    assert len(agent.tools) == 1


async def test_real_agents_sdk_on_invoke_signature_matches(mock_gate, ctx):
    """Calls ``on_invoke_tool`` with the real SDK calling convention
    ``(ToolContext, json_str)`` to lock the signature contract."""
    from kitelogik.adapters.openai_agents import OpenAIAgentsAdapter

    adapter = OpenAIAgentsAdapter(gate=mock_gate, context=ctx)
    adapter.register("echo", lambda msg: f"echo:{msg}")

    [tool] = adapter.agent_tools()
    # Pass a real-ish ToolContext-shaped object — the wrapper ignores it,
    # so an opaque object suffices for the signature contract test.
    fake_ctx = object()
    out = await tool.on_invoke_tool(fake_ctx, json.dumps({"msg": "hi"}))
    assert out == "result"


# ── Multi-agent governance helpers ──────────────────────────────────────────


@pytest.fixture
def allow_event_gate():
    """Mock gate that allows agent.delegate events as well as tool calls."""
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
    gate.evaluate = AsyncMock(
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
def deny_event_gate():
    """Mock gate that denies agent.delegate events."""
    gate = MagicMock(spec=PolicyGate)
    gate.evaluate = AsyncMock(
        return_value=PolicyDecision(
            allow=False,
            deny=True,
            risk_tier=RiskTier.SECURITY_CRITICAL,
            requires_hitl=False,
            reason="Delegation denied by policy",
        )
    )
    gate.sanitize_response = MagicMock(return_value=MagicMock(content="result", was_modified=False))
    return gate


def test_register_handoff_returns_real_handoff_object(allow_event_gate, ctx):
    """``register_handoff`` returns an ``agents.Handoff`` ready for
    ``Agent(handoffs=[...])``."""
    pytest.importorskip("agents", reason="openai-agents not installed")
    from agents import Agent, Handoff

    from kitelogik.adapters.openai_agents import OpenAIAgentsAdapter

    target = Agent(name="billing_specialist", instructions="bill")
    adapter = OpenAIAgentsAdapter(gate=allow_event_gate, context=ctx)

    h = adapter.register_handoff(target)
    assert isinstance(h, Handoff)
    parent = Agent(name="router", instructions="route", handoffs=[h])
    assert len(parent.handoffs) == 1


async def test_register_handoff_runs_user_callback_on_allow(allow_event_gate, ctx):
    """When governance allows, the user's ``on_handoff`` callback fires."""
    pytest.importorskip("agents", reason="openai-agents not installed")
    from agents import Agent

    from kitelogik.adapters.openai_agents import OpenAIAgentsAdapter

    fired = {"n": 0}

    def my_callback(_ctx):
        fired["n"] += 1

    target = Agent(name="billing", instructions="bill")
    adapter = OpenAIAgentsAdapter(gate=allow_event_gate, context=ctx)
    h = adapter.register_handoff(target, on_handoff=my_callback)

    await h.on_invoke_handoff(None, "")
    assert fired["n"] == 1
    allow_event_gate.evaluate.assert_awaited_once()


async def test_register_handoff_blocks_when_governance_denies(deny_event_gate, ctx):
    """A denied delegation propagates an error; user callback never runs."""
    pytest.importorskip("agents", reason="openai-agents not installed")
    from agents import Agent

    from kitelogik.adapters.openai_agents import OpenAIAgentsAdapter
    from kitelogik.governed import GovernanceError

    fired = {"n": 0}

    def my_callback(_ctx):
        fired["n"] += 1

    target = Agent(name="restricted", instructions="x")
    adapter = OpenAIAgentsAdapter(gate=deny_event_gate, context=ctx)
    h = adapter.register_handoff(target, on_handoff=my_callback)

    with pytest.raises(GovernanceError):
        await h.on_invoke_handoff(None, "")
    assert fired["n"] == 0


def test_register_agent_as_tool_returns_function_tool(allow_event_gate, ctx):
    """``register_agent_as_tool`` produces a real ``FunctionTool``."""
    pytest.importorskip("agents", reason="openai-agents not installed")
    from agents import Agent, FunctionTool

    from kitelogik.adapters.openai_agents import OpenAIAgentsAdapter

    inner = Agent(name="researcher", instructions="research")
    adapter = OpenAIAgentsAdapter(gate=allow_event_gate, context=ctx)

    tool = adapter.register_agent_as_tool(
        inner, tool_name="ask_researcher", tool_description="Run a research query"
    )
    assert isinstance(tool, FunctionTool)
    assert tool.name == "ask_researcher"


async def test_register_agent_as_tool_blocks_invocation_when_denied(deny_event_gate, ctx):
    """A denied delegation surfaces a JSON blocked payload to the model."""
    pytest.importorskip("agents", reason="openai-agents not installed")
    from agents import Agent

    from kitelogik.adapters.openai_agents import OpenAIAgentsAdapter

    inner = Agent(name="restricted", instructions="x")
    adapter = OpenAIAgentsAdapter(gate=deny_event_gate, context=ctx)
    tool = adapter.register_agent_as_tool(
        inner, tool_name="ask_restricted", tool_description="Restricted"
    )

    out = await tool.on_invoke_tool(None, "{}")
    payload = json.loads(out)
    assert payload["blocked"] is True
    assert "Delegation denied by policy" in payload["reason"]


async def test_governed_handoff_free_function_runs_gate(allow_event_gate, ctx):
    """The free function in ``_base`` is the framework-agnostic path: any
    framework or hand-rolled multi-agent code can call it directly to
    gate an ``agent.delegate`` event."""
    from kitelogik.adapters._base import governed_handoff

    await governed_handoff(
        gate=allow_event_gate,
        context=ctx,
        target="downstream",
        requested_capabilities=["read_orders"],
    )
    allow_event_gate.evaluate.assert_awaited_once()


async def test_governed_handoff_free_function_raises_on_deny(deny_event_gate, ctx):
    """Free function raises GovernanceError on deny so callers can branch."""
    from kitelogik.adapters._base import governed_handoff
    from kitelogik.governed import GovernanceError

    with pytest.raises(GovernanceError):
        await governed_handoff(gate=deny_event_gate, context=ctx, target="downstream")
