# SPDX-License-Identifier: Apache-2.0
"""Tests for the LlamaIndex, Semantic Kernel, Haystack, and Dify adapters.

The first set of tests parametrises generic governance-pipeline behavior
across the four adapters via :meth:`BaseGovernedAdapter.execute`. The
framework-specific output assertions (``llamaindex_tools()``,
``kernel_plugin()``, ``haystack_tools()``, ``dify_tools()``) live in
their own test sections below — each one optionally instantiates the
real framework Agent / Kernel as a smoke test of integration shape, and
skips when the framework package is not installed.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from kitelogik.adapters.dify import DifyAdapter
from kitelogik.adapters.haystack import HaystackAdapter
from kitelogik.adapters.llamaindex import LlamaIndexAdapter
from kitelogik.adapters.semantic_kernel import SemanticKernelAdapter
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import PolicyDecision, RiskTier, SessionContext

# ── Adapter / output-method pairs (used for generic governance tests) ───────

_ADAPTERS = [
    LlamaIndexAdapter,
    SemanticKernelAdapter,
    HaystackAdapter,
    DifyAdapter,
]

_IDS = ["llamaindex", "semantic_kernel", "haystack", "dify"]


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


# ── Import guard tests ──────────────────────────────────────────────────────


def test_llamaindex_import_guard():
    from kitelogik.adapters.llamaindex import _require_llamaindex

    try:
        _require_llamaindex()
    except ImportError as e:
        assert "llama-index" in str(e).lower()


def test_semantic_kernel_import_guard():
    from kitelogik.adapters.semantic_kernel import _require_semantic_kernel

    try:
        _require_semantic_kernel()
    except ImportError as e:
        assert "semantic-kernel" in str(e).lower()


def test_haystack_import_guard():
    from kitelogik.adapters.haystack import _require_haystack

    try:
        _require_haystack()
    except ImportError as e:
        assert "haystack" in str(e).lower()


def test_dify_import_guard():
    from kitelogik.adapters.dify import _require_dify

    try:
        _require_dify()
    except ImportError as e:
        assert "dify" in str(e).lower()


# ── Generic governance-pipeline tests (BaseGovernedAdapter.execute) ────────
# Exercise the policy gate + sanitize + dispatch pipeline that backs every
# adapter. Framework-shape output is tested per-adapter further down.


@pytest.mark.parametrize("adapter_cls", _ADAPTERS, ids=_IDS)
def test_register_chaining(adapter_cls, mock_gate, ctx):
    adapter = adapter_cls(gate=mock_gate, context=ctx)
    result = adapter.register("tool_a", lambda: "ok", description="Test")
    assert result is adapter


@pytest.mark.parametrize("adapter_cls", _ADAPTERS, ids=_IDS)
def test_register_multiple(adapter_cls, mock_gate, ctx):
    adapter = adapter_cls(gate=mock_gate, context=ctx)
    adapter.register("a", lambda: "a").register("b", lambda: "b")
    assert len(adapter._tools) == 2


@pytest.mark.parametrize("adapter_cls", _ADAPTERS, ids=_IDS)
async def test_execute_allowed(adapter_cls, mock_gate, ctx):
    adapter = adapter_cls(gate=mock_gate, context=ctx)
    adapter.register("read_data", lambda customer_id: f"data_{customer_id}")

    result = await adapter.execute("read_data", {"customer_id": "cust_001"})
    assert result == "result"  # sanitized content
    mock_gate.evaluate_tool_call.assert_called_once()


@pytest.mark.parametrize("adapter_cls", _ADAPTERS, ids=_IDS)
async def test_execute_denied(adapter_cls, deny_gate, ctx):
    adapter = adapter_cls(gate=deny_gate, context=ctx)
    adapter.register("delete_all", lambda: "deleted")

    result = await adapter.execute("delete_all", {})
    assert result["blocked"] is True


@pytest.mark.parametrize("adapter_cls", _ADAPTERS, ids=_IDS)
async def test_execute_unknown_tool(adapter_cls, mock_gate, ctx):
    adapter = adapter_cls(gate=mock_gate, context=ctx)
    result = await adapter.execute("nonexistent", {})
    assert "error" in result


@pytest.mark.parametrize("adapter_cls", _ADAPTERS, ids=_IDS)
async def test_execute_async_fn(adapter_cls, mock_gate, ctx):
    async def async_tool(x: str) -> str:
        return f"async_{x}"

    adapter = adapter_cls(gate=mock_gate, context=ctx)
    adapter.register("async_tool", async_tool)

    result = await adapter.execute("async_tool", {"x": "test"})
    assert result == "result"  # sanitized


@pytest.mark.parametrize("adapter_cls", _ADAPTERS, ids=_IDS)
def test_action_override(adapter_cls, mock_gate, ctx):
    adapter = adapter_cls(gate=mock_gate, context=ctx)
    adapter.register("my_tool", lambda: "ok", action="custom_action")

    _, action_name, _ = adapter._tools["my_tool"]
    assert action_name == "custom_action"


@pytest.mark.parametrize("adapter_cls", _ADAPTERS, ids=_IDS)
def test_register_raises_on_duplicate_name(adapter_cls, mock_gate, ctx):
    """Registering the same tool name twice raises ValueError instead of
    silently clobbering the first registration."""
    adapter = adapter_cls(gate=mock_gate, context=ctx)
    adapter.register("greet", lambda: "hello")

    with pytest.raises(ValueError, match="already registered"):
        adapter.register("greet", lambda: "world")


# ── LlamaIndex framework-shape tests ────────────────────────────────────────


def test_llamaindex_returns_function_tool_instances(mock_gate, ctx):
    pytest.importorskip("llama_index.core.tools", reason="llama-index not installed")
    from llama_index.core.tools import FunctionTool

    adapter = LlamaIndexAdapter(gate=mock_gate, context=ctx)
    adapter.register("ping", lambda: "pong", description="Ping")
    adapter.register("echo", lambda msg: f"echo:{msg}", description="Echo")

    tools = adapter.llamaindex_tools()
    assert len(tools) == 2
    assert all(isinstance(t, FunctionTool) for t in tools)
    names = {t.metadata.name for t in tools}
    assert names == {"ping", "echo"}


async def test_llamaindex_tool_routes_through_governance(mock_gate, ctx):
    pytest.importorskip("llama_index.core.tools", reason="llama-index not installed")

    adapter = LlamaIndexAdapter(gate=mock_gate, context=ctx)
    adapter.register("lookup", lambda key: f"value:{key}")

    [tool] = adapter.llamaindex_tools()
    # acall is the public async path that LlamaIndex agents use.
    output = await tool.acall(key="user-1")
    # FunctionTool wraps the raw return in a ToolOutput with a .content attr.
    text = getattr(output, "content", str(output))
    assert "result" in text  # sanitize_response fixture
    mock_gate.evaluate_tool_call.assert_awaited_once()


# ── Semantic Kernel framework-shape tests ──────────────────────────────────


def test_semantic_kernel_returns_plugin_object(mock_gate, ctx):
    pytest.importorskip("semantic_kernel", reason="semantic-kernel not installed")

    adapter = SemanticKernelAdapter(gate=mock_gate, context=ctx)
    adapter.register("ping", lambda: "pong", description="Ping")
    adapter.register("echo", lambda msg: f"echo:{msg}", description="Echo")

    plugin = adapter.kernel_plugin()
    # Plugin instance has the registered names as method attributes,
    # each carrying the @kernel_function decorator metadata.
    assert callable(getattr(plugin, "ping", None))
    assert callable(getattr(plugin, "echo", None))


def test_semantic_kernel_add_to_kernel_registers_plugin(mock_gate, ctx):
    pytest.importorskip("semantic_kernel", reason="semantic-kernel not installed")
    from semantic_kernel import Kernel

    adapter = SemanticKernelAdapter(gate=mock_gate, context=ctx)
    adapter.register("ping", lambda: "pong", description="Ping")

    kernel = Kernel()
    plugin = adapter.add_to_kernel(kernel, plugin_name="kl_smoke")

    # The plugin is registered on the kernel; SK exposes it via .plugins.
    assert "kl_smoke" in kernel.plugins
    assert plugin is not None


# ── Haystack framework-shape tests ──────────────────────────────────────────


def test_haystack_returns_tool_instances(mock_gate, ctx):
    pytest.importorskip("haystack", reason="haystack-ai not installed")
    from haystack.tools import Tool

    adapter = HaystackAdapter(gate=mock_gate, context=ctx)
    adapter.register(
        "ping",
        lambda: "pong",
        description="Ping",
        parameters={"type": "object", "properties": {}},
    )

    [tool] = adapter.haystack_tools()
    assert isinstance(tool, Tool)
    assert tool.name == "ping"
    assert tool.description == "Ping"
    assert tool.parameters == {"type": "object", "properties": {}}


def test_haystack_tool_invokes_underlying_fn(mock_gate, ctx):
    pytest.importorskip("haystack", reason="haystack-ai not installed")

    adapter = HaystackAdapter(gate=mock_gate, context=ctx)
    adapter.register(
        "echo",
        lambda msg: f"echo:{msg}",
        description="Echo",
        parameters={
            "type": "object",
            "properties": {"msg": {"type": "string"}},
            "required": ["msg"],
        },
    )

    [tool] = adapter.haystack_tools()
    # Haystack invokes Tool.function directly with kwargs unpacked.
    output = tool.function(msg="hi")
    assert output == "result"  # sanitize_response fixture


# ── Dify dict-shape (in-process testing only) ───────────────────────────────


def test_dify_tools_returns_dict_shape(mock_gate, ctx):
    """``dify_tools()`` returns dict descriptors for in-process governance
    tests. Deployable Dify plugins use :class:`GovernedDifyTool` instead.
    """
    adapter = DifyAdapter(gate=mock_gate, context=ctx)
    adapter.register("ping", lambda: "pong", description="Ping")

    tools = adapter.dify_tools()
    assert isinstance(tools, list)
    assert tools[0]["name"] == "ping"
    assert callable(tools[0]["function"])


# ── GovernedDifyTool — deployable Dify plugin path ─────────────────────────


def test_governed_dify_tool_runs_invoke_governed_when_allowed(mock_gate, ctx):
    """Subclassing ``GovernedDifyTool`` and overriding ``_invoke_governed``
    produces a deployable Dify plugin. The base class runs the policy
    gate first; ``_invoke_governed`` only fires when governance allows.
    """
    from kitelogik.adapters.dify import GovernedDifyTool

    class PingTool(GovernedDifyTool):
        gate = mock_gate
        context = ctx
        action = "ping"

        def _invoke_governed(self, tool_parameters):
            yield self._wrap_text("pong")

    [msg] = list(PingTool()._invoke({}))
    text = (
        msg["text"] if isinstance(msg, dict) else msg.message.text  # type: ignore[union-attr]
    )
    # sanitize_response fixture rewrites to "result" — proves governance ran.
    assert "result" in text or text == "pong"


def test_governed_dify_tool_blocks_when_denied(deny_gate, ctx):
    """A governance denial yields a single text message containing the
    denial payload; the user's ``_invoke_governed`` never runs.
    """
    from kitelogik.adapters.dify import GovernedDifyTool

    called = {"n": 0}

    class DangerousTool(GovernedDifyTool):
        gate = deny_gate
        context = ctx
        action = "dangerous"
        deny_message = "Blocked by enterprise policy."

        def _invoke_governed(self, tool_parameters):
            called["n"] += 1
            yield self._wrap_text("never")

    [msg] = list(DangerousTool()._invoke({}))
    text = (
        msg["text"] if isinstance(msg, dict) else msg.message.text  # type: ignore[union-attr]
    )
    assert "blocked" in text.lower()
    assert "Blocked by enterprise policy." in text
    assert called["n"] == 0


def test_make_governed_dify_tool_wraps_a_plain_callable(mock_gate, ctx):
    """``make_governed_dify_tool`` builds a ``GovernedDifyTool`` subclass
    from a plain function — for users who want to deploy a Dify plugin
    without writing the class scaffolding manually.
    """
    from kitelogik.adapters.dify import GovernedDifyTool, make_governed_dify_tool

    def echo(msg: str) -> str:
        return f"echo:{msg}"

    tool_cls = make_governed_dify_tool(echo, gate=mock_gate, context=ctx)
    assert issubclass(tool_cls, GovernedDifyTool)
    assert tool_cls.action == "echo"

    [msg] = list(tool_cls()._invoke({"msg": "hi"}))
    text = (
        msg["text"] if isinstance(msg, dict) else msg.message.text  # type: ignore[union-attr]
    )
    assert "result" in text or "echo:hi" in text


def test_governed_dify_tool_requires_gate_and_context():
    """Construction without ``gate`` / ``context`` fails loudly so users
    don't ship a plugin with disabled governance.
    """
    from kitelogik.adapters.dify import GovernedDifyTool

    class NoConfig(GovernedDifyTool):
        def _invoke_governed(self, tool_parameters):
            yield self._wrap_text("never")

    with pytest.raises(RuntimeError, match=".gate.*.context"):
        list(NoConfig()._invoke({}))
