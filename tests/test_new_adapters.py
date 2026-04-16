# SPDX-License-Identifier: Apache-2.0
"""Tests for the LlamaIndex, Semantic Kernel, Haystack, and Dify adapters.

All four adapters inherit from BaseGovernedAdapter so we parametrize
the same test cases across all of them.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from kitelogik.adapters.dify import DifyAdapter
from kitelogik.adapters.haystack import HaystackAdapter
from kitelogik.adapters.llamaindex import LlamaIndexAdapter
from kitelogik.adapters.semantic_kernel import SemanticKernelAdapter
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import PolicyDecision, RiskTier, SessionContext

# ── Adapter / tools-method pairs ────────────────────────────────────────────

_ADAPTERS = [
    (LlamaIndexAdapter, "llamaindex_tools"),
    (SemanticKernelAdapter, "kernel_functions"),
    (HaystackAdapter, "haystack_tools"),
    (DifyAdapter, "dify_tools"),
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


# ── Parametrized tests across all adapters ──────────────────────────────────


@pytest.mark.parametrize("adapter_cls,tools_method", _ADAPTERS, ids=_IDS)
def test_register_chaining(adapter_cls, tools_method, mock_gate, ctx):
    adapter = adapter_cls(gate=mock_gate, context=ctx)
    result = adapter.register("tool_a", lambda: "ok", description="Test")
    assert result is adapter


@pytest.mark.parametrize("adapter_cls,tools_method", _ADAPTERS, ids=_IDS)
def test_register_multiple(adapter_cls, tools_method, mock_gate, ctx):
    adapter = adapter_cls(gate=mock_gate, context=ctx)
    adapter.register("a", lambda: "a").register("b", lambda: "b")
    assert len(adapter._tools) == 2


@pytest.mark.parametrize("adapter_cls,tools_method", _ADAPTERS, ids=_IDS)
async def test_execute_allowed(adapter_cls, tools_method, mock_gate, ctx):
    adapter = adapter_cls(gate=mock_gate, context=ctx)
    adapter.register("read_data", lambda customer_id: f"data_{customer_id}")

    result = await adapter.execute("read_data", {"customer_id": "cust_001"})
    assert result == "result"  # sanitized content
    mock_gate.evaluate_tool_call.assert_called_once()


@pytest.mark.parametrize("adapter_cls,tools_method", _ADAPTERS, ids=_IDS)
async def test_execute_denied(adapter_cls, tools_method, deny_gate, ctx):
    adapter = adapter_cls(gate=deny_gate, context=ctx)
    adapter.register("delete_all", lambda: "deleted")

    result = await adapter.execute("delete_all", {})
    assert result["blocked"] is True


@pytest.mark.parametrize("adapter_cls,tools_method", _ADAPTERS, ids=_IDS)
async def test_execute_unknown_tool(adapter_cls, tools_method, mock_gate, ctx):
    adapter = adapter_cls(gate=mock_gate, context=ctx)
    result = await adapter.execute("nonexistent", {})
    assert "error" in result


@pytest.mark.parametrize("adapter_cls,tools_method", _ADAPTERS, ids=_IDS)
def test_tools_output(adapter_cls, tools_method, mock_gate, ctx):
    adapter = adapter_cls(gate=mock_gate, context=ctx)
    adapter.register("tool_a", lambda: "a", description="Tool A")
    adapter.register("tool_b", lambda: "b", description="Tool B")

    tools = getattr(adapter, tools_method)()
    assert len(tools) == 2
    assert tools[0]["name"] == "tool_a"
    assert tools[0]["description"] == "Tool A"
    assert callable(tools[0]["function"])


@pytest.mark.parametrize("adapter_cls,tools_method", _ADAPTERS, ids=_IDS)
async def test_execute_async_fn(adapter_cls, tools_method, mock_gate, ctx):
    async def async_tool(x: str) -> str:
        return f"async_{x}"

    adapter = adapter_cls(gate=mock_gate, context=ctx)
    adapter.register("async_tool", async_tool)

    result = await adapter.execute("async_tool", {"x": "test"})
    assert result == "result"  # sanitized


@pytest.mark.parametrize("adapter_cls,tools_method", _ADAPTERS, ids=_IDS)
def test_action_override(adapter_cls, tools_method, mock_gate, ctx):
    adapter = adapter_cls(gate=mock_gate, context=ctx)
    adapter.register("my_tool", lambda: "ok", action="custom_action")

    _, action_name, _ = adapter._tools["my_tool"]
    assert action_name == "custom_action"
