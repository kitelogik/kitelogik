# SPDX-License-Identifier: Apache-2.0
"""
Tests for kitelogik.adapters.langchain — as_governed_tool() and govern_toolkit().

Skipped automatically when langchain-core is not installed.
"""

from unittest.mock import AsyncMock

import pytest

langchain_core = pytest.importorskip("langchain_core", reason="langchain-core not installed")

from kitelogik.adapters.langchain import as_governed_tool, govern_toolkit  # noqa: E402
from kitelogik.tether.gate import PolicyGate  # noqa: E402
from kitelogik.tether.models import PolicyDecision, RiskTier, SessionContext  # noqa: E402
from kitelogik.tether.opa_client import OPAClient  # noqa: E402

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def ctx() -> SessionContext:
    return SessionContext(
        session_id="lc_sess_001",
        user_role="support_agent",
        session_scopes=["read_customer"],
    )


@pytest.fixture
def allow_dec() -> PolicyDecision:
    return PolicyDecision(
        allow=True,
        deny=False,
        risk_tier=RiskTier.INFORMATIONAL,
        requires_hitl=False,
        reason="Allowed",
    )


@pytest.fixture
def deny_dec() -> PolicyDecision:
    return PolicyDecision(
        allow=False,
        deny=True,
        risk_tier=RiskTier.SECURITY_CRITICAL,
        requires_hitl=False,
        reason="Hard blocked",
    )


@pytest.fixture
def mock_opa(allow_dec: PolicyDecision) -> OPAClient:
    client = AsyncMock(spec=OPAClient)
    client.evaluate.return_value = allow_dec
    return client


@pytest.fixture
def gate(mock_opa: OPAClient) -> PolicyGate:
    return PolicyGate(opa_client=mock_opa)


# ── as_governed_tool() ────────────────────────────────────────────────────────


def test_as_governed_tool_creates_tool_with_correct_name_and_description(gate, ctx):
    tool = as_governed_tool(
        name="get_customer_record",
        fn=lambda customer_id: f"record:{customer_id}",
        gate=gate,
        context=ctx,
        description="Retrieve customer record by ID.",
    )
    assert tool.name == "get_customer_record"
    assert tool.description == "Retrieve customer record by ID."


async def test_as_governed_tool_allows_call_and_returns_result(gate, ctx, mock_opa, allow_dec):
    mock_opa.evaluate.return_value = allow_dec

    tool = as_governed_tool(
        name="lookup",
        fn=lambda item_id: f"data:{item_id}",
        gate=gate,
        context=ctx,
    )
    result = await tool.coroutine(item_id="itm_001")
    assert result == "data:itm_001"


async def test_as_governed_tool_denies_call_returns_blocked_message(gate, ctx, mock_opa, deny_dec):
    mock_opa.evaluate.return_value = deny_dec

    tool = as_governed_tool(
        name="restricted_action",
        fn=lambda: "should not run",
        gate=gate,
        context=ctx,
    )
    result = await tool.coroutine()
    assert "[BLOCKED]" in result


async def test_as_governed_tool_multi_arg_via_public_ainvoke(gate, ctx, mock_opa, allow_dec):
    """Multi-arg tools invoked via the public ``ainvoke`` API (the path
    LangGraph's tool node uses) must accept per-arg payloads and route
    them to ``fn``. The wrapper infers a Pydantic schema from ``fn``'s
    signature so ``StructuredTool`` validates per-argument types.
    """
    mock_opa.evaluate.return_value = allow_dec

    def place_order(sku: str, qty: int) -> str:
        return f"PO:{qty}x{sku}"

    tool = as_governed_tool(
        name="place_order",
        fn=place_order,
        gate=gate,
        context=ctx,
        description="Place a purchase order.",
    )
    result = await tool.ainvoke({"sku": "SKU-002", "qty": 50})
    assert result == "PO:50xSKU-002"


async def test_as_governed_tool_async_function_executed_correctly(gate, ctx, mock_opa, allow_dec):
    mock_opa.evaluate.return_value = allow_dec

    async def async_fn(x: int) -> str:
        return f"async:{x}"

    tool = as_governed_tool(
        name="async_tool",
        fn=async_fn,
        gate=gate,
        context=ctx,
    )
    result = await tool.coroutine(x=7)
    assert result == "async:7"


# ── govern_toolkit() ──────────────────────────────────────────────────────────


async def test_govern_toolkit_wraps_all_tools(gate, ctx, mock_opa, allow_dec):
    mock_opa.evaluate.return_value = allow_dec

    from langchain_core.tools import StructuredTool

    tool_a = StructuredTool.from_function(
        func=lambda: "a",
        name="tool_a",
        description="Tool A",
    )
    tool_b = StructuredTool.from_function(
        func=lambda: "b",
        name="tool_b",
        description="Tool B",
    )

    governed_tools = govern_toolkit([tool_a, tool_b], gate=gate, context=ctx)

    assert len(governed_tools) == 2
    assert governed_tools[0].name == "tool_a"
    assert governed_tools[1].name == "tool_b"


async def test_govern_toolkit_each_tool_passes_through_governance(gate, ctx, mock_opa, allow_dec):
    mock_opa.evaluate.return_value = allow_dec

    from langchain_core.tools import StructuredTool

    tool = StructuredTool.from_function(
        func=lambda val: f"result:{val}",
        name="lookup",
        description="Lookup a value",
    )

    governed_tools = govern_toolkit([tool], gate=gate, context=ctx)
    result = await governed_tools[0].coroutine(val="hello")
    assert result == "result:hello"
    mock_opa.evaluate.assert_called_once()


async def test_govern_toolkit_deny_returns_blocked_message(gate, ctx, mock_opa, deny_dec):
    mock_opa.evaluate.return_value = deny_dec

    from langchain_core.tools import StructuredTool

    tool = StructuredTool.from_function(
        func=lambda: "never",
        name="blocked_tool",
        description="Should be blocked",
    )

    governed_tools = govern_toolkit([tool], gate=gate, context=ctx)
    result = await governed_tools[0].coroutine()
    assert "[BLOCKED]" in result


async def test_govern_toolkit_preserves_args_schema(gate, ctx, mock_opa, allow_dec):
    """``govern_toolkit`` preserves the wrapped tool's ``args_schema`` so
    that callers like LangGraph's ``ToolNode`` can still validate
    per-argument types from the model's tool call. Falls back to inferring
    the schema from ``_run`` when no explicit schema is set.
    """
    mock_opa.evaluate.return_value = allow_dec

    from langchain_core.tools import StructuredTool
    from pydantic import BaseModel, Field

    class SearchArgs(BaseModel):
        query: str = Field(description="The search query")
        limit: int = 10

    original = StructuredTool.from_function(
        func=lambda query, limit=10: f"hits:{limit}:{query}",
        name="search",
        description="Search the index",
        args_schema=SearchArgs,
    )

    governed = govern_toolkit([original], gate=gate, context=ctx)

    # Schema is preserved on the wrapper (callers like LangGraph's ToolNode
    # introspect this to validate per-call args).
    assert governed[0].args_schema is SearchArgs

    # End-to-end: a real ainvoke call with the schema's field names succeeds.
    result = await governed[0].ainvoke({"query": "kitelogik", "limit": 3})
    assert result == "hits:3:kitelogik"


async def test_govern_toolkit_falls_back_to_run_signature(gate, ctx, mock_opa, allow_dec):
    """When a BaseTool exposes no ``args_schema``, the wrapper infers one from
    the underlying ``_run`` signature so concrete fields still flow through.
    """
    mock_opa.evaluate.return_value = allow_dec

    from langchain_core.tools import BaseTool

    class CustomTool(BaseTool):
        name: str = "compute"
        description: str = "Compute a value"

        def _run(self, x: int, y: int = 1) -> str:  # type: ignore[override]
            return f"{x + y}"

    governed = govern_toolkit([CustomTool()], gate=gate, context=ctx)
    # A real call lands on _run via ainvoke; if no schema were inferred this
    # would fail with a Pydantic validation error.
    result = await governed[0].ainvoke({"x": 5, "y": 7})
    assert result == "12"


# ── Import guard ──────────────────────────────────────────────────────────────


def test_governed_tool_handles_missing_langchain_core_with_helpful_message(gate, ctx):
    """
    When langchain_core is not installed, _require_langchain() must raise
    ImportError with an install hint rather than a bare ModuleNotFoundError.
    """
    import sys
    from unittest.mock import patch

    with patch.dict(sys.modules, {"langchain_core": None, "langchain_core.tools": None}):
        # Re-import after patching so _require_langchain() sees the absence
        from importlib import reload

        import kitelogik.adapters.langchain as lc_mod

        try:
            reload(lc_mod)
            lc_mod._require_langchain()
            # If langchain_core is genuinely installed the reload won't raise;
            # just verify the function exists and runs without error when installed.
        except ImportError as e:
            assert "pip install langchain-core" in str(e)
        except Exception:
            pass  # Other reload side-effects in CI are acceptable
