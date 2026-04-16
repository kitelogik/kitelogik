# SPDX-License-Identifier: Apache-2.0
"""
LangChain adapter — governed tools for LangChain and LangGraph agents.

Two integration patterns:

Pattern 1: as_governed_tool() — wrap a single function as a governed BaseTool
──────────────────────────────────────────────────────────────────────────────
    from kitelogik.adapters.langchain import as_governed_tool

    governed_refund = as_governed_tool(
        name="approve_refund",
        fn=approve_refund_fn,
        gate=gate,
        context=ctx,
        description="Approve a refund for a customer. Args: customer_id (str), amount (float).",
    )

    agent = create_react_agent(llm, tools=[governed_refund])

Pattern 2: govern_toolkit() — govern an entire list of tools at once
─────────────────────────────────────────────────────────────────────
    from kitelogik.adapters.langchain import govern_toolkit
    from langchain_community.tools import some_tool_a, some_tool_b

    governed_tools = govern_toolkit([some_tool_a, some_tool_b], gate=gate, context=ctx)
    agent = create_react_agent(llm, tools=governed_tools)

Requirements
------------
    pip install langchain-core     # langchain_core.tools.BaseTool
    # or: pip install langchain    # full package

Kite Logik does NOT declare langchain-core as a hard dependency to keep the
OSS install lightweight. It is only imported at call time; if it is not
installed, a clear ImportError is raised.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from kitelogik.governed import GovernanceError, _check_decision, _maybe_sanitize
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import SessionContext, ToolCallInput

if TYPE_CHECKING:
    try:
        from langchain_core.tools import BaseTool
    except ImportError:
        BaseTool = Any  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)


def as_governed_tool(
    name: str,
    fn: Callable,
    gate: PolicyGate,
    context: SessionContext,
    description: str = "",
    action: str | None = None,
    sanitize: bool = True,
) -> BaseTool:
    """
    Wrap a callable as a governed LangChain BaseTool.

    The policy gate runs before the function body. If the call is denied, the
    tool returns a structured denial message — the agent loop continues and the
    model can handle the refusal.

    Parameters
    ----------
    name : str
            Tool name shown to the model and used in OPA policy lookups.
    fn : Callable
            The underlying function. Sync or async.
    gate : PolicyGate
    context : SessionContext
    description : str
            Tool description passed to the model.
    action : str, optional
            OPA action name override. Defaults to ``name``.
    sanitize : bool, default True
            Sanitize string return values for prompt injection.

    Returns
    -------
    BaseTool
            A LangChain tool that is drop-in compatible with any agent or chain.
    """
    _require_langchain()
    from langchain_core.tools import StructuredTool

    action_name = action or name
    _gate = gate
    _context = context

    async def _governed_async(**kwargs: Any) -> str:
        tc = ToolCallInput(action=action_name, tool_name=name, args=kwargs)
        try:
            decision = await _gate.evaluate_tool_call(tc, _context)
            _check_decision(name, decision)
        except GovernanceError as e:
            return f"[BLOCKED] {e}"

        if inspect.iscoroutinefunction(fn):
            result = await fn(**kwargs)
        else:
            result = fn(**kwargs)

        result = _maybe_sanitize(_gate, result, sanitize)
        return result if isinstance(result, str) else str(result)

    def _governed_sync(**kwargs: Any) -> str:
        return asyncio.get_event_loop().run_until_complete(_governed_async(**kwargs))

    # Build a StructuredTool — supports both sync and async invocation
    return StructuredTool.from_function(
        func=_governed_sync,
        coroutine=_governed_async,
        name=name,
        description=description or f"Governed tool: {name}",
    )


def govern_toolkit(
    tools: list[BaseTool],
    gate: PolicyGate,
    context: SessionContext,
    sanitize: bool = True,
) -> list[BaseTool]:
    """
    Wrap an existing list of LangChain BaseTool instances with governance.

    Each tool in the list is wrapped so its ``_run`` / ``_arun`` methods pass
    through the policy gate before executing.

    Parameters
    ----------
    tools : list[BaseTool]
            Existing LangChain tools (e.g. from a community toolkit).
    gate : PolicyGate
    context : SessionContext
    sanitize : bool, default True

    Returns
    -------
    list[BaseTool]
            The same tools with governance applied. Original tool objects are not
            mutated; new wrapper objects are returned.

    Example
    -------
            from langchain_community.agent_toolkits import SQLDatabaseToolkit
            raw_tools = SQLDatabaseToolkit(db=db, llm=llm).get_tools()
            governed_tools = govern_toolkit(raw_tools, gate=gate, context=ctx)
    """
    _require_langchain()
    return [_wrap_existing_tool(t, gate, context, sanitize) for t in tools]


# ── Internal helpers ──────────────────────────────────────────────────────────


def _require_langchain() -> None:
    try:
        import langchain_core  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "langchain-core is required for the LangChain adapter.\n"
            "Install it with:  pip install langchain-core\n"
            "Or:               pip install langchain"
        ) from e


def _wrap_existing_tool(
    tool: BaseTool,
    gate: PolicyGate,
    context: SessionContext,
    sanitize: bool,
) -> BaseTool:
    """Wrap an existing BaseTool instance without mutating it."""
    from langchain_core.tools import StructuredTool

    original_name = tool.name
    original_desc = tool.description
    action_name = original_name
    _gate = gate
    _context = context

    async def _governed_async(**kwargs: Any) -> str:
        tc = ToolCallInput(action=action_name, tool_name=original_name, args=kwargs)
        try:
            decision = await _gate.evaluate_tool_call(tc, _context)
            _check_decision(original_name, decision)
        except GovernanceError as e:
            return f"[BLOCKED] {e}"

        if hasattr(tool, "_arun"):
            result = await tool._arun(**kwargs)
        else:
            result = tool._run(**kwargs)

        result = _maybe_sanitize(_gate, result, sanitize)
        return result if isinstance(result, str) else str(result)

    def _governed_sync(**kwargs: Any) -> str:
        return asyncio.get_event_loop().run_until_complete(_governed_async(**kwargs))

    return StructuredTool.from_function(
        func=_governed_sync,
        coroutine=_governed_async,
        name=original_name,
        description=original_desc,
    )
