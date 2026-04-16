# SPDX-License-Identifier: Apache-2.0
"""
LangGraph adapter — governed tool nodes for LangGraph graphs.

Usage
-----
    from kitelogik.adapters.langgraph import as_governed_node, govern_graph_tools

    # Pattern 1: wrap a single function as a governed graph node
    governed_search = as_governed_node("search", search_fn, gate=gate, context=ctx)

    # Pattern 2: wrap multiple tool functions for use in a ToolNode
    tools = govern_graph_tools(
        {"search": search_fn, "calculator": calc_fn},
        gate=gate, context=ctx,
    )

Requirements
------------
    pip install langgraph

LangGraph is NOT a hard dependency.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable
from typing import Any

from kitelogik.governed import GovernanceError, _check_decision, _maybe_sanitize
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import SessionContext, ToolCallInput

logger = logging.getLogger(__name__)


def _require_langgraph() -> None:
    try:
        import langgraph  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "langgraph is required for the LangGraph adapter.\n"
            "Install it with:  pip install langgraph"
        ) from e


def as_governed_node(
    name: str,
    fn: Callable,
    gate: PolicyGate,
    context: SessionContext,
    action: str | None = None,
    sanitize: bool = True,
) -> Callable:
    """
    Wrap a function as a governed LangGraph node.

    Returns a new async function that evaluates the governance pipeline before
    calling the underlying function. Suitable for use as a graph node.

    Parameters
    ----------
    name : str
            Tool/node name used in OPA policy lookups.
    fn : Callable
            The underlying function.
    gate : PolicyGate
    context : SessionContext
    action : str, optional
            OPA action name override.
    sanitize : bool, default True
    """
    action_name = action or name

    async def _governed_node(state: dict[str, Any]) -> dict[str, Any]:
        args = state.get("args", {})
        tc = ToolCallInput(action=action_name, tool_name=name, args=args)

        try:
            decision = await gate.evaluate_tool_call(tc, context)
            _check_decision(name, decision)
        except GovernanceError as e:
            return {**state, "result": f"[BLOCKED] {e}", "blocked": True}

        if inspect.iscoroutinefunction(fn):
            result = await fn(**args)
        else:
            result = fn(**args)

        result = _maybe_sanitize(gate, result, sanitize)
        return {**state, "result": result, "blocked": False}

    _governed_node.__name__ = f"governed_{name}"
    _governed_node.__doc__ = f"Governed node: {name}"
    return _governed_node


def govern_graph_tools(
    tools: dict[str, Callable],
    gate: PolicyGate,
    context: SessionContext,
    sanitize: bool = True,
) -> list:
    """
    Wrap multiple tool functions as governed LangChain tools for use in a ToolNode.

    Parameters
    ----------
    tools : dict[str, Callable]
            Mapping of tool names to functions.
    gate : PolicyGate
    context : SessionContext
    sanitize : bool, default True

    Returns
    -------
    list[BaseTool]
            LangChain StructuredTool instances governed by the policy gate.
            Pass these to ``ToolNode(tools=...)`` in your graph.
    """
    _require_langgraph()
    from kitelogik.adapters.langchain import as_governed_tool

    return [
        as_governed_tool(
            name=name,
            fn=fn,
            gate=gate,
            context=context,
            sanitize=sanitize,
        )
        for name, fn in tools.items()
    ]
