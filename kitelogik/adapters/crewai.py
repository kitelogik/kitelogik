# SPDX-License-Identifier: Apache-2.0
"""
CrewAI adapter — governed tool execution for CrewAI agents.

Usage
-----
    from kitelogik.adapters.crewai import CrewAIAdapter

    adapter = CrewAIAdapter(gate=gate, context=ctx)
    adapter.register("search_web", search_web_fn, description="Search the web")

    tools = adapter.crewai_tools()  # pass to Agent(tools=...)

Requirements
------------
    pip install crewai

CrewAI is NOT a hard dependency. It is only imported at call time.
"""

import inspect
import logging
from collections.abc import Callable
from typing import Any

from kitelogik.governed import (
    GovernanceError,
    _check_decision,
    _maybe_sanitize,
    _run_coroutine_sync,
)
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import SessionContext, ToolCallInput

logger = logging.getLogger(__name__)


def _require_crewai() -> None:
    try:
        import crewai  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "crewai is required for the CrewAI adapter.\nInstall it with:  pip install crewai"
        ) from e


class CrewAIAdapter:
    """
    Governed tool executor for CrewAI agents.

    Register tools, then call crewai_tools() to get a list of CrewAI Tool
    objects that route through the governance pipeline.

    Parameters
    ----------
    gate : PolicyGate
    context : SessionContext
    sanitize : bool, default True
    """

    def __init__(
        self,
        gate: PolicyGate,
        context: SessionContext,
        sanitize: bool = True,
    ) -> None:
        self._gate = gate
        self._context = context
        self._sanitize = sanitize
        self._tools: dict[str, tuple[Callable, str, str]] = {}

    def register(
        self,
        name: str,
        fn: Callable,
        description: str = "",
        action: str | None = None,
    ) -> "CrewAIAdapter":
        """Register a tool function. Returns self for chaining."""
        self._tools[name] = (fn, action or name, description)
        return self

    def crewai_tools(self) -> list:
        """Return a list of CrewAI Tool objects for all registered tools."""
        _require_crewai()

        tools = []
        for name, (fn, action_name, description) in self._tools.items():
            tool = self._create_governed_tool(name, fn, action_name, description)
            tools.append(tool)
        return tools

    def _create_governed_tool(
        self,
        name: str,
        fn: Callable,
        action_name: str,
        description: str,
    ) -> Any:
        """Create a single governed CrewAI tool."""
        _require_crewai()
        from crewai.tools import tool as crewai_tool_decorator

        gate = self._gate
        context = self._context
        sanitize = self._sanitize

        @crewai_tool_decorator(name)
        def governed_tool(**kwargs: Any) -> str:
            """Governed tool wrapper."""
            tc = ToolCallInput(action=action_name, tool_name=name, args=kwargs)
            try:
                decision = _run_coroutine_sync(gate.evaluate_tool_call(tc, context))
                _check_decision(name, decision)
            except GovernanceError as e:
                return f"[BLOCKED] {e}"

            if inspect.iscoroutinefunction(fn):
                result = _run_coroutine_sync(fn(**kwargs))
            else:
                result = fn(**kwargs)

            result = _maybe_sanitize(gate, result, sanitize)
            return result if isinstance(result, str) else str(result)

        governed_tool.__doc__ = description or f"Governed tool: {name}"
        return governed_tool
