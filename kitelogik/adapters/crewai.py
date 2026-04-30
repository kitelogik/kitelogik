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

import logging
from collections.abc import Callable
from typing import Any

from kitelogik.adapters._base import _run_governed_call
from kitelogik.governed import _run_coroutine_sync
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import SessionContext

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
        """Register a tool function. Returns self for chaining.

        Raises
        ------
        ValueError
            If a tool with ``name`` is already registered.
        """
        if name in self._tools:
            raise ValueError(
                f"Tool '{name}' is already registered on this adapter. "
                f"Choose a different name or unregister it first."
            )
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
            allowed, result, err = _run_coroutine_sync(
                _run_governed_call(
                    gate=gate,
                    context=context,
                    action=action_name,
                    tool_name=name,
                    args=kwargs,
                    fn=fn,
                    sanitize=sanitize,
                )
            )
            if not allowed:
                return f"[BLOCKED] {err}"
            return result if isinstance(result, str) else str(result)

        governed_tool.__doc__ = description or f"Governed tool: {name}"
        return governed_tool
