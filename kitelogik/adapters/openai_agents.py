# SPDX-License-Identifier: Apache-2.0
"""
OpenAI Agents SDK adapter — governed tool execution for the OpenAI Agents SDK.

Usage
-----
    from kitelogik.adapters.openai_agents import OpenAIAgentsAdapter

    adapter = OpenAIAgentsAdapter(gate=gate, context=ctx)
    adapter.register(
        "search", search_fn, description="Search docs",
        params={"query": {"type": "string"}},
    )

    tools = adapter.agent_tools()  # pass to Agent(tools=...)

Requirements
------------
    pip install openai-agents

The openai-agents package is NOT a hard dependency.
"""

import inspect
import json
import logging
from collections.abc import Callable
from typing import Any

from kitelogik.governed import GovernanceError, _check_decision, _maybe_sanitize
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import SessionContext, ToolCallInput

logger = logging.getLogger(__name__)


def _require_openai_agents() -> None:
    try:
        import agents  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "openai-agents is required for the OpenAI Agents SDK adapter.\n"
            "Install it with:  pip install openai-agents"
        ) from e


class OpenAIAgentsAdapter:
    """
    Governed tool executor for the OpenAI Agents SDK.

    Register tools, then call agent_tools() to get FunctionTool instances
    that route through the governance pipeline.

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
        self._tools: dict[str, tuple[Callable, str, str, dict]] = {}

    def register(
        self,
        name: str,
        fn: Callable,
        description: str = "",
        params: dict | None = None,
        action: str | None = None,
    ) -> "OpenAIAgentsAdapter":
        """Register a tool function. Returns self for chaining."""
        self._tools[name] = (fn, action or name, description, params or {})
        return self

    def agent_tools(self) -> list:
        """Return a list of FunctionTool objects for all registered tools."""
        _require_openai_agents()
        from agents import FunctionTool

        tools = []
        for name, (fn, action_name, description, params) in self._tools.items():
            gate = self._gate
            context = self._context
            sanitize = self._sanitize

            async def _governed_fn(
                _fn=fn,
                _name=name,
                _action=action_name,
                _sanitize=sanitize,
                **kwargs: Any,
            ) -> str:
                tc = ToolCallInput(action=_action, tool_name=_name, args=kwargs)
                try:
                    decision = await gate.evaluate_tool_call(tc, context)
                    _check_decision(_name, decision)
                except GovernanceError as e:
                    return json.dumps({"blocked": True, "reason": str(e)})

                if inspect.iscoroutinefunction(_fn):
                    result = await _fn(**kwargs)
                else:
                    result = _fn(**kwargs)

                result = _maybe_sanitize(gate, result, _sanitize)
                return result if isinstance(result, str) else json.dumps(result)

            tool = FunctionTool(
                name=name,
                description=description or f"Governed tool: {name}",
                params_json_schema={
                    "type": "object",
                    "properties": params,
                },
                on_invoke_tool=_governed_fn,
            )
            tools.append(tool)
        return tools
