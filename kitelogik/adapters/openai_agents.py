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

import json
import logging
from collections.abc import Callable
from typing import Any

from kitelogik.adapters._base import _run_governed_call
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import SessionContext

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
        """Return a list of ``FunctionTool`` objects for all registered tools.

        The Agents SDK calls each tool via
        ``on_invoke_tool(ctx: ToolContext, input: str) -> Awaitable[Any]``
        where ``input`` is a JSON string. The wrapper parses it, runs the
        governance pipeline, executes the registered function (sync calls
        run in a thread to avoid blocking the agent loop), and returns
        the sanitized result as a string. ``strict_json_schema=False`` so
        ad-hoc schemas registered via ``register(params=...)`` aren't
        rejected for missing strict-mode fields like
        ``additionalProperties: false``.
        """
        _require_openai_agents()
        from agents import FunctionTool

        tools = []
        for name, (fn, action_name, description, params) in self._tools.items():
            tools.append(
                FunctionTool(
                    name=name,
                    description=description or f"Governed tool: {name}",
                    params_json_schema={"type": "object", "properties": params},
                    on_invoke_tool=self._make_on_invoke(name, fn, action_name),
                    strict_json_schema=False,
                )
            )
        return tools

    def _make_on_invoke(
        self,
        name: str,
        fn: Callable,
        action_name: str,
    ) -> Callable[[Any, str], Any]:
        """Build a SDK-shaped ``on_invoke_tool`` for a single registered fn."""
        gate = self._gate
        context = self._context
        sanitize = self._sanitize

        async def _governed_fn(_ctx: Any, json_args: str) -> str:
            try:
                kwargs = json.loads(json_args) if json_args else {}
            except json.JSONDecodeError:
                return json.dumps({"error": "Malformed tool arguments"})
            if not isinstance(kwargs, dict):
                return json.dumps({"error": "Tool arguments must be a JSON object"})

            allowed, result, err = await _run_governed_call(
                gate=gate,
                context=context,
                action=action_name,
                tool_name=name,
                args=kwargs,
                fn=fn,
                sanitize=sanitize,
            )
            if not allowed:
                return json.dumps({"blocked": True, "reason": str(err)})
            return result if isinstance(result, str) else json.dumps(result)

        return _governed_fn
