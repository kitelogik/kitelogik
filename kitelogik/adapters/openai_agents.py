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

from kitelogik.adapters._base import _run_governed_call, governed_handoff
from kitelogik.governed import GovernanceError
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

    # ── Multi-agent governance ──────────────────────────────────────────────

    def register_handoff(
        self,
        target_agent: Any,
        *,
        action: str = "agent.delegate",
        on_handoff: Callable | None = None,
        tool_name_override: str | None = None,
        tool_description_override: str | None = None,
    ) -> Any:
        """Build a governed ``Handoff`` for ``Agent(handoffs=[...])``.

        The Agents SDK transfers control to ``target_agent`` whenever the
        model requests this handoff. This wrapper inserts an
        ``agent.delegate`` governance check *before* the transfer: if
        the policy denies, an exception propagates and the handoff is
        rejected; the user-supplied ``on_handoff`` callback (if any) is
        invoked only on allow.

        Parameters
        ----------
        target_agent
            The destination ``agents.Agent`` (or compatible object).
        action
            OPA action name. Defaults to ``"agent.delegate"`` so the
            same policy rule covers all delegations regardless of
            framework.
        on_handoff
            Optional user callback invoked after governance allows the
            handoff. May be sync or async; signature is ``(ctx)``.
        tool_name_override, tool_description_override
            Forwarded to ``agents.handoff()`` unchanged.

        Returns
        -------
        Handoff
            Pass directly to ``Agent(handoffs=[...])``.

        Notes
        -----
        Input-typed handoffs (``input_type=...``) are not supported
        here. Use :func:`agents.handoff` directly with a custom
        callback that calls :func:`governed_handoff` itself if you
        need typed inputs.
        """
        _require_openai_agents()
        from agents import handoff

        gate = self._gate
        context = self._context
        target_name = getattr(target_agent, "name", str(target_agent))

        async def _on_handoff(ctx: Any) -> None:
            await governed_handoff(
                gate=gate,
                context=context,
                target=target_name,
                action=action,
            )
            if on_handoff is None:
                return
            if inspect.iscoroutinefunction(on_handoff):
                await on_handoff(ctx)
            else:
                on_handoff(ctx)

        return handoff(
            agent=target_agent,
            on_handoff=_on_handoff,
            tool_name_override=tool_name_override,
            tool_description_override=tool_description_override,
        )

    def register_agent_as_tool(
        self,
        agent: Any,
        *,
        tool_name: str,
        tool_description: str,
        action: str = "agent.delegate",
    ) -> Any:
        """Wrap ``agent.as_tool(...)`` with delegation governance.

        Returns a ``FunctionTool`` that, when the parent agent invokes
        it, first evaluates an ``agent.delegate`` event and only runs
        the underlying agent-as-tool on allow. On deny the tool returns
        a JSON ``{"blocked": True, "reason": ...}`` payload — visible
        to the model so it can recover.
        """
        _require_openai_agents()
        from agents import FunctionTool

        gate = self._gate
        context = self._context
        target_name = getattr(agent, "name", tool_name)

        underlying = agent.as_tool(
            tool_name=tool_name,
            tool_description=tool_description,
        )

        async def _governed_invoke(ctx: Any, json_args: str) -> Any:
            try:
                await governed_handoff(
                    gate=gate, context=context, target=target_name, action=action
                )
            except GovernanceError as e:
                return json.dumps({"blocked": True, "reason": str(e)})
            return await underlying.on_invoke_tool(ctx, json_args)

        return FunctionTool(
            name=underlying.name,
            description=underlying.description,
            params_json_schema=underlying.params_json_schema,
            on_invoke_tool=_governed_invoke,
            strict_json_schema=False,
        )

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
