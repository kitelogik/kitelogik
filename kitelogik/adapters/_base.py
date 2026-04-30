# SPDX-License-Identifier: Apache-2.0
"""
Base class for governed framework adapters.

Centralises the security-critical governance pipeline (evaluate → check →
execute → sanitize) so that framework-specific adapters only override the
tool-definition output method.
"""

import asyncio
import inspect
import logging
from collections.abc import Callable
from typing import Any

from opentelemetry import trace

from kitelogik.governed import GovernanceError, _check_decision, _maybe_sanitize
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import GovernanceEvent, SessionContext, ToolCallInput

logger = logging.getLogger(__name__)
_tracer = trace.get_tracer("kitelogik.adapter")


async def _run_governed_call(
    *,
    gate: PolicyGate,
    context: SessionContext,
    action: str,
    tool_name: str,
    args: dict[str, Any],
    fn: Callable,
    sanitize: bool = True,
) -> tuple[bool, Any, GovernanceError | None]:
    """Run the governance pipeline for a single tool call.

    Pipeline: build a :class:`ToolCallInput` → evaluate the policy gate
    → check the decision → execute ``fn`` (sync callables run on a
    thread so blocking I/O does not stall the agent loop) → sanitize
    the result.

    Returns
    -------
    (allowed, result, error)
        - ``allowed=True``: ``result`` is the sanitized return value;
          ``error`` is ``None``.
        - ``allowed=False``: ``result`` is ``None``; ``error`` is the
          :class:`GovernanceError` raised by the gate. Format ``error``
          for the model however the calling framework prefers (JSON
          payload, ``[BLOCKED]`` prefix string, etc.).
    """
    with _tracer.start_as_current_span("kitelogik.adapter.tool_call") as span:
        span.set_attribute("kitelogik.tool.name", tool_name)
        span.set_attribute("kitelogik.tool.action", action)
        span.set_attribute("kitelogik.session_id", context.session_id)

        tc = ToolCallInput(action=action, tool_name=tool_name, args=args)
        try:
            decision = await gate.evaluate_tool_call(tc, context)
            _check_decision(tool_name, decision)
        except GovernanceError as e:
            logger.info("Tool call blocked by governance: tool=%s reason=%s", tool_name, e)
            span.set_attribute("kitelogik.allowed", False)
            return False, None, e

        if inspect.iscoroutinefunction(fn):
            result = await fn(**args)
        else:
            result = await asyncio.to_thread(fn, **args)

        span.set_attribute("kitelogik.allowed", True)
        return True, _maybe_sanitize(gate, result, sanitize), None


async def governed_handoff(
    *,
    gate: PolicyGate,
    context: SessionContext,
    target: str,
    action: str = "agent.delegate",
    requested_capabilities: list[str] | None = None,
) -> None:
    """Evaluate an ``agent.delegate`` governance event before a handoff.

    Generic helper for any framework (or hand-rolled multi-agent code)
    that needs to gate cross-agent delegation. Raises
    :class:`GovernanceError` on deny so the caller can short-circuit;
    returns ``None`` on allow.

    Parameters
    ----------
    gate, context
        The configured policy gate and parent session context.
    target
        Identifier of the agent receiving the handoff (logged + sent
        to the policy as ``delegation_target``).
    action
        OPA action name. Defaults to ``"agent.delegate"``.
    requested_capabilities
        Optional list of capability names the parent wants to grant the
        child. Surfaced to the policy so scope-narrowing rules can fire.

    Raises
    ------
    GovernanceError
        If the policy gate denies, hard-blocks, or escalates the
        delegation. Inspect ``error.decision`` to distinguish hard
        deny from HITL.
    """
    event = GovernanceEvent(
        event_type="agent.delegate",
        session_id=context.session_id,
        action=action,
        context=context,
        delegation_target=target,
        requested_capabilities=requested_capabilities or [],
    )
    decision = await gate.evaluate(event)
    _check_decision(action, decision)


class BaseGovernedAdapter:
    """
    Governed tool executor base class.

    Subclasses implement ``framework_tools()`` to return tool definitions
    in the format expected by their framework.

    Parameters
    ----------
    gate : PolicyGate
    context : SessionContext
    sanitize : bool, default True
            Sanitize string return values for prompt injection.
    deny_message : str, optional
            Message returned to the model when a call is blocked.
    """

    def __init__(
        self,
        gate: PolicyGate,
        context: SessionContext,
        sanitize: bool = True,
        deny_message: str | None = None,
    ) -> None:
        self._gate = gate
        self._context = context
        self._sanitize = sanitize
        self._deny_message = deny_message or "Action blocked by governance policy."
        self._tools: dict[str, tuple[Callable, str, str]] = {}

    def register(
        self,
        name: str,
        fn: Callable,
        description: str = "",
        action: str | None = None,
    ) -> "BaseGovernedAdapter":
        """
        Register a tool function.

        Parameters
        ----------
        name : str
                Tool name.
        fn : Callable
                The underlying function to execute if the call is allowed.
        description : str
                Tool description for the agent framework.
        action : str, optional
                OPA action name override. Defaults to ``name``.

        Returns self for chaining.

        Raises
        ------
        ValueError
            If a tool with ``name`` is already registered. Use a
            different name or unregister the existing tool first.
        """
        if name in self._tools:
            raise ValueError(
                f"Tool '{name}' is already registered on this adapter. "
                f"Choose a different name or unregister it first."
            )
        desc = description or (fn.__doc__ or "").strip().split("\n")[0] or f"Call {name}"
        self._tools[name] = (fn, action or name, desc)
        return self

    async def execute(self, name: str, args: dict[str, Any]) -> Any:
        """
        Execute a tool call through the governance pipeline.

        Returns the tool result if allowed, or a denial message if blocked.
        """
        if name not in self._tools:
            return {"error": f"Tool '{name}' not registered in adapter"}

        fn, action_name, _ = self._tools[name]

        try:
            allowed, result, _err = await _run_governed_call(
                gate=self._gate,
                context=self._context,
                action=action_name,
                tool_name=name,
                args=args,
                fn=fn,
                sanitize=self._sanitize,
            )
        except Exception as e:
            logger.exception("Tool execution error: tool=%s", name)
            return {"error": str(e)}

        if not allowed:
            return {"blocked": True, "reason": self._deny_message}
        return result

    def _make_governed_fn(self, name: str, fn: Callable, action_name: str) -> Callable:
        """Create a governed wrapper function for a tool."""
        adapter = self

        async def governed_fn(**kwargs: Any) -> Any:
            return await adapter.execute(name, kwargs)

        governed_fn.__name__ = name
        governed_fn.__doc__ = fn.__doc__
        return governed_fn
