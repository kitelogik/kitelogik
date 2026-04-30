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

from kitelogik.governed import GovernanceError, _check_decision, _maybe_sanitize
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import SessionContext, ToolCallInput

logger = logging.getLogger(__name__)


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
    tc = ToolCallInput(action=action, tool_name=tool_name, args=args)
    try:
        decision = await gate.evaluate_tool_call(tc, context)
        _check_decision(tool_name, decision)
    except GovernanceError as e:
        logger.info("Tool call blocked by governance: tool=%s reason=%s", tool_name, e)
        return False, None, e

    if inspect.iscoroutinefunction(fn):
        result = await fn(**args)
    else:
        result = await asyncio.to_thread(fn, **args)

    return True, _maybe_sanitize(gate, result, sanitize), None


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
        """
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
