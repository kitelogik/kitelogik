# SPDX-License-Identifier: Apache-2.0
"""
Google ADK adapter — governed tool execution for Google Agent Development Kit.

Drop this into any Google ADK agent. The adapter intercepts tool calls
and routes each one through the Kite Logik policy gate before the
underlying function executes.

Usage
-----
    from kitelogik.adapters.google_adk import GoogleADKAdapter

    gate    = PolicyGate(opa_client=OPAClient())
    context = SessionContext(
        session_id="sess_001",
        user_role="analyst",
        session_scopes=["read_customer"],
    )

    adapter = GoogleADKAdapter(gate=gate, context=context)
    adapter.register("get_customer", get_customer_fn, description="Get customer by ID")

    # Pass governed tools to your ADK agent. ADK accepts either plain
    # callables (auto-wrapped) or FunctionTool instances; we return
    # callables so ADK can introspect parameter types directly.
    from google.adk import Agent
    agent = Agent(name="support", model="gemini-2.0-flash", tools=adapter.adk_tools())
"""

import asyncio
import functools
import inspect
import json
import logging
from collections.abc import Callable
from typing import Any

from kitelogik.adapters._base import BaseGovernedAdapter
from kitelogik.governed import GovernanceError, _check_decision, _maybe_sanitize
from kitelogik.tether.models import ToolCallInput

logger = logging.getLogger(__name__)


def _require_google_adk():  # type: ignore[no-untyped-def]
    try:
        import google.adk  # type: ignore[import-untyped]

        return google.adk
    except ImportError:
        raise ImportError(
            "google-adk is required for the Google ADK adapter. "
            "Install it with: pip install google-adk"
        ) from None


class GoogleADKAdapter(BaseGovernedAdapter):
    """
    Governed tool executor for Google Agent Development Kit.

    Wraps tool functions and routes each call through the Kite Logik
    policy gate before execution. Returns a list of callables (with the
    original function signatures preserved via :func:`functools.wraps`)
    so ADK can introspect parameter types and build its tool schema.
    """

    def adk_tools(self) -> list[Callable[..., Any]]:
        """
        Return governed callables ready for ``Agent(tools=...)``.

        The returned callables retain the original function's name,
        docstring, and signature (via ``functools.wraps``) so ADK's
        automatic schema inference works as if the user passed the
        underlying function directly. Each call routes through the
        policy gate first; denied calls return a JSON ``{"blocked":
        True, "reason": ...}`` payload, matching ADK's expectation
        that tools return strings.
        """
        return [
            self._build_governed_callable(name, fn, action_name)
            for name, (fn, action_name, _description) in self._tools.items()
        ]

    def _build_governed_callable(
        self,
        name: str,
        fn: Callable,
        action_name: str,
    ) -> Callable[..., Any]:
        """Wrap ``fn`` with governance, preserving its signature."""
        gate = self._gate
        context = self._context
        sanitize = self._sanitize
        deny_message = self._deny_message

        @functools.wraps(fn)
        async def governed(**kwargs: Any) -> str:
            tc = ToolCallInput(action=action_name, tool_name=name, args=kwargs)
            try:
                decision = await gate.evaluate_tool_call(tc, context)
                _check_decision(name, decision)
            except GovernanceError as e:
                logger.info("Tool call blocked by governance: tool=%s reason=%s", name, e)
                return json.dumps({"blocked": True, "reason": deny_message})

            if inspect.iscoroutinefunction(fn):
                result = await fn(**kwargs)
            else:
                result = await asyncio.to_thread(fn, **kwargs)

            result = _maybe_sanitize(gate, result, sanitize)
            return result if isinstance(result, str) else json.dumps(result)

        # ``functools.wraps`` already copies __name__, __doc__,
        # __wrapped__, __module__. Force-set __name__ if a tool was
        # registered under a different name than fn.__name__.
        governed.__name__ = name
        return governed
