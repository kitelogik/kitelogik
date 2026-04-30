# SPDX-License-Identifier: Apache-2.0
"""
PydanticAI adapter — governed tool execution for PydanticAI agents.

Drop this into any PydanticAI agent. The adapter intercepts tool calls
and routes each one through the Kite Logik policy gate before the
underlying function executes.

Usage
-----
    from kitelogik.adapters.pydantic_ai import PydanticAIAdapter

    gate    = PolicyGate(opa_client=OPAClient())
    context = SessionContext(
        session_id="sess_001",
        user_role="analyst",
        session_scopes=["read_customer"],
    )

    adapter = PydanticAIAdapter(gate=gate, context=context)
    adapter.register("get_customer", get_customer_fn, description="Get customer by ID")

    # Pass governed Tool instances to your PydanticAI Agent:
    from pydantic_ai import Agent
    agent = Agent("openai:gpt-4o", tools=adapter.pydantic_tools())
"""

import functools
import json
import logging
from collections.abc import Callable
from typing import Any

from kitelogik.adapters._base import BaseGovernedAdapter, _run_governed_call

logger = logging.getLogger(__name__)


def _require_pydantic_ai():  # type: ignore[no-untyped-def]
    try:
        import pydantic_ai  # type: ignore[import-untyped]

        return pydantic_ai
    except ImportError:
        raise ImportError(
            "pydantic-ai is required for the PydanticAI adapter. "
            "Install it with: pip install pydantic-ai"
        ) from None


class PydanticAIAdapter(BaseGovernedAdapter):
    """
    Governed tool executor for PydanticAI agents.

    Wraps tool functions and routes each call through the Kite Logik
    policy gate before execution. Returns a list of ``pydantic_ai.Tool``
    instances ready for ``Agent(tools=...)``.
    """

    def pydantic_tools(self) -> list[Any]:
        """
        Return ``pydantic_ai.Tool`` instances for all registered tools.

        Each returned Tool wraps a governed callable that runs the
        policy pipeline before invoking the registered function. Sync
        tools are dispatched on a thread to avoid stalling the agent
        loop. ``takes_ctx=False`` because the wrapper handles context
        internally via the adapter's ``SessionContext``.
        """
        _require_pydantic_ai()
        from pydantic_ai import Tool  # type: ignore[import-untyped]

        return [
            Tool(
                self._build_governed_callable(name, fn, action_name),
                takes_ctx=False,
                name=name,
                description=description,
            )
            for name, (fn, action_name, description) in self._tools.items()
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
            allowed, result, _err = await _run_governed_call(
                gate=gate,
                context=context,
                action=action_name,
                tool_name=name,
                args=kwargs,
                fn=fn,
                sanitize=sanitize,
            )
            if not allowed:
                return json.dumps({"blocked": True, "reason": deny_message})
            return result if isinstance(result, str) else json.dumps(result)

        governed.__name__ = name
        return governed
