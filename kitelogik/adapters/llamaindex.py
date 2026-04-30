# SPDX-License-Identifier: Apache-2.0
"""
LlamaIndex adapter — governed tool execution for LlamaIndex agents.

Drop this into any LlamaIndex agent. The adapter intercepts tool calls
and routes each one through the Kite Logik policy gate before the
underlying function executes.

Usage
-----
    from kitelogik.adapters.llamaindex import LlamaIndexAdapter

    gate    = PolicyGate(opa_client=OPAClient())
    context = SessionContext(
        session_id="sess_001",
        user_role="analyst",
        session_scopes=["read_customer"],
    )

    adapter = LlamaIndexAdapter(gate=gate, context=context)
    adapter.register("get_customer", get_customer_fn, description="Get customer by ID")

    # Pass governed FunctionTool instances to your LlamaIndex agent:
    from llama_index.core.agent import ReActAgent
    agent = ReActAgent.from_tools(adapter.llamaindex_tools(), llm=llm)
"""

import functools
import json
import logging
from collections.abc import Callable
from typing import Any

from kitelogik.adapters._base import BaseGovernedAdapter, _run_governed_call

logger = logging.getLogger(__name__)


def _require_llamaindex():  # type: ignore[no-untyped-def]
    try:
        import llama_index  # type: ignore[import-untyped]

        return llama_index
    except ImportError:
        raise ImportError(
            "llama-index is required for the LlamaIndex adapter. "
            "Install it with: pip install llama-index"
        ) from None


class LlamaIndexAdapter(BaseGovernedAdapter):
    """
    Governed tool executor for LlamaIndex agents.

    Wraps tool functions and routes each call through the Kite Logik
    policy gate before execution. Returns a list of
    ``llama_index.core.tools.FunctionTool`` instances.
    """

    def llamaindex_tools(self) -> list[Any]:
        """
        Return ``FunctionTool`` instances for all registered tools.

        Each tool is built via ``FunctionTool.from_defaults`` with both
        a sync ``fn`` and an ``async_fn`` populated by the same governed
        wrapper, so LlamaIndex agents that prefer ``acall`` (async path)
        and those that go through ``call`` (sync path) both flow through
        the policy gate. Sync registered functions run on a thread pool
        to avoid stalling the agent's event loop.
        """
        _require_llamaindex()
        from llama_index.core.tools import FunctionTool  # type: ignore[import-untyped]

        tools: list[Any] = []
        for name, (fn, action_name, description) in self._tools.items():
            governed_async = self._build_governed_async(name, fn, action_name)
            governed_sync = self._build_governed_sync(governed_async)
            tools.append(
                FunctionTool.from_defaults(
                    fn=governed_sync,
                    async_fn=governed_async,
                    name=name,
                    description=description or f"Governed tool: {name}",
                )
            )
        return tools

    def _build_governed_async(
        self,
        name: str,
        fn: Callable,
        action_name: str,
    ) -> Callable[..., Any]:
        """Async governed wrapper preserving fn's signature."""
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

    def _build_governed_sync(self, governed_async: Callable) -> Callable[..., Any]:
        """Sync wrapper that bridges to the async governed callable."""
        from kitelogik.governed import _run_coroutine_sync

        @functools.wraps(governed_async)
        def sync_wrapper(**kwargs: Any) -> str:
            return _run_coroutine_sync(governed_async(**kwargs))  # type: ignore[no-any-return]

        return sync_wrapper
