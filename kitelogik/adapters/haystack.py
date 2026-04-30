# SPDX-License-Identifier: Apache-2.0
"""
Haystack adapter — governed tool execution for deepset Haystack agents.

Drop this into any Haystack agent pipeline. The adapter intercepts tool calls
and routes each one through the Kite Logik policy gate before the
underlying function executes.

Usage
-----
    from kitelogik.adapters.haystack import HaystackAdapter

    gate    = PolicyGate(opa_client=OPAClient())
    context = SessionContext(
        session_id="sess_001",
        user_role="analyst",
        session_scopes=["read_customer"],
    )

    adapter = HaystackAdapter(gate=gate, context=context)
    adapter.register(
        "get_customer",
        get_customer_fn,
        description="Get customer by ID",
        parameters={
            "type": "object",
            "properties": {"customer_id": {"type": "string"}},
            "required": ["customer_id"],
        },
    )

    # Pass governed Tool instances to your Haystack generator/agent:
    from haystack.components.generators.chat import OpenAIChatGenerator
    generator = OpenAIChatGenerator(tools=adapter.haystack_tools())

Note
----
Haystack ``Tool`` requires a JSON Schema describing each parameter via the
``parameters`` argument to :meth:`HaystackAdapter.register`. Without it, the
generator cannot serialise the tool to the model's tool-spec.
"""

import functools
import json
import logging
from collections.abc import Callable
from typing import Any

from kitelogik.adapters._base import BaseGovernedAdapter, _run_governed_call
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import SessionContext

logger = logging.getLogger(__name__)


def _require_haystack():  # type: ignore[no-untyped-def]
    try:
        import haystack  # type: ignore[import-untyped]

        return haystack
    except ImportError:
        raise ImportError(
            "haystack-ai is required for the Haystack adapter. "
            "Install it with: pip install haystack-ai"
        ) from None


class HaystackAdapter(BaseGovernedAdapter):
    """
    Governed tool executor for deepset Haystack agents.

    Differs from the other dict-shape adapters in that ``register()``
    accepts an explicit ``parameters`` JSON Schema. Haystack's
    ``Tool`` dataclass requires a schema (it is serialised into the
    OpenAI/Anthropic tool spec the generator sends to the model), so
    callers must provide it when registering.
    """

    def __init__(
        self,
        gate: PolicyGate,
        context: SessionContext,
        sanitize: bool = True,
        deny_message: str | None = None,
    ) -> None:
        super().__init__(gate=gate, context=context, sanitize=sanitize, deny_message=deny_message)
        # Per-tool parameter schema, keyed by registered name.
        self._parameters: dict[str, dict] = {}

    def register(  # type: ignore[override]
        self,
        name: str,
        fn: Callable,
        description: str = "",
        action: str | None = None,
        parameters: dict | None = None,
    ) -> "HaystackAdapter":
        """
        Register a tool function.

        Parameters
        ----------
        name, fn, description, action
            See :meth:`BaseGovernedAdapter.register`.
        parameters : dict, optional
            JSON Schema describing the tool's input parameters. Required
            for the generator to serialise the tool spec; if omitted,
            an empty object schema (``{"type": "object", "properties": {}}``)
            is used, which only works for no-arg tools.
        """
        super().register(name=name, fn=fn, description=description, action=action)
        self._parameters[name] = parameters or {"type": "object", "properties": {}}
        return self

    def haystack_tools(self) -> list[Any]:
        """Return ``haystack.tools.Tool`` instances ready for a generator."""
        _require_haystack()
        from haystack.tools import Tool  # type: ignore[import-untyped]

        return [
            Tool(
                name=name,
                description=description or f"Governed tool: {name}",
                parameters=self._parameters.get(name, {"type": "object", "properties": {}}),
                function=self._build_governed_callable(name, fn, action_name),
            )
            for name, (fn, action_name, description) in self._tools.items()
        ]

    def _build_governed_callable(
        self,
        name: str,
        fn: Callable,
        action_name: str,
    ) -> Callable[..., Any]:
        """Sync wrapper preserving fn's signature; bridges to async governance."""
        from kitelogik.governed import _run_coroutine_sync

        gate = self._gate
        context = self._context
        sanitize = self._sanitize
        deny_message = self._deny_message

        @functools.wraps(fn)
        def governed(**kwargs: Any) -> str:
            allowed, result, _err = _run_coroutine_sync(
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
                return json.dumps({"blocked": True, "reason": deny_message})
            return result if isinstance(result, str) else json.dumps(result)

        governed.__name__ = name
        return governed
