# SPDX-License-Identifier: Apache-2.0
"""
Semantic Kernel adapter — governed tool execution for Microsoft Semantic Kernel.

Drop this into any Semantic Kernel agent. The adapter intercepts tool calls
and routes each one through the Kite Logik policy gate before the
underlying function executes.

Usage
-----
    from kitelogik.adapters.semantic_kernel import SemanticKernelAdapter

    gate    = PolicyGate(opa_client=OPAClient())
    context = SessionContext(
        session_id="sess_001",
        user_role="analyst",
        session_scopes=["read_customer"],
    )

    adapter = SemanticKernelAdapter(gate=gate, context=context)
    adapter.register("get_customer", get_customer_fn, description="Get customer by ID")

    # Two equivalent ways to plug into a Kernel:
    from semantic_kernel import Kernel
    kernel = Kernel()

    # 1. Pull the plugin instance and add it yourself:
    kernel.add_plugin(adapter.kernel_plugin(), plugin_name="kitelogik")

    # 2. Or use the convenience helper:
    adapter.add_to_kernel(kernel, plugin_name="kitelogik")
"""

import functools
import json
import logging
from collections.abc import Callable
from typing import Any

from kitelogik.adapters._base import BaseGovernedAdapter, _run_governed_call

logger = logging.getLogger(__name__)


def _require_semantic_kernel():  # type: ignore[no-untyped-def]
    try:
        import semantic_kernel  # type: ignore[import-untyped]

        return semantic_kernel
    except ImportError:
        raise ImportError(
            "semantic-kernel is required for the Semantic Kernel adapter. "
            "Install it with: pip install semantic-kernel"
        ) from None


class SemanticKernelAdapter(BaseGovernedAdapter):
    """
    Governed tool executor for Microsoft Semantic Kernel.

    Semantic Kernel takes a *plugin* — a regular Python object whose
    methods are decorated with ``@kernel_function`` — and registers it
    via ``Kernel.add_plugin(<instance>, plugin_name=...)``. This adapter
    builds that plugin object dynamically, so every registered function
    becomes a governed kernel function on a single plugin class.
    """

    def kernel_plugin(self) -> Any:
        """
        Return a single plugin instance whose methods are governed
        ``@kernel_function`` methods (one per registered tool).
        """
        _require_semantic_kernel()
        from semantic_kernel.functions import kernel_function  # type: ignore[import-untyped]

        methods: dict[str, Callable] = {}
        for name, (fn, action_name, description) in self._tools.items():
            method = self._build_governed_method(name, fn, action_name)
            methods[name] = kernel_function(
                name=name,
                description=description or f"Governed tool: {name}",
            )(method)

        plugin_cls = type("KiteLogikGovernedPlugin", (), methods)
        return plugin_cls()

    def kernel_functions(self) -> Any:
        """Backwards-compatible alias for :meth:`kernel_plugin`.

        The original method name is preserved; the return value is the
        plugin instance, not a list. Semantic Kernel's API surface is
        plugin-shaped, not list-shaped.
        """
        return self.kernel_plugin()

    def add_to_kernel(self, kernel: Any, plugin_name: str = "kitelogik") -> Any:
        """Convenience helper — register the governed plugin on ``kernel``.

        Equivalent to ``kernel.add_plugin(adapter.kernel_plugin(),
        plugin_name=plugin_name)``. Returns the registered ``KernelPlugin``.
        """
        return kernel.add_plugin(self.kernel_plugin(), plugin_name=plugin_name)

    def _build_governed_method(
        self,
        name: str,
        fn: Callable,
        action_name: str,
    ) -> Callable[..., Any]:
        """Build a governed method (sig: ``(self, **kwargs)``) for the plugin class."""
        gate = self._gate
        context = self._context
        sanitize = self._sanitize
        deny_message = self._deny_message

        @functools.wraps(fn)
        async def governed(_self: Any, **kwargs: Any) -> str:
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
