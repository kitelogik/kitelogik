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

    # Pass governed tools to your Semantic Kernel agent:
    tools = adapter.kernel_functions()
"""

from kitelogik.adapters._base import BaseGovernedAdapter


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

    Wraps tool functions and routes each call through the Kite Logik
    policy gate before execution.
    """

    def kernel_functions(self) -> list[dict]:
        """
        Return tool definitions compatible with Semantic Kernel's function interface.

        Each tool includes a governed wrapper function, name, and description.
        """
        tools = []
        for name, (fn, action_name, description) in self._tools.items():
            tools.append(
                {
                    "name": name,
                    "description": description,
                    "function": self._make_governed_fn(name, fn, action_name),
                }
            )
        return tools
