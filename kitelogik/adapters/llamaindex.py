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

    # Pass governed tools to your LlamaIndex agent:
    tools = adapter.llamaindex_tools()
"""

from kitelogik.adapters._base import BaseGovernedAdapter


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
    policy gate before execution.
    """

    def llamaindex_tools(self) -> list[dict]:
        """
        Return tool definitions compatible with LlamaIndex's tool interface.

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
