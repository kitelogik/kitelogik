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

    # Pass governed tools to your PydanticAI agent:
    tools = adapter.pydantic_tools()
"""

from kitelogik.adapters._base import BaseGovernedAdapter


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
    policy gate before execution.
    """

    def pydantic_tools(self) -> list[dict]:
        """
        Return tool definitions compatible with PydanticAI's tool interface.

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
