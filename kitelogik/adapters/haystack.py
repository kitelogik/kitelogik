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
    adapter.register("get_customer", get_customer_fn, description="Get customer by ID")

    # Pass governed tools to your Haystack agent:
    tools = adapter.haystack_tools()
"""

from kitelogik.adapters._base import BaseGovernedAdapter


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

    Wraps tool functions and routes each call through the Kite Logik
    policy gate before execution.
    """

    def haystack_tools(self) -> list[dict]:
        """
        Return tool definitions compatible with Haystack's tool interface.

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
