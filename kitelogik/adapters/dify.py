# SPDX-License-Identifier: Apache-2.0
"""
Dify adapter — governed tool execution for Dify agent workflows.

Drop this into any Dify custom tool integration. The adapter intercepts
tool calls and routes each one through the Kite Logik policy gate before
the underlying function executes.

Usage
-----
    from kitelogik.adapters.dify import DifyAdapter

    gate    = PolicyGate(opa_client=OPAClient())
    context = SessionContext(
        session_id="sess_001",
        user_role="analyst",
        session_scopes=["read_customer"],
    )

    adapter = DifyAdapter(gate=gate, context=context)
    adapter.register("get_customer", get_customer_fn, description="Get customer by ID")

    # Pass governed tools to your Dify workflow:
    tools = adapter.dify_tools()
"""

from kitelogik.adapters._base import BaseGovernedAdapter


def _require_dify():  # type: ignore[no-untyped-def]
    try:
        import dify_plugin  # type: ignore[import-untyped]

        return dify_plugin
    except ImportError:
        raise ImportError(
            "dify-plugin-sdk is required for the Dify adapter. "
            "Install it with: pip install dify-plugin-sdk"
        ) from None


class DifyAdapter(BaseGovernedAdapter):
    """
    Governed tool executor for Dify agent workflows.

    Wraps tool functions and routes each call through the Kite Logik
    policy gate before execution.
    """

    def dify_tools(self) -> list[dict]:
        """
        Return tool definitions compatible with Dify's tool interface.

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
