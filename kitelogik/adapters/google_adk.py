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

    # Pass governed tools to your ADK agent:
    tools = adapter.adk_tools()
"""

from kitelogik.adapters._base import BaseGovernedAdapter


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
    policy gate before execution.
    """

    def adk_tools(self) -> list[dict]:
        """
        Return tool definitions in a format compatible with Google ADK.

        Each tool definition includes name, description, and a governed
        execution wrapper.
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
