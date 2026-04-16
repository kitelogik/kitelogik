# SPDX-License-Identifier: Apache-2.0
"""
OpenAI adapter — governed tool execution for OpenAI function calling.

Drop this into any existing OpenAI agent loop. The adapter intercepts
tool_calls from the model response and routes each one through the Kite
Logik policy gate before the underlying function executes.

Usage
-----
    import json
    import openai
    from kitelogik.adapters.openai import OpenAIAdapter

    gate    = PolicyGate(opa_client=OPAClient())
    context = SessionContext(
        session_id="sess_001",
        user_role="support_agent",
        session_scopes=["read_customer", "approve_refund_under_100"],
    )

    adapter = OpenAIAdapter(gate=gate, context=context)
    adapter.register("get_customer_record", get_customer_record_fn)
    adapter.register("approve_refund", approve_refund_fn)

    # Your existing OpenAI agent loop:
    client   = openai.AsyncOpenAI()
    messages = [{"role": "user", "content": "Refund $50 to cust_001"}]

    while True:
        response = await client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            tools=adapter.openai_tool_schemas(),   # ← pass governed schemas
        )
        choice = response.choices[0]
        if choice.finish_reason != "tool_calls":
            break

        messages.append(choice.message)
        tool_results = await adapter.execute_all(choice.message.tool_calls)
        messages.extend(tool_results)

    print(response.choices[0].message.content)

No changes are needed to your OpenAI client configuration, model selection,
message history, or prompt. Only tool execution is intercepted.
"""

import asyncio
import inspect
import json
import logging
from collections.abc import Callable
from typing import Any

from kitelogik.governed import GovernanceError, _check_decision, _maybe_sanitize
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import SessionContext, ToolCallInput

logger = logging.getLogger(__name__)


class OpenAIAdapter:
    """
    Governed tool executor for OpenAI's function-calling interface.

    Wraps the standard `tool_calls` execution path. Each call is evaluated
    by the policy gate before the underlying function runs. Denied calls
    return an error message in the tool result (the agent loop continues;
    the model sees the denial and can respond appropriately).

    Parameters
    ----------
    gate : PolicyGate
    context : SessionContext
    sanitize : bool, default True
            Sanitize string return values for prompt injection.
    deny_message : str, optional
            Message returned to the model when a call is blocked.
            Defaults to a standard governance denial message.
    """

    def __init__(
        self,
        gate: PolicyGate,
        context: SessionContext,
        sanitize: bool = True,
        deny_message: str | None = None,
    ) -> None:
        self._gate = gate
        self._context = context
        self._sanitize = sanitize
        self._deny_message = deny_message or "Action blocked by governance policy."
        self._tools: dict[str, tuple[Callable, dict]] = {}

    def register(
        self,
        name: str,
        fn: Callable,
        schema: dict | None = None,
        action: str | None = None,
    ) -> "OpenAIAdapter":
        """
        Register a tool function.

        Parameters
        ----------
        name : str
                Tool name — must match what appears in your OpenAI tool schemas.
        fn : Callable
                The underlying function to execute if the call is allowed.
        schema : dict, optional
                OpenAI function schema (the ``function`` block inside a tool
                definition). If provided, it is returned by ``openai_tool_schemas()``.
        action : str, optional
                OPA action name override. Defaults to ``name``.

        Returns self for chaining.
        """
        self._tools[name] = (fn, action or name, schema)
        return self

    def openai_tool_schemas(self) -> list[dict]:
        """
        Return the list of OpenAI tool definitions for all registered tools
        that have a schema. Pass this directly to the ``tools`` parameter of
        ``client.chat.completions.create()``.
        """
        return [
            {"type": "function", "function": schema}
            for _, _, schema in self._tools.values()
            if schema is not None
        ]

    async def execute(self, tool_call: Any) -> dict:
        """
        Execute a single OpenAI tool_call through the governance pipeline.

        Parameters
        ----------
        tool_call : openai.types.chat.ChatCompletionMessageToolCall
                A single tool call object from ``response.choices[0].message.tool_calls``.

        Returns
        -------
        dict
                An OpenAI-format tool result message ready to append to messages::

                        {"role": "tool", "tool_call_id": "...", "content": "..."}
        """
        name = tool_call.function.name
        tool_call_id = tool_call.id

        try:
            args = json.loads(tool_call.function.arguments)
        except json.JSONDecodeError:
            return _tool_result(tool_call_id, '{"error": "Malformed tool arguments"}')

        if name not in self._tools:
            return _tool_result(
                tool_call_id,
                json.dumps({"error": f"Tool '{name}' not registered in adapter"}),
            )

        fn, action_name, _ = self._tools[name]
        tc = ToolCallInput(action=action_name, tool_name=name, args=args)

        try:
            decision = await self._gate.evaluate_tool_call(tc, self._context)
            _check_decision(name, decision)
        except GovernanceError as e:
            logger.info("Tool call blocked by governance: tool=%s reason=%s", name, e)
            return _tool_result(
                tool_call_id,
                json.dumps({"blocked": True, "reason": self._deny_message}),
            )

        try:
            if inspect.iscoroutinefunction(fn):
                result = await fn(**args)
            else:
                result = fn(**args)
        except Exception as e:
            logger.exception("Tool execution error: tool=%s", name)
            return _tool_result(tool_call_id, json.dumps({"error": str(e)}))

        result = _maybe_sanitize(self._gate, result, self._sanitize)
        content = result if isinstance(result, str) else json.dumps(result)
        return _tool_result(tool_call_id, content)

    async def execute_all(self, tool_calls: list[Any]) -> list[dict]:
        """
        Execute a list of tool_calls concurrently through the governance pipeline.

        Returns a list of tool result messages in the same order as ``tool_calls``.
        Safe to pass directly to ``messages.extend()``.
        """
        return await asyncio.gather(*[self.execute(tc) for tc in tool_calls])

    def execute_sync(self, tool_call: Any) -> dict:
        """Synchronous variant of execute(). Runs the event loop internally."""
        return asyncio.get_event_loop().run_until_complete(self.execute(tool_call))


def _tool_result(tool_call_id: str, content: str) -> dict:
    return {"role": "tool", "tool_call_id": tool_call_id, "content": content}
