# SPDX-License-Identifier: Apache-2.0
"""
governed — zero-restructuring governance for existing tool functions.

Two integration patterns:

Pattern 1: Decorator — wrap a single function
────────────────────────────────────────────
    gate    = PolicyGate(opa_client=OPAClient())
    context = SessionContext(session_id="s1", user_role="support_agent",
                             session_scopes=["read_customer"])

    @governed(gate=gate, context=context)
    async def get_customer_record(customer_id: str) -> str:
        return db.query(customer_id)

    # Governance runs before the function body executes.
    # GovernanceError is raised if the call is denied or blocked.
    result = await get_customer_record("cust_001")

Pattern 2: GovernedToolbox — register many tools, call by name
──────────────────────────────────────────────────────────────
    toolbox = GovernedToolbox(gate=gate, context=context)
    toolbox.register("get_customer_record", get_customer_record)
    toolbox.register("approve_refund", approve_refund)

    result = await toolbox.call("approve_refund", {"customer_id": "c1", "amount": 50})

GovernedToolbox is framework-agnostic — use it with OpenAI, Anthropic, Gemini,
LlamaIndex, CrewAI, or any other agent framework that executes tool calls by name.
"""

import asyncio
import functools
import inspect
import logging
from collections.abc import Callable
from typing import Any

from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import PolicyDecision, SessionContext, ToolCallInput

logger = logging.getLogger(__name__)


def _run_coroutine_sync(coro: Any) -> Any:
    """Run a coroutine from synchronous code, handling existing event loops.

    Uses ``asyncio.run()`` when no event loop is running. When called from
    within an existing loop (e.g. Jupyter, FastAPI), falls back to a
    background thread with its own loop to avoid ``RuntimeError``.

    .. warning::
            The thread-pool fallback blocks the calling thread. If the caller is
            itself a thread-pool worker with limited concurrency (e.g. CrewAI's
            tool executor), sustained concurrent usage may cause delays. This is
            an inherent limitation of sync-bridging async code.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is None:
        return asyncio.run(coro)

    # Already inside a running loop — run in a background thread
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(asyncio.run, coro)
        return future.result()


class GovernanceError(Exception):
    """
    Raised when a governed tool call is blocked or denied by policy.

    Attributes
    ----------
    decision : PolicyDecision
            The full OPA decision, including risk_tier, reason, and rule_matched.
            Inspect this to distinguish a hard block (decision.deny=True) from a
            policy denial (decision.allow=False) or a HITL requirement.
    """

    def __init__(self, message: str, decision: PolicyDecision) -> None:
        super().__init__(message)
        self.decision = decision


class governed:
    """
    Decorator that wraps a tool function with Kite Logik governance.

    The policy gate runs *before* the function body. If the call is denied or
    blocked, GovernanceError is raised and the function never executes. If the
    call is allowed, the function runs normally and its return value is
    sanitized for prompt injection before being returned.

    Works with both sync and async functions.

    Parameters
    ----------
    gate : PolicyGate
            The configured policy gate.
    context : SessionContext
            The session context (role, scopes, session_id). Shared across all
            calls made within the same session; create a new context per session.
    action : str, optional
            The OPA action name. Defaults to the function name. Override when the
            function name differs from the tool name registered in your policies.
    sanitize : bool, default True
            Whether to scan string return values for prompt injection payloads.
            Set False only if you are sanitizing elsewhere.

    Example
    -------
            @governed(gate=gate, context=ctx)
            async def approve_refund(customer_id: str, amount: float) -> str:
                    return payment_api.refund(customer_id, amount)
    """

    def __init__(
        self,
        gate: PolicyGate,
        context: SessionContext,
        action: str | None = None,
        sanitize: bool = True,
    ) -> None:
        self._gate = gate
        self._context = context
        self._action = action
        self._sanitize = sanitize

    def __call__(self, fn: Callable) -> Callable:
        action_name = self._action or fn.__name__
        gate = self._gate
        context = self._context
        sanitize = self._sanitize

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = _bind_args(fn, args, kwargs)
            tool_call = ToolCallInput(
                action=action_name,
                tool_name=action_name,
                args=bound,
            )
            decision = await gate.evaluate_tool_call(tool_call, context)
            _check_decision(action_name, decision)

            result = await fn(*args, **kwargs)
            return _maybe_sanitize(gate, result, sanitize)

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = _bind_args(fn, args, kwargs)
            tool_call = ToolCallInput(
                action=action_name,
                tool_name=action_name,
                args=bound,
            )
            decision = _run_coroutine_sync(gate.evaluate_tool_call(tool_call, context))
            _check_decision(action_name, decision)

            result = fn(*args, **kwargs)
            return _maybe_sanitize(gate, result, sanitize)

        if inspect.iscoroutinefunction(fn):
            return async_wrapper
        return sync_wrapper


class GovernedToolbox:
    """
    A governed, framework-agnostic tool registry.

    Register your existing tool functions once; call them by name through the
    governance pipeline. Compatible with any agent framework that dispatches
    tool calls as (name, args_dict) pairs.

    Example — OpenAI-style loop::

            toolbox = GovernedToolbox(gate=gate, context=ctx)
            toolbox.register("get_customer_record", get_customer_record)
            toolbox.register("approve_refund", approve_refund)

            # In your agent loop:
            for tool_call in response.choices[0].message.tool_calls:
                    import json
                    args = json.loads(tool_call.function.arguments)
                    result = await toolbox.call(tool_call.function.name, args)

    Parameters
    ----------
    gate : PolicyGate
    context : SessionContext
    sanitize : bool, default True
            Sanitize string return values for prompt injection.
    """

    def __init__(
        self,
        gate: PolicyGate,
        context: SessionContext,
        sanitize: bool = True,
    ) -> None:
        self._gate = gate
        self._context = context
        self._sanitize = sanitize
        self._tools: dict[str, Callable] = {}

    def register(
        self,
        name: str,
        fn: Callable,
        action: str | None = None,
    ) -> "GovernedToolbox":
        """
        Register a tool function under a name.

        Parameters
        ----------
        name : str
                The tool name used in agent calls and OPA policies.
        fn : Callable
                The underlying function. Sync or async.
        action : str, optional
                Override the OPA action name if it differs from ``name``.

        Returns self to support chaining::

                toolbox.register("a", fn_a).register("b", fn_b)
        """
        self._tools[name] = (fn, action or name)
        return self

    def tool_names(self) -> list[str]:
        """Return the list of registered tool names."""
        return list(self._tools.keys())

    async def call(
        self,
        name: str,
        args: dict[str, Any],
    ) -> Any:
        """
        Execute a tool call through the governance pipeline.

        Raises
        ------
        KeyError
                If ``name`` is not registered.
        GovernanceError
                If the call is blocked or denied by policy.
        """
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' is not registered in this GovernedToolbox")

        fn, action_name = self._tools[name]
        tool_call = ToolCallInput(
            action=action_name,
            tool_name=name,
            args=args,
        )
        decision = await self._gate.evaluate_tool_call(tool_call, self._context)
        _check_decision(name, decision)

        if inspect.iscoroutinefunction(fn):
            result = await fn(**args)
        else:
            result = fn(**args)

        return _maybe_sanitize(self._gate, result, self._sanitize)

    def tool_schemas(self) -> list[dict]:
        """Export registered tools as Anthropic-compatible tool definitions.

        Generates tool schemas by inspecting each registered function's
        signature and docstring. Use the returned list directly as the
        ``tools`` parameter in ``anthropic.Client.messages.create()``.

        Returns
        -------
        list[dict]
                List of tool definitions in Anthropic format, each with
                ``name``, ``description``, and ``input_schema`` keys.
        """
        schemas: list[dict] = []
        for name, (fn, _action) in self._tools.items():
            description = (fn.__doc__ or f"Call {name}").strip().split("\n")[0]
            properties: dict[str, dict] = {}
            required: list[str] = []

            sig = inspect.signature(fn)
            for param_name, param in sig.parameters.items():
                if param_name == "self":
                    continue
                json_type = _python_type_to_json(param.annotation)
                properties[param_name] = {"type": json_type}
                if param.default is inspect.Parameter.empty:
                    required.append(param_name)

            schema: dict[str, Any] = {
                "name": name,
                "description": description,
                "input_schema": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            }
            schemas.append(schema)
        return schemas

    def call_sync(self, name: str, args: dict[str, Any]) -> Any:
        """Synchronous variant of call(). Safe to call from within existing event loops."""
        return _run_coroutine_sync(self.call(name, args))

    async def evaluate_plan(self, steps: list[dict]) -> PolicyDecision:
        """
        Evaluate a proposed plan (sequence of actions) before execution.

        Returns a PolicyDecision. Callers should check decision.allow before
        proceeding with the plan steps.

        Raises GovernanceError if the plan is denied.
        """
        decision = await self._gate.evaluate_plan(steps, self._context)
        if decision.deny or not decision.allow:
            raise GovernanceError(
                f"Plan denied by policy: {decision.reason}",
                decision=decision,
            )
        return decision


# ── Internal helpers ──────────────────────────────────────────────────────────


def _bind_args(fn: Callable, args: tuple, kwargs: dict) -> dict:
    """Convert positional + keyword call args to a flat dict for OPA input."""
    try:
        sig = inspect.signature(fn)
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except TypeError:
        # Fall back to kwargs only if binding fails (e.g. *args functions)
        return kwargs


def _check_decision(action: str, decision: PolicyDecision) -> None:
    """Raise GovernanceError if the policy decision is not ALLOW."""
    if decision.deny:
        raise GovernanceError(
            f"Tool '{action}' hard blocked by security policy: {decision.reason}",
            decision=decision,
        )
    if not decision.allow:
        if decision.requires_hitl:
            raise GovernanceError(
                f"Tool '{action}' requires human approval (risk tier: {decision.risk_tier})",
                decision=decision,
            )
        raise GovernanceError(
            f"Tool '{action}' denied by policy: {decision.reason}",
            decision=decision,
        )


_TYPE_MAP: dict[type, str] = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
    list: "array",
    dict: "object",
}


def _python_type_to_json(annotation: Any) -> str:
    """Map a Python type annotation to a JSON Schema type string."""
    if annotation is inspect.Parameter.empty:
        return "string"
    return _TYPE_MAP.get(annotation, "string")


def _maybe_sanitize(gate: PolicyGate, result: Any, sanitize: bool) -> Any:
    """Sanitize string results if enabled."""
    if sanitize and isinstance(result, str):
        sanitized = gate.sanitize_response(result)
        if sanitized.was_modified:
            logger.warning(
                "Prompt injection payload redacted from tool output: patterns=%s",
                sanitized.injection_patterns_found,
            )
        return sanitized.content
    return result
