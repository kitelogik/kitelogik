# SPDX-License-Identifier: Apache-2.0
"""
LangChain adapter — governed tools for LangChain and LangGraph agents.

Two integration patterns:

Pattern 1: as_governed_tool() — wrap a single function as a governed BaseTool
──────────────────────────────────────────────────────────────────────────────
    from kitelogik.adapters.langchain import as_governed_tool

    governed_refund = as_governed_tool(
        name="approve_refund",
        fn=approve_refund_fn,
        gate=gate,
        context=ctx,
        description="Approve a refund for a customer. Args: customer_id (str), amount (float).",
    )

    agent = create_react_agent(llm, tools=[governed_refund])

Pattern 2: govern_toolkit() — govern an entire list of tools at once
─────────────────────────────────────────────────────────────────────
    from kitelogik.adapters.langchain import govern_toolkit
    from langchain_community.tools import some_tool_a, some_tool_b

    governed_tools = govern_toolkit([some_tool_a, some_tool_b], gate=gate, context=ctx)
    agent = create_react_agent(llm, tools=governed_tools)

Requirements
------------
    pip install langchain-core     # langchain_core.tools.BaseTool
    # or: pip install langchain    # full package

Kite Logik does NOT declare langchain-core as a hard dependency to keep the
OSS install lightweight. It is only imported at call time; if it is not
installed, a clear ImportError is raised.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from kitelogik.governed import (
    GovernanceError,
    _check_decision,
    _maybe_sanitize,
    _run_coroutine_sync,
)
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import SessionContext, ToolCallInput

if TYPE_CHECKING:
    try:
        from langchain_core.tools import BaseTool
    except ImportError:
        BaseTool = Any  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)


def as_governed_tool(
    name: str,
    fn: Callable,
    gate: PolicyGate,
    context: SessionContext,
    description: str = "",
    action: str | None = None,
    sanitize: bool = True,
) -> BaseTool:
    """
    Wrap a callable as a governed LangChain BaseTool.

    The policy gate runs before the function body. If the call is denied, the
    tool returns a structured denial message — the agent loop continues and the
    model can handle the refusal.

    Parameters
    ----------
    name : str
            Tool name shown to the model and used in OPA policy lookups.
    fn : Callable
            The underlying function. Sync or async.
    gate : PolicyGate
    context : SessionContext
    description : str
            Tool description passed to the model.
    action : str, optional
            OPA action name override. Defaults to ``name``.
    sanitize : bool, default True
            Sanitize string return values for prompt injection.

    Returns
    -------
    BaseTool
            A LangChain tool that is drop-in compatible with any agent or chain.
    """
    _require_langchain()
    from langchain_core.tools import StructuredTool

    action_name = action or name
    _gate = gate
    _context = context

    async def _governed_async(**kwargs: Any) -> str:
        tc = ToolCallInput(action=action_name, tool_name=name, args=kwargs)
        try:
            decision = await _gate.evaluate_tool_call(tc, _context)
            _check_decision(name, decision)
        except GovernanceError as e:
            return f"[BLOCKED] {e}"

        if inspect.iscoroutinefunction(fn):
            result = await fn(**kwargs)
        else:
            result = fn(**kwargs)

        result = _maybe_sanitize(_gate, result, sanitize)
        return result if isinstance(result, str) else str(result)

    def _governed_sync(**kwargs: Any) -> str:
        result: str = _run_coroutine_sync(_governed_async(**kwargs))
        return result

    # Infer a Pydantic args schema from `fn`'s signature so LangChain can
    # validate per-argument types from the model's tool call. Without this
    # the StructuredTool falls back to inferring from the wrapper's
    # ``**kwargs`` signature, which yields no fields and rejects every
    # call with a Pydantic validation error.
    args_schema = _build_args_schema_from_fn(fn, name)

    # Build a StructuredTool — supports both sync and async invocation
    return StructuredTool.from_function(
        func=_governed_sync,
        coroutine=_governed_async,
        name=name,
        description=description or f"Governed tool: {name}",
        args_schema=args_schema,
    )


def _build_args_schema_from_fn(fn: Callable, name: str) -> Any:
    """Build a Pydantic ``BaseModel`` mirroring ``fn``'s signature.

    Used to give LangChain's ``StructuredTool`` a real schema instead of
    inferring from the governed wrapper's ``**kwargs``. Falls back to
    ``None`` if ``fn`` has no inspectable parameters or if Pydantic is
    not importable, in which case StructuredTool's default inference
    runs (covering the no-args case).
    """
    try:
        from pydantic import create_model
    except ImportError:
        return None

    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return None

    fields: dict[str, Any] = {}
    for param_name, param in sig.parameters.items():
        if param_name in ("self", "cls"):
            continue
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            # Skip *args / **kwargs — LangChain wants concrete fields
            continue
        annotation = param.annotation if param.annotation is not param.empty else str
        default = ... if param.default is param.empty else param.default
        fields[param_name] = (annotation, default)

    if not fields:
        return None

    return create_model(f"{name.capitalize()}Args", **fields)


def govern_toolkit(
    tools: list[BaseTool],
    gate: PolicyGate,
    context: SessionContext,
    sanitize: bool = True,
) -> list[BaseTool]:
    """
    Wrap an existing list of LangChain BaseTool instances with governance.

    Each tool in the list is wrapped so its ``_run`` / ``_arun`` methods pass
    through the policy gate before executing.

    Parameters
    ----------
    tools : list[BaseTool]
            Existing LangChain tools (e.g. from a community toolkit).
    gate : PolicyGate
    context : SessionContext
    sanitize : bool, default True

    Returns
    -------
    list[BaseTool]
            The same tools with governance applied. Original tool objects are not
            mutated; new wrapper objects are returned.

    Example
    -------
            from langchain_community.agent_toolkits import SQLDatabaseToolkit
            raw_tools = SQLDatabaseToolkit(db=db, llm=llm).get_tools()
            governed_tools = govern_toolkit(raw_tools, gate=gate, context=ctx)
    """
    _require_langchain()
    return [_wrap_existing_tool(t, gate, context, sanitize) for t in tools]


# ── Internal helpers ──────────────────────────────────────────────────────────


def _require_langchain() -> None:
    try:
        import langchain_core  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "langchain-core is required for the LangChain adapter.\n"
            "Install it with:  pip install langchain-core\n"
            "Or:               pip install langchain"
        ) from e


def _wrap_existing_tool(
    tool: BaseTool,
    gate: PolicyGate,
    context: SessionContext,
    sanitize: bool,
) -> BaseTool:
    """Wrap an existing BaseTool instance without mutating it."""
    from langchain_core.tools import StructuredTool

    original_name = tool.name
    original_desc = tool.description
    action_name = original_name
    _gate = gate
    _context = context

    async def _governed_async(**kwargs: Any) -> str:
        tc = ToolCallInput(action=action_name, tool_name=original_name, args=kwargs)
        try:
            decision = await _gate.evaluate_tool_call(tc, _context)
            _check_decision(original_name, decision)
        except GovernanceError as e:
            return f"[BLOCKED] {e}"

        # Public API ainvoke/invoke handles RunnableConfig threading and is
        # forward-compatible with langchain-core ≥0.3 which requires `config`
        # in `_arun`. Falls back to the private accessors only when the public
        # API is unavailable (older langchain-core).
        if hasattr(tool, "ainvoke"):
            result = await tool.ainvoke(kwargs)
        elif hasattr(tool, "_arun"):
            result = await tool._arun(**kwargs)
        elif hasattr(tool, "invoke"):
            result = tool.invoke(kwargs)
        else:
            result = tool._run(**kwargs)

        result = _maybe_sanitize(_gate, result, sanitize)
        return result if isinstance(result, str) else str(result)

    def _governed_sync(**kwargs: Any) -> str:
        result: str = _run_coroutine_sync(_governed_async(**kwargs))
        return result

    # Preserve the original tool's args_schema so per-arg Pydantic
    # validation still applies. Without this, StructuredTool falls back
    # to inferring from the wrapper's ``**kwargs`` signature, which has
    # no fields and rejects every call. Fall back to inferring from the
    # tool's ``_run`` / ``_arun`` signature when no schema is exposed.
    args_schema = _extract_args_schema(tool)

    return StructuredTool.from_function(
        func=_governed_sync,
        coroutine=_governed_async,
        name=original_name,
        description=original_desc,
        args_schema=args_schema,
    )


def _extract_args_schema(tool: Any) -> Any:
    """Pull an ``args_schema`` off a BaseTool, or infer one from ``_run``."""
    schema = getattr(tool, "args_schema", None)
    if schema is not None:
        return schema
    for method_name in ("_run", "_arun"):
        method = getattr(tool, method_name, None)
        if method is None:
            continue
        return _build_args_schema_from_fn(method, getattr(tool, "name", "tool"))
    return None
