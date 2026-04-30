# SPDX-License-Identifier: Apache-2.0
"""
Dify adapter — governed tool execution for Dify agent workflows.

Dify tools are different from the other framework integrations: they are
*deployable plugin artifacts* (a Python class subclassing ``Tool`` plus a
YAML manifest), not in-process Python objects passed to a constructor.
The "Dify Plugin SDK" expects you to:

1. Subclass ``dify_plugin.tool.Tool``.
2. Implement ``_invoke(self, tool_parameters: dict) -> Generator[ToolInvokeMessage]``.
3. Ship a ``manifest.yaml`` describing the tool's name, description, and
   input schema.
4. Deploy the plugin to a Dify instance.

Two integration paths are supported here:

Path 1 — :class:`GovernedDifyTool` base class (recommended)
    Subclass ``GovernedDifyTool`` instead of ``dify_plugin.tool.Tool``.
    Override ``_invoke_governed(tool_parameters)`` (a regular method) and
    the base class wraps it in a governed ``_invoke`` that runs the Kite
    Logik policy gate before your code executes. Suitable for production
    Dify plugins.

Path 2 — :meth:`DifyAdapter.dify_tools` (legacy, in-process only)
    Returns a list of dict-shaped tool descriptors. The shape is *not*
    compatible with Dify's plugin loader — these dicts cannot be
    deployed to a real Dify instance — but they remain useful for
    adapter-level governance unit tests via
    :meth:`BaseGovernedAdapter.execute`.

Usage (Path 1)
--------------
    from kitelogik.adapters.dify import GovernedDifyTool
    from kitelogik.tether.gate import PolicyGate
    from kitelogik.tether.models import SessionContext

    class GetCustomerTool(GovernedDifyTool):
        # Configure governance once; ``_gate`` and ``_context`` can be
        # injected at instance-construction time by the plugin runtime.
        gate = PolicyGate(opa_client=...)
        context = SessionContext(session_id="...", user_role="...", session_scopes=[...])
        action = "get_customer"

        def _invoke_governed(self, tool_parameters):
            customer_id = tool_parameters["customer_id"]
            yield self.create_text_message(f"record:{customer_id}")
"""

import asyncio
import inspect
import json
import logging
from collections.abc import Callable, Generator
from typing import Any

from kitelogik.adapters._base import BaseGovernedAdapter
from kitelogik.governed import GovernanceError, _check_decision, _maybe_sanitize
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import SessionContext, ToolCallInput

logger = logging.getLogger(__name__)


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

    .. note::
        Dify is unique among the supported frameworks: tools are deployable
        plugin artifacts (subclass + YAML manifest) rather than in-process
        Python objects. For a real Dify integration, subclass
        :class:`GovernedDifyTool`. The :meth:`dify_tools` method below
        is preserved for adapter-level governance unit tests but is *not*
        deployable to a Dify instance.
    """

    def dify_tools(self) -> list[dict]:
        """
        Return dict-shaped tool descriptors for in-process testing.

        Each dict contains ``{name, description, function}``. The
        callable runs the governance pipeline before invoking the
        registered function. This shape is **not** accepted by the Dify
        plugin loader — use :class:`GovernedDifyTool` for deployment.
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


class GovernedDifyTool:
    """Base class for Dify plugin tools that need Kite Logik governance.

    Subclass this **in place of** ``dify_plugin.tool.Tool`` (this class
    inherits from ``Tool`` when ``dify_plugin`` is installed) and
    implement :meth:`_invoke_governed` instead of ``_invoke``. The
    base class wraps your method with the policy pipeline so every
    invocation is gated before your code runs.

    Configure governance via class attributes (or set them at
    construction time):

    Attributes
    ----------
    gate : PolicyGate
        The configured policy gate.
    context : SessionContext
        The session context for this Dify tenant / user / agent.
    action : str | None
        The OPA action name. Falls back to ``self.__class__.__name__``
        if not set.
    sanitize : bool, default True
        Whether to sanitize string return values for prompt injection.
    deny_message : str
        Override the agent-visible denial message.

    Implementation note
    -------------------
    The class deliberately does **not** import ``dify_plugin`` at
    module-load time so the base class works for unit tests without
    Dify installed. When ``dify_plugin`` is available, the
    ``_invoke`` override below mirrors Dify's expected generator
    contract; otherwise it raises a clear ImportError.
    """

    gate: PolicyGate | None = None
    context: SessionContext | None = None
    action: str | None = None
    sanitize: bool = True
    deny_message: str = "Action blocked by governance policy."

    def _invoke_governed(self, tool_parameters: dict[str, Any]) -> Any:
        """Implement the tool body. Will only run if governance allows it."""
        raise NotImplementedError

    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[Any, None, None]:
        """Dify's expected entry point — wraps ``_invoke_governed`` with governance.

        Yields the same ``ToolInvokeMessage`` objects Dify expects from a
        regular ``Tool._invoke``. On governance denial yields a single
        text message with the configured ``deny_message`` so the
        plugin doesn't silently swallow the block.

        The ``dify_plugin`` package is optional here: when installed, the
        helpers below build real ``ToolInvokeMessage`` instances; when
        not, they fall back to a dict shape that's easy to unit-test.
        """
        if self.gate is None or self.context is None:
            raise RuntimeError(
                "GovernedDifyTool requires .gate and .context to be set "
                "before invocation. Set them as class attributes or in "
                "__init__."
            )

        action_name = self.action or self.__class__.__name__
        tc = ToolCallInput(
            action=action_name,
            tool_name=self.__class__.__name__,
            args=tool_parameters or {},
        )

        try:
            decision = asyncio.run(self.gate.evaluate_tool_call(tc, self.context))
            _check_decision(action_name, decision)
        except GovernanceError as e:
            logger.info(
                "Dify tool blocked by governance: tool=%s reason=%s",
                self.__class__.__name__,
                e,
            )
            yield self._block_message(self.deny_message)
            return

        result = self._invoke_governed(tool_parameters)

        # ``_invoke_governed`` may return a generator (Dify-native) or a
        # plain value. Normalise both shapes through sanitize and yield.
        if inspect.isgenerator(result):
            for msg in result:
                yield self._sanitize_message(msg)
        else:
            yield self._sanitize_message(self._wrap_text(result))

    def _block_message(self, reason: str) -> Any:
        """Build a Dify text message that surfaces the governance denial."""
        try:
            from dify_plugin.entities.tool import (  # type: ignore[import-untyped]
                ToolInvokeMessage,
            )

            return ToolInvokeMessage(
                type=ToolInvokeMessage.MessageType.TEXT,
                message=ToolInvokeMessage.TextMessage(
                    text=json.dumps({"blocked": True, "reason": reason})
                ),
            )
        except ImportError:
            # Tests without dify_plugin still want a stable shape.
            return {"type": "text", "text": json.dumps({"blocked": True, "reason": reason})}

    def _wrap_text(self, content: Any) -> Any:
        """Wrap a plain return value as a Dify text ToolInvokeMessage."""
        text = content if isinstance(content, str) else json.dumps(content)
        try:
            from dify_plugin.entities.tool import (  # type: ignore[import-untyped]
                ToolInvokeMessage,
            )

            return ToolInvokeMessage(
                type=ToolInvokeMessage.MessageType.TEXT,
                message=ToolInvokeMessage.TextMessage(text=text),
            )
        except ImportError:
            return {"type": "text", "text": text}

    def _sanitize_message(self, msg: Any) -> Any:
        """Apply the configured sanitizer to a ``ToolInvokeMessage``'s text."""
        if not self.sanitize or self.gate is None:
            return msg
        text = self._extract_text(msg)
        if text is None:
            return msg
        sanitized = _maybe_sanitize(self.gate, text, True)
        if sanitized != text:
            return self._wrap_text(sanitized)
        return msg

    def _extract_text(self, msg: Any) -> str | None:
        """Pull the text payload off a ToolInvokeMessage when present."""
        # Real Dify ToolInvokeMessage carries the text at .message.text;
        # the dict fallback used in tests carries it at ['text'].
        message = getattr(msg, "message", None)
        if message is not None and hasattr(message, "text"):
            text = message.text
            return text if isinstance(text, str) else None
        if isinstance(msg, dict):
            text = msg.get("text")
            return text if isinstance(text, str) else None
        return None


def _resolve_dify_tool_base() -> Any:
    """Resolve the Dify ``Tool`` base class lazily. Returns ``object`` when
    ``dify_plugin`` is not installed so the module still imports cleanly
    in environments without the SDK (CI, unit tests, etc.).
    """
    try:
        from dify_plugin.tool import Tool  # type: ignore[import-untyped]

        return Tool
    except ImportError:
        return object


# Re-class GovernedDifyTool to inherit from Dify's Tool when available.
# This pattern keeps the module importable everywhere while giving real
# Dify deployments a proper subclass relationship.
_dify_tool_base = _resolve_dify_tool_base()
if _dify_tool_base is not object:
    GovernedDifyTool = type(  # type: ignore[assignment,misc]
        "GovernedDifyTool",
        (GovernedDifyTool, _dify_tool_base),
        {},
    )


# ── Convenience: turn a plain callable into a GovernedDifyTool subclass ───


def make_governed_dify_tool(
    fn: Callable[..., Any],
    *,
    gate: PolicyGate,
    context: SessionContext,
    action: str | None = None,
    sanitize: bool = True,
    deny_message: str = "Action blocked by governance policy.",
    name: str | None = None,
) -> type[GovernedDifyTool]:
    """Build a :class:`GovernedDifyTool` subclass that wraps ``fn``.

    Useful when you have a plain Python function and want it deployable
    as a Dify plugin without writing a class manually.

    Parameters
    ----------
    fn
        The function to wrap. Receives ``**tool_parameters`` as kwargs.
    gate, context, action, sanitize, deny_message
        Governance config — applied to the resulting tool class.
    name
        Class name. Defaults to ``fn.__name__.title() + "Tool"``.

    Returns
    -------
    type[GovernedDifyTool]
        The dynamically-built tool class. Instantiate it inside the Dify
        plugin runtime.
    """
    cls_name = name or f"{fn.__name__.title()}Tool"

    def _invoke_governed(self: Any, tool_parameters: dict[str, Any]) -> Any:
        return fn(**(tool_parameters or {}))

    return type(  # type: ignore[no-any-return]
        cls_name,
        (GovernedDifyTool,),
        {
            "gate": gate,
            "context": context,
            "action": action or fn.__name__,
            "sanitize": sanitize,
            "deny_message": deny_message,
            "_invoke_governed": _invoke_governed,
        },
    )
