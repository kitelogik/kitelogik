# SPDX-License-Identifier: Apache-2.0
"""
AgentSession — the core agent execution loop for Kite Logik.

The PolicyGate runs in-process for policy evaluation. Every tool call
flows through the governance pipeline: credential check → OPA evaluation
→ allow/deny/HITL escalation → tool dispatch → response sanitisation.
"""

import inspect
import json
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from kitelogik.agents.llm import AnthropicLLMClient, LLMClient, ToolCall
from kitelogik.anchor.credentials import CredentialBroker
from kitelogik.anchor.models import ActionStatus, PendingAction
from kitelogik.anchor.queue import HITLQueue
from kitelogik.audit.store import AuditStore
from kitelogik.memory.models import TrustTier
from kitelogik.memory.store import MemoryStore
from kitelogik.observability.tracer import get_tracer
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import GovernanceEvent, PolicyDecision, SessionContext, ToolCallInput

from .tools import TOOL_SCHEMAS, execute_tool

logger = logging.getLogger(__name__)

# Memory tools are handled locally — they don't route through MCP
_MEMORY_TOOLS = {"query_memory", "write_memory"}


@dataclass
class SessionResult:
    session_id: str
    final_response: str
    tool_calls: list[dict] = field(default_factory=list)
    blocked_calls: list[dict] = field(default_factory=list)
    hitl_required: list[dict] = field(default_factory=list)


class AgentSession:
    """
    A single scoped execution of a Claude agent.

    Invariants:
    - A session token is issued at run start and revoked on completion.
    - HITL actions block until approved/denied/timed-out (not fire-and-forget).
    - Memory reads/writes carry provenance; external values are sanitized.

    Parameters
    ----------
    gate : ``PolicyGate``
            In-process policy gate for governance evaluation.
    context : ``SessionContext``
            Session-scoped identity, scopes, and delegation metadata.
    model : str, optional
            LLM model identifier (default ``"claude-sonnet-4-6"``).
    hitl_queue : ``HITLQueue`` or None, optional
            Human-in-the-loop escalation queue.
    hitl_timeout : float, optional
            Seconds to wait for a HITL decision before timing out (default 300).
    credential_broker : ``CredentialBroker`` or None, optional
            Broker for issuing and revoking session-scoped credentials.
    memory_store : ``MemoryStore`` or None, optional
            Provenance-tracked agent memory store.
    audit_store : ``AuditStore`` or None, optional
            Immutable audit log store.
    llm_client : ``LLMClient`` or None, optional
            LLM provider client. Defaults to ``AnthropicLLMClient``.
    tools : list[dict] or None, optional
            Tool schemas to pass to the LLM. Defaults to the built-in demo
            tool schemas if not provided.
    tool_handler : callable or None, optional
            Async function ``(name: str, args: dict) -> str`` for dispatching
            tool calls. When provided, used instead of the built-in mock
            tool dispatcher for tools not handled by memory.
    """

    def __init__(
        self,
        gate: PolicyGate,
        context: SessionContext,
        model: str = "claude-sonnet-4-6",
        hitl_queue: HITLQueue | None = None,
        hitl_timeout: float = 300.0,
        credential_broker: CredentialBroker | None = None,
        memory_store: MemoryStore | None = None,
        audit_store: AuditStore | None = None,
        llm_client: LLMClient | None = None,
        tools: list[dict] | None = None,
        tool_handler: Callable[[str, dict], Any] | None = None,
    ) -> None:
        if gate is None:
            raise ValueError("AgentSession requires a PolicyGate")
        self.gate = gate
        self.context = context
        self.model = model
        self.hitl_queue = hitl_queue
        self.hitl_timeout = hitl_timeout
        self.credential_broker = credential_broker
        self.memory_store = memory_store
        self.audit_store = audit_store
        self._llm = llm_client or AnthropicLLMClient()
        self._tracer = get_tracer("kitelogik.agent")
        self._tools = tools or TOOL_SCHEMAS
        self._tool_handler = tool_handler

    async def run_async(
        self,
        prompt: str,
        max_iterations: int = 10,
        on_event: Callable[[dict], None] | None = None,
    ) -> SessionResult:
        """
        Run the agent session asynchronously.

        Issues a credential at the start of the session and revokes it on
        completion. HITL actions block until a human decision is received.

        Parameters
        ----------
        prompt : str
                The user prompt to execute.
        max_iterations : int, optional
                Maximum number of LLM turns (default 10).
        on_event : callable or None, optional
                Event callback invoked for governance, HITL, and sandbox events.

        Returns
        -------
        ``SessionResult``
                Final response text, tool call records, and blocked/HITL lists.
        """
        with self._tracer.start_as_current_span("agent_session") as span:
            span.set_attribute("kitelogik.session_id", self.context.session_id)
            span.set_attribute("gen_ai.request.model", self.model)
            span.set_attribute("kitelogik.user_role", self.context.user_role)

            # Governance check: evaluate agent.spawn before proceeding
            spawn_event = GovernanceEvent(
                event_type="agent.spawn",
                session_id=self.context.session_id,
                action="agent.spawn",
                context=self.context,
                requested_capabilities=list(self.context.session_scopes),
            )
            spawn_decision = await self.gate.evaluate(spawn_event)
            if not spawn_decision.allow or spawn_decision.deny:
                if on_event:
                    on_event(
                        {
                            "type": "agent_spawn_denied",
                            "session_id": self.context.session_id,
                            "reason": spawn_decision.reason,
                        }
                    )
                from kitelogik.governed import GovernanceError

                raise GovernanceError(
                    f"Agent spawn denied: {spawn_decision.reason}",
                    decision=spawn_decision,
                )

            # Issue session-scoped credential (skip if already delegated)
            token = None
            if self.credential_broker and not self.context.token_id:
                token = self.credential_broker.issue(
                    self.context.session_id,
                    self.context.session_scopes,
                )
                self.context = self.context.model_copy(update={"token_id": token.token_id})
                span.set_attribute("kitelogik.token_id", token.token_id)
                if on_event:
                    on_event(
                        {
                            "type": "credential_issued",
                            "token_id": token.token_id,
                            "scopes": token.scopes,
                        }
                    )
            elif self.context.token_id:
                span.set_attribute("kitelogik.token_id", self.context.token_id)
                span.set_attribute("kitelogik.delegation_depth", self.context.delegation_depth)

            try:
                result = await self._run_loop(prompt, max_iterations, on_event)
            finally:
                # Revoke token only if this session issued it (not delegated)
                if token and self.credential_broker:
                    self.credential_broker.revoke(token.token_id)
                    if on_event:
                        on_event({"type": "credential_revoked", "token_id": token.token_id})

            return result

    async def _run_loop(
        self,
        prompt: str,
        max_iterations: int,
        on_event: Callable[[dict], None] | None,
    ) -> SessionResult:
        result = SessionResult(session_id=self.context.session_id, final_response="")
        messages: list[dict] = [{"role": "user", "content": prompt}]

        system = (
            "You are an AI agent operating inside the Kite Logik governance platform. "
            "Your role is to attempt the action the user requests using the available tools. "
            "Do not pre-judge whether an action will be allowed — always call the relevant tool "
            "and let the policy enforcement layer decide. "
            "If a tool call is blocked or requires approval, relay that outcome to the user clearly."  # noqa: E501
        )

        for _ in range(max_iterations):
            response = await self._llm.create_message(
                model=self.model,
                max_tokens=4096,
                tools=self._tools,
                system=system,
                messages=messages,
            )

            if response.stop_reason == "end_turn":
                if response.text_content:
                    result.final_response = response.text_content
                break

            if response.stop_reason == "tool_use":
                messages.append(self._llm.format_assistant_message(response.raw_content))
                tool_results = []

                for tc in response.tool_calls:
                    call_record = {"tool": tc.name, "args": tc.input}
                    tool_content = await self._dispatch_direct(tc, call_record, result, on_event)

                    tool_results.append(self._llm.format_tool_result(tc.id, tool_content))

                messages.append({"role": "user", "content": tool_results})

        return result

    async def _dispatch_direct(
        self,
        block: ToolCall,
        call_record: dict,
        result: SessionResult,
        on_event: Callable[[dict], None] | None,
    ) -> str:
        """
        Evaluate via in-process PolicyGate and dispatch the tool call.

        Parameters
        ----------
        block : ``ToolCall``
                The tool call extracted from the LLM response.
        call_record : dict
                Mutable record dict accumulating metadata for this call.
        result : ``SessionResult``
                Session result object to append tool call / blocked records to.
        on_event : callable or None
                Event callback.

        Returns
        -------
        str
                Tool result content to feed back to the LLM.
        """
        tool_call = ToolCallInput(
            action=block.name,
            tool_name=block.name,
            args=block.input,
            resource_path=block.input.get("path") or block.input.get("resource_path"),
        )

        t0 = time.perf_counter()
        decision = await self.gate.evaluate_tool_call(tool_call, self.context)
        latency_ms = int((time.perf_counter() - t0) * 1000)

        if on_event:
            on_event(
                {
                    "type": "gate_decision",
                    "tool": block.name,
                    "args": block.input,
                    "decision": decision,
                    "latency_ms": latency_ms,
                    "context": self.context,
                }
            )

        call_record["decision"] = decision.model_dump(mode="json")

        if decision.deny:
            result.blocked_calls.append(call_record)
            await self._audit("blocked", block.name, block.input, decision)
            return (
                f"Tool call '{block.name}' was hard-blocked by the security policy. "
                f"Reason: {decision.reason}. "
                "This action is not permitted in this environment. "
                "Inform the user and do not attempt this action again."
            )

        if decision.requires_hitl:
            tool_content = await self._handle_hitl(block, decision, call_record, result, on_event)
            return tool_content

        if not decision.allow:
            result.blocked_calls.append(call_record)
            await self._audit("soft_denied", block.name, block.input, decision)
            return (
                f"Tool call '{block.name}' was denied by policy. "
                f"Reason: {decision.reason}. "
                "Suggest a compliant alternative to the user if one exists."
            )

        tool_content = await self._execute_tool(block.name, block.input, on_event)
        result.tool_calls.append(call_record)
        await self._audit("allowed", block.name, block.input, decision)
        return tool_content

    async def _audit(
        self,
        outcome: str,
        tool_name: str,
        args: dict,
        decision: "PolicyDecision",
        hitl_action_id: str | None = None,
        hitl_decided_by: str | None = None,
    ) -> None:
        if self.audit_store:
            try:
                await self.audit_store.record(
                    session_id=self.context.session_id,
                    tool_name=tool_name,
                    args=args,
                    decision=decision,
                    context=self.context,
                    outcome=outcome,
                    hitl_action_id=hitl_action_id,
                    hitl_decided_by=hitl_decided_by,
                )
            except Exception as e:
                logger.error(
                    "Audit write failed (non-fatal): session=%s error=%s",
                    self.context.session_id,
                    e,
                    exc_info=True,
                )

    async def _handle_hitl(
        self,
        block: ToolCall,
        decision: PolicyDecision,
        call_record: dict,
        result: SessionResult,
        on_event: Callable[[dict], None] | None,
    ) -> str:
        action_id = uuid.uuid4().hex[:12]

        if self.hitl_queue:
            action = PendingAction(
                id=action_id,
                session_id=self.context.session_id,
                tool_name=block.name,
                args=block.input,
                risk_tier=decision.risk_tier.value,
                status=ActionStatus.PENDING,
                created_at=datetime.now(UTC),
            )
            await self.hitl_queue.enqueue(action)

        call_record["hitl_action_id"] = action_id

        if on_event:
            on_event(
                {
                    "type": "hitl_queued",
                    "tool": block.name,
                    "args": block.input,
                    "action_id": action_id,
                    "risk_tier": decision.risk_tier.value,
                    "timeout_seconds": int(self.hitl_timeout),
                }
            )

        await self._audit(
            "hitl_queued", block.name, block.input, decision, hitl_action_id=action_id
        )

        # Block and wait for human decision
        if self.hitl_queue:
            decided = await self.hitl_queue.wait_for_decision(
                action_id, timeout_seconds=self.hitl_timeout
            )

            if on_event:
                on_event(
                    {
                        "type": "hitl_resolved",
                        "action_id": action_id,
                        "status": decided.status.value,
                        "decided_by": decided.decided_by,
                        "denial_reason": decided.denial_reason,
                    }
                )

            if decided.status == ActionStatus.APPROVED:
                result.tool_calls.append(call_record)
                tool_content = await self._execute_tool(block.name, block.input, on_event)
                await self._audit(
                    "hitl_approved",
                    block.name,
                    block.input,
                    decision,
                    hitl_action_id=action_id,
                    hitl_decided_by=decided.decided_by,
                )
                return tool_content

            elif decided.status == ActionStatus.TIMED_OUT:
                result.hitl_required.append(call_record)
                await self._audit(
                    "hitl_timeout",
                    block.name,
                    block.input,
                    decision,
                    hitl_action_id=action_id,
                )
                return (
                    f"Tool call '{block.name}' timed out waiting for human approval "
                    f"after {int(self.hitl_timeout)}s. The action was not executed. "
                    "Inform the user and ask them to retry after an approver reviews the request."
                )
            else:
                result.blocked_calls.append(call_record)
                reason = decided.denial_reason or "Denied by approver"
                await self._audit(
                    "hitl_denied",
                    block.name,
                    block.input,
                    decision,
                    hitl_action_id=action_id,
                    hitl_decided_by=decided.decided_by,
                )
                return (
                    f"Tool call '{block.name}' was denied by human approver. "
                    f"Reason: {reason}. Inform the user of this decision."
                )

        # No queue — surface as pending (Phase 2 fallback)
        result.hitl_required.append(call_record)
        return (
            f"Tool call '{block.name}' requires human approval "
            f"(risk tier: {decision.risk_tier.value}). "
            f"Action ID: {action_id}. "
            "The action has been queued for review. Inform the user."
        )

    async def _execute_tool(
        self,
        tool_name: str,
        args: dict,
        on_event: Callable[[dict], None] | None,
    ) -> str:
        # Memory tools are handled internally
        if tool_name in _MEMORY_TOOLS and self.memory_store:
            return await self._handle_memory_tool(tool_name, args)

        if self._tool_handler:
            handler_result = self._tool_handler(tool_name, args)
            if inspect.isawaitable(handler_result):
                raw_output = await handler_result
            else:
                raw_output = handler_result
            raw_output = str(raw_output)
        else:
            raw_output = execute_tool(tool_name, args)
        if self.gate:
            sanitized = self.gate.sanitize_response(raw_output)
            if on_event:
                on_event(
                    {
                        "type": "sanitize",
                        "was_modified": sanitized.was_modified,
                        "patterns": sanitized.injection_patterns_found,
                    }
                )
            return sanitized.content
        return raw_output

    async def _handle_memory_tool(self, tool_name: str, args: dict) -> str:
        if tool_name == "query_memory":
            key = args.get("key", "")
            entry = await self.memory_store.read(key)
            if entry is None:
                return json.dumps({"error": f"Key '{key}' not found in memory"})
            return json.dumps(
                {
                    "key": entry.key,
                    "value": entry.value,
                    "trust_tier": entry.trust_tier.value,
                    "source": entry.source,
                    "sanitized": entry.sanitized,
                }
            )

        if tool_name == "write_memory":
            key = args.get("key", "")
            value = args.get("value", "")
            # Worker agents (delegation_depth > 0) write at lower trust
            trust_tier = (
                TrustTier.DELEGATED if self.context.delegation_depth > 0 else TrustTier.EXTERNAL
            )
            entry = await self.memory_store.write(
                key=key,
                value=value,
                trust_tier=trust_tier,
                source="agent",
                session_id=self.context.session_id,
            )
            return json.dumps(
                {
                    "status": "written",
                    "key": entry.key,
                    "trust_tier": entry.trust_tier.value,
                    "sanitized": entry.sanitized,
                }
            )

        return json.dumps({"error": f"Unknown memory tool: '{tool_name}'"})
