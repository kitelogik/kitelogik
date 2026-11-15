# SPDX-License-Identifier: Apache-2.0
"""
AgentSession — the core agent execution loop for Kite Logik.

The PolicyGate runs in-process for policy evaluation. Every tool call
flows through the governance pipeline: credential check → OPA evaluation
→ allow/deny/HITL escalation → tool dispatch → response sanitisation.
"""

import asyncio
import inspect
import json
import logging
import random
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from kitelogik.agents.errors import (
    AgentSessionError,
    LLMProviderError,
    SessionAlreadyRanError,
    ToolHandlerError,
)
from kitelogik.agents.llm import (
    DEFAULT_MAX_TOKENS,
    AnthropicLLMClient,
    LLMClient,
    LLMResponse,
    RetryConfig,
    ToolCall,
    is_retryable_error,
)
from kitelogik.anchor.credentials import CredentialBroker
from kitelogik.anchor.models import ActionStatus, PendingAction
from kitelogik.anchor.queue import HITLQueue
from kitelogik.audit.store import AuditStore
from kitelogik.memory.models import TrustTier
from kitelogik.memory.store import MemoryStore
from kitelogik.observability.tracer import get_tracer
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import GovernanceEvent, PolicyDecision, SessionContext, ToolCallInput

logger = logging.getLogger(__name__)

# Memory tools are handled locally — they don't route through MCP
_MEMORY_TOOLS = {"query_memory", "write_memory"}

# Seconds the session will wait for a human decision on an escalated
# (HITL-required) action before timing out. Five minutes balances "slow
# enough for a human reviewer to respond" against "fast enough that an
# abandoned session doesn't tie up resources indefinitely". Override per
# call via ``AgentSession(hitl_timeout=...)``.
DEFAULT_HITL_TIMEOUT_SECONDS = 300.0

DEFAULT_SYSTEM_PROMPT = (
    "You are an AI agent operating inside the Kite Logik governance platform. "
    "Your role is to attempt the action the user requests using the available tools. "
    "Do not pre-judge whether an action will be allowed — always call the relevant tool "
    "and let the policy enforcement layer decide. "
    "If a tool call is blocked or requires approval, relay that outcome to the user clearly."
)


def default_memory_write_policy(context: SessionContext, key: str, value: str) -> TrustTier:
    """Default rule for classifying agent-written memory.

    Parameters
    ----------
    context : SessionContext
        Session context — ``delegation_depth`` drives the decision.
    key : str
        Memory key (unused by the default policy; available for overrides).
    value : str
        Memory value (unused by the default policy; available for overrides).

    Returns
    -------
    TrustTier
        :attr:`TrustTier.DELEGATED` for worker agents
        (``delegation_depth > 0``); :attr:`TrustTier.EXTERNAL` for the
        primary session.

    Notes
    -----
    Both tiers are sanitised on ingestion — see
    :meth:`~kitelogik.memory.store.MemoryStore.write`. Override via the
    ``memory_write_policy`` keyword on :class:`AgentSession` when your
    domain needs a different assignment (e.g. treating any
    tool-output-derived write as :attr:`TrustTier.UNTRUSTED`).
    """
    return TrustTier.DELEGATED if context.delegation_depth > 0 else TrustTier.EXTERNAL


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
    model : str or None, optional
            LLM model identifier. When ``None``, falls back to
            ``llm_client.default_model`` (``claude-sonnet-4-6`` for the
            default ``AnthropicLLMClient``).
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
            Tool schemas surfaced to the LLM. Defaults to ``[]`` — the session
            has no tools available unless the caller supplies them or a
            framework adapter registers them. (Earlier releases defaulted to
            an internal demo-tool set; this has been removed.)
    tool_handler : callable or None, optional
            Sync or async function ``(name: str, args: dict) -> str`` for
            dispatching tool calls. When absent, tool calls that aren't memory
            tools surface a ``{"error": ...}`` result to the LLM.
    system_prompt : str or None, optional
            Override the default governance-aware system prompt. Pass ``None``
            (the default) to use :data:`DEFAULT_SYSTEM_PROMPT`; pass a string to
            replace it entirely. Use ``DEFAULT_SYSTEM_PROMPT + "..."`` to append.
    retry_config : ``RetryConfig`` or None, optional
            Exponential-backoff retry policy for LLM provider calls. Defaults
            to 2 retries with 0.5s → 1.0s backoff. Only 429 and 5xx (or
            unclassified) errors are retried; 4xx client errors fail fast.
    fallback_llm_client : ``LLMClient`` or None, optional
            Alternative provider to try once the retry budget is exhausted.
            If the fallback also fails, its error is raised (wrapped in
            :class:`LLMProviderError`). Common use: Claude → Bedrock Claude.
    memory_write_policy : callable or None, optional
            ``(context, key, value) -> TrustTier`` — classifier for agent-
            written memory. Defaults to :func:`default_memory_write_policy`
            (DELEGATED for worker agents, EXTERNAL for primary sessions).
    """

    def __init__(
        self,
        gate: PolicyGate,
        context: SessionContext,
        model: str | None = None,
        hitl_queue: HITLQueue | None = None,
        hitl_timeout: float = DEFAULT_HITL_TIMEOUT_SECONDS,
        credential_broker: CredentialBroker | None = None,
        memory_store: MemoryStore | None = None,
        audit_store: AuditStore | None = None,
        llm_client: LLMClient | None = None,
        tools: list[dict] | None = None,
        tool_handler: Callable[[str, dict], Any] | None = None,
        system_prompt: str | None = None,
        retry_config: RetryConfig | None = None,
        fallback_llm_client: LLMClient | None = None,
        memory_write_policy: Callable[[SessionContext, str, str], TrustTier] | None = None,
    ) -> None:
        if gate is None:
            raise ValueError("AgentSession requires a PolicyGate")
        self.gate = gate
        self.context = context
        self._llm = llm_client or AnthropicLLMClient()
        if model is None:
            model = getattr(self._llm, "default_model", None)
            if not model:
                raise ValueError(
                    "AgentSession(model=...) was not provided and the LLM client "
                    "does not expose a `default_model`. Pass model= explicitly."
                )
        self.model = model
        self.hitl_queue = hitl_queue
        self.hitl_timeout = hitl_timeout
        self.credential_broker = credential_broker
        self.memory_store = memory_store
        self.audit_store = audit_store
        self.system_prompt = system_prompt or DEFAULT_SYSTEM_PROMPT
        self.retry_config = retry_config or RetryConfig()
        self._fallback_llm = fallback_llm_client
        self._memory_write_policy = memory_write_policy or default_memory_write_policy
        self._has_run = False
        self._approved_plan: list[dict] | None = None
        self._tracer = get_tracer("kitelogik.agent")
        # No default tools — callers must pass ``tools=[...]`` explicitly (or
        # leave empty and register tools through an adapter / ``tool_handler``).
        # Earlier releases defaulted to a private demo-tool set; that leaked
        # mock data (e.g. fake customer records) into the public API surface
        # and has been removed intentionally.
        self._tools: list[dict] = list(tools) if tools is not None else []
        self._tool_handler = tool_handler

    async def submit_plan(
        self,
        steps: list[dict],
        on_event: Callable[[dict], None] | None = None,
    ) -> PolicyDecision:
        """Submit a proposed plan for governance evaluation before execution.

        Parameters
        ----------
        steps : list[dict]
            Proposed plan steps, each shaped ``{"tool_name": str, "args":
            dict, ...}``. Additional keys are passed through to the Rego
            policy unchanged.
        on_event : callable or None, optional
            Event callback; receives a ``{"type": "plan_decision", ...}``
            event with the full decision.

        Returns
        -------
        PolicyDecision
            The gate's ruling on the plan. **Does not raise** on deny —
            callers decide whether to abort or re-plan.

        Notes
        -----
        The approved plan (``allow=True``, ``deny=False`` and
        ``requires_hitl=False``) is cached on ``self._approved_plan`` so
        subsequent tool-call evaluation can cross-check against it. A plan
        that policy allows but routes to HITL is not approved.

        Examples
        --------
        >>> plan = [{"tool_name": "read_customer", "args": {"id": "c1"}}]
        >>> decision = await session.submit_plan(plan)
        >>> if decision.allow and not decision.requires_hitl:
        ...     await session.run_async("execute the plan")
        """
        event = GovernanceEvent(
            event_type="agent.plan",
            session_id=self.context.session_id,
            action="agent.plan",
            context=self.context,
            steps=steps,
        )
        decision = await self.gate.evaluate(event)
        if on_event:
            on_event(
                {
                    "type": "plan_decision",
                    "steps": steps,
                    "decision": decision.model_dump(mode="json"),
                }
            )
        if decision.allow and not decision.deny and not decision.requires_hitl:
            self._approved_plan = steps
        return decision

    def run_sync(
        self,
        prompt: str,
        max_iterations: int = 10,
        on_event: Callable[[dict], None] | None = None,
    ) -> SessionResult:
        """Synchronous wrapper around :meth:`run_async`.

        Parameters
        ----------
        prompt : str
            The user prompt to execute.
        max_iterations : int, optional
            Maximum LLM turns (default 10).
        on_event : callable or None, optional
            Event callback forwarded to :meth:`run_async`.

        Returns
        -------
        SessionResult
            Final response text, tool-call records, and blocked/HITL lists.

        Raises
        ------
        RuntimeError
            If called from within an already-running event loop. Prefer
            :meth:`run_async` in that case.

        Examples
        --------
        >>> session = AgentSession(gate=gate, context=ctx)
        >>> result = session.run_sync("hello")
        >>> print(result.final_response)
        """
        return asyncio.run(self.run_async(prompt, max_iterations=max_iterations, on_event=on_event))

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

        ``AgentSession`` is single-use: a second call to ``run_async`` raises
        :class:`SessionAlreadyRanError`. Construct a new session for a new run.

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
        if self._has_run:
            raise SessionAlreadyRanError(
                "AgentSession instances are single-use. Construct a new session for each run."
            )
        self._has_run = True

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
            # requires_hitl blocks even when policy also allows: spawn has no
            # human-approval flow, so an escalated spawn fails closed.
            if spawn_decision.deny or not spawn_decision.allow or spawn_decision.requires_hitl:
                reason = spawn_decision.reason
                if spawn_decision.requires_hitl and not spawn_decision.deny:
                    reason = f"requires human approval (risk tier: {spawn_decision.risk_tier})"
                if on_event:
                    on_event(
                        {
                            "type": "agent_spawn_denied",
                            "session_id": self.context.session_id,
                            "reason": reason,
                        }
                    )
                from kitelogik.governed import GovernanceError

                raise GovernanceError(
                    f"Agent spawn denied: {reason}",
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
                # Revoke any token tied to this session_id — covers both the
                # locally-issued case and the delegated case (where the child
                # token was issued by a parent via broker.delegate but is owned
                # by *this* session for its lifetime). revoke_session is
                # idempotent; calling it after revoke(token.token_id) is safe.
                if self.credential_broker:
                    if token:
                        self.credential_broker.revoke(token.token_id)
                    revoked_count = self.credential_broker.revoke_session(self.context.session_id)
                    if on_event and (token or revoked_count):
                        on_event(
                            {
                                "type": "credential_revoked",
                                "session_id": self.context.session_id,
                                "token_id": token.token_id if token else self.context.token_id,
                            }
                        )

            return result

    async def _run_loop(
        self,
        prompt: str,
        max_iterations: int,
        on_event: Callable[[dict], None] | None,
    ) -> SessionResult:

        result = SessionResult(session_id=self.context.session_id, final_response="")
        messages: list[dict] = [{"role": "user", "content": prompt}]

        for iteration_idx in range(max_iterations):
            # Per-call span: one span per LLM invocation, attributes follow
            # GenAI semconv v1.37 (gen_ai.request.model, gen_ai.usage.*).
            with self._tracer.start_as_current_span("gen_ai.chat") as call_span:
                call_span.set_attribute("gen_ai.system", type(self._llm).__name__)
                call_span.set_attribute("gen_ai.request.model", self.model)
                call_span.set_attribute("kitelogik.iteration", iteration_idx)
                response = await self._call_with_retry(messages, on_event)

                if response.input_tokens is not None:
                    call_span.set_attribute("gen_ai.usage.input_tokens", response.input_tokens)
                if response.output_tokens is not None:
                    call_span.set_attribute("gen_ai.usage.output_tokens", response.output_tokens)
                call_span.set_attribute("gen_ai.response.finish_reason", response.stop_reason)

            budget_decision = await self._check_budget(response, on_event)
            if budget_decision is not None and budget_decision.deny:
                if on_event:
                    on_event(
                        {
                            "type": "budget_exhausted",
                            "reason": budget_decision.reason,
                            "decision": budget_decision.model_dump(mode="json"),
                        }
                    )
                result.final_response = (
                    response.text_content or f"Session halted: {budget_decision.reason}"
                )
                return result

            if response.stop_reason == "end_turn":
                if response.text_content:
                    result.final_response = response.text_content
                break

            if response.stop_reason == "tool_use":
                messages.append(self._llm.format_assistant_message(response.raw_content))
                pairs: list[tuple[str, str]] = []

                for tc in response.tool_calls:
                    call_record = {"tool": tc.name, "args": tc.input}
                    tool_content = await self._dispatch_direct(tc, call_record, result, on_event)
                    pairs.append((tc.id, tool_content))

                messages.extend(self._llm.build_tool_result_messages(pairs))

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

    async def _call_with_retry(
        self,
        messages: list[dict],
        on_event: Callable[[dict], None] | None,
    ) -> LLMResponse:
        """Call the LLM with exponential-backoff retries, then fall back.

        Parameters
        ----------
        messages : list[dict]
            Current conversation history to pass to ``create_message``.
        on_event : callable or None
            Event callback; receives ``llm_retry`` events between retries
            and an ``llm_fallback`` event when the fallback client takes over.

        Returns
        -------
        LLMResponse
            The successful response from the primary or fallback client.

        Raises
        ------
        LLMProviderError
            When all retries and the fallback attempt have failed. The final
            underlying exception is available on ``.original`` and
            ``__cause__``.

        Notes
        -----
        Retryable failures (429, 5xx, unclassified) are retried up to
        ``retry_config.max_retries`` times with jittered exponential backoff
        (see :class:`~kitelogik.agents.llm.RetryConfig`). Non-retryable
        failures (4xx) fail fast without retries. Fallback is attempted
        exactly once after the retry budget is exhausted.
        """

        async def _one_attempt(client: LLMClient) -> LLMResponse:
            return await client.create_message(
                model=self.model,
                max_tokens=DEFAULT_MAX_TOKENS,
                tools=self._tools,  # type: ignore[arg-type]
                system=self.system_prompt,
                messages=messages,
            )

        last_exc: Exception | None = None
        for attempt in range(self.retry_config.max_retries + 1):
            try:
                return await _one_attempt(self._llm)
            except AgentSessionError:
                raise
            except Exception as e:
                last_exc = e
                if not is_retryable_error(e):
                    break
                if attempt == self.retry_config.max_retries:
                    break
                delay = min(
                    self.retry_config.initial_delay * (self.retry_config.backoff_factor**attempt)
                    + random.uniform(0, 0.1),
                    self.retry_config.max_delay,
                )
                if on_event:
                    on_event(
                        {
                            "type": "llm_retry",
                            "attempt": attempt + 1,
                            "delay_s": delay,
                            "error": f"{type(e).__name__}: {e}",
                        }
                    )
                await asyncio.sleep(delay)

        if self._fallback_llm is not None:
            if on_event:
                on_event({"type": "llm_fallback", "to": type(self._fallback_llm).__name__})
            try:
                return await _one_attempt(self._fallback_llm)
            except AgentSessionError:
                raise
            except Exception as e:
                last_exc = e

        assert last_exc is not None
        raise LLMProviderError(
            f"LLM provider call failed after retries: {type(last_exc).__name__}: {last_exc}",
            original=last_exc,
        ) from last_exc

    async def _check_budget(
        self,
        response: LLMResponse,
        on_event: Callable[[dict], None] | None,
    ) -> PolicyDecision | None:
        """Update budget counters and fire an ``agent.budget`` event.

        Parameters
        ----------
        response : LLMResponse
            The response just returned from the LLM — used to tally
            ``input_tokens`` and ``output_tokens``.
        on_event : callable or None
            Event callback; receives a ``budget_check`` event on every
            non-null evaluation.

        Returns
        -------
        PolicyDecision or None
            ``None`` when no budget is configured — short-circuits to avoid
            a gate round-trip per turn. Otherwise the gate's :class:`PolicyDecision`
            for the ``agent.budget`` event, so the caller can halt the loop
            on ``deny``.

        Notes
        -----
        Mutates ``self.context`` via ``model_copy`` to advance the
        ``budget_used_tokens`` / ``budget_used_api_calls`` counters. Safe
        because :class:`AgentSession` is single-use (see
        :class:`~kitelogik.agents.errors.SessionAlreadyRanError`).
        """
        ctx = self.context
        if (
            ctx.budget_total_tokens is None
            and ctx.budget_total_api_calls is None
            and ctx.budget_total_cost_cents is None
        ):
            return None

        used_tokens = (ctx.budget_used_tokens or 0) + (
            (response.input_tokens or 0) + (response.output_tokens or 0)
        )
        used_api_calls = (ctx.budget_used_api_calls or 0) + 1
        self.context = ctx.model_copy(
            update={
                "budget_used_tokens": used_tokens
                if ctx.budget_total_tokens is not None
                else ctx.budget_used_tokens,
                "budget_used_api_calls": used_api_calls
                if ctx.budget_total_api_calls is not None
                else ctx.budget_used_api_calls,
            }
        )

        event = GovernanceEvent(
            event_type="agent.budget",
            session_id=self.context.session_id,
            action="agent.budget",
            context=self.context,
        )
        decision = await self.gate.evaluate(event)
        if on_event:
            on_event(
                {
                    "type": "budget_check",
                    "used_tokens": used_tokens,
                    "used_api_calls": used_api_calls,
                    "decision": decision.model_dump(mode="json"),
                }
            )
        return decision

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
            try:
                handler_result = self._tool_handler(tool_name, args)
                if inspect.isawaitable(handler_result):
                    raw_output = await handler_result
                else:
                    raw_output = handler_result
                raw_output = str(raw_output)
            except AgentSessionError:
                raise
            except Exception as e:
                raise ToolHandlerError(
                    tool_name,
                    f"{type(e).__name__}: {e}",
                    original=e,
                ) from e
        else:
            # No tool_handler configured — surface this cleanly to the LLM as
            # a tool-result error rather than crashing the session. Users wire
            # real tools by passing ``tool_handler=`` or using a framework
            # adapter (e.g. OpenAIAdapter.register()).
            raw_output = json.dumps(
                {
                    "error": (
                        f"No handler registered for tool '{tool_name}'. "
                        "Pass `tool_handler=` to AgentSession or register the "
                        "tool through a framework adapter."
                    )
                }
            )
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
            assert self.memory_store is not None
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
            trust_tier = self._memory_write_policy(self.context, key, value)
            assert self.memory_store is not None
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
