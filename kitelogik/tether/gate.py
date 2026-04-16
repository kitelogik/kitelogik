# SPDX-License-Identifier: Apache-2.0
import logging
import time
from typing import TYPE_CHECKING

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from .models import (
    GovernanceEvent,
    PolicyDecision,
    PolicyEvaluator,
    PolicyInput,
    RiskTier,
    SanitizedResponse,
    SessionContext,
    ToolCallInput,
)
from .opa_client import OPAConnectionError
from .sanitizer import sanitize_tool_output

if TYPE_CHECKING:
    from kitelogik.anchor.credentials import CredentialBroker

logger = logging.getLogger(__name__)

_INVALID_TOKEN_DECISION = PolicyDecision(
    allow=False,
    deny=True,
    risk_tier=RiskTier.SECURITY_CRITICAL,
    requires_hitl=False,
    reason="Invalid or expired session token — access denied",
    rule_matched="credential_validation",
)


class PolicyGate:
    """The Tether — the core enforcement layer of Kite Logik.

    Intercepts every tool call before execution and every tool response
    before it reaches the agent context. Applies three stages in sequence:

    1. Credential validation — token must be valid and non-revoked
    2. Schema validation — ``PolicyInput`` construction (Pydantic)
    3. Policy evaluation — deterministic business rule enforcement

    Each stage emits a child OTel span with ``kitelogik.duration_ms`` so
    the 5-10 ms per-call latency budget can be tracked per stage.
    Response sanitisation is a separate call via ``sanitize_response``.

    Parameters
    ----------
    opa_client : PolicyEvaluator
            Backend that evaluates Rego policies (``OPAClient``,
            ``RegorusClient``, or ``HierarchicalEvaluator``).
    tracer : opentelemetry.trace.Tracer or None
            OTel tracer instance. Falls back to ``kitelogik.tether``.
    credential_broker : CredentialBroker or None
            If provided, token validation runs before policy evaluation.
    """

    def __init__(
        self,
        opa_client: PolicyEvaluator,
        tracer: trace.Tracer | None = None,
        credential_broker: "CredentialBroker | None" = None,
    ) -> None:
        self.opa = opa_client
        self.tracer = tracer or trace.get_tracer("kitelogik.tether")
        self._broker = credential_broker

    async def evaluate_tool_call(
        self,
        tool_call: ToolCallInput,
        context: SessionContext,
    ) -> PolicyDecision:
        """Evaluate a tool call against business rules and security policies.

        Parameters
        ----------
        tool_call : ToolCallInput
                The tool invocation to evaluate.
        context : SessionContext
                Session metadata (role, scopes, token).

        Returns
        -------
        PolicyDecision
                The allow/deny decision. Callers must check ``decision.allow``
                and ``decision.deny`` before proceeding with execution.
        """
        with self.tracer.start_as_current_span("policy_gate.evaluate") as span:
            span.set_attribute("kitelogik.action", tool_call.action)
            span.set_attribute("kitelogik.tool_name", tool_call.tool_name)
            span.set_attribute("kitelogik.session_id", context.session_id)
            span.set_attribute("kitelogik.user_role", context.user_role)

            # Step 1: validate session credential before calling OPA
            if self._broker and context.token_id:
                token = self._broker.validate(context.token_id)
                if token is None:
                    span.set_attribute("kitelogik.policy.allow", False)
                    span.set_attribute("kitelogik.policy.deny", True)
                    span.set_attribute(
                        "kitelogik.policy.risk_tier", RiskTier.SECURITY_CRITICAL.value
                    )
                    span.set_attribute("kitelogik.policy.requires_hitl", False)
                    span.set_attribute("kitelogik.policy.reason", _INVALID_TOKEN_DECISION.reason)
                    span.set_status(Status(StatusCode.ERROR, "Invalid session token"))
                    logger.warning(
                        "Tool call rejected: invalid session token",
                        extra={"token_id": context.token_id, "session_id": context.session_id},
                    )
                    return _INVALID_TOKEN_DECISION

            with self.tracer.start_as_current_span("policy_gate.schema_validate") as val_span:
                _t0 = time.perf_counter()
                policy_input = PolicyInput(
                    action=tool_call.action,
                    tool_name=tool_call.tool_name,
                    args=tool_call.args,
                    resource_path=tool_call.resource_path,
                    context=context,
                )
                val_span.set_attribute(
                    "kitelogik.duration_ms", round((time.perf_counter() - _t0) * 1000, 3)
                )

            with self.tracer.start_as_current_span("policy_gate.opa_evaluate") as opa_span:
                _t0 = time.perf_counter()
                try:
                    decision = await self.opa.evaluate(policy_input)
                except OPAConnectionError as e:
                    opa_span.set_attribute(
                        "kitelogik.duration_ms", round((time.perf_counter() - _t0) * 1000, 3)
                    )
                    opa_span.set_status(Status(StatusCode.ERROR, "OPA unreachable"))
                    logger.critical(
                        "OPA unreachable — failing closed with deny-all decision. session=%s error=%s",  # noqa: E501
                        context.session_id,
                        e,
                    )
                    span.set_status(Status(StatusCode.ERROR, "OPA unreachable — denied"))
                    return PolicyDecision(
                        allow=False,
                        deny=True,
                        risk_tier=RiskTier.SECURITY_CRITICAL,
                        requires_hitl=False,
                        reason="OPA policy engine unreachable — all tool calls denied until connection is restored",  # noqa: E501
                        rule_matched="opa_connection_failure",
                    )
                opa_span.set_attribute(
                    "kitelogik.duration_ms", round((time.perf_counter() - _t0) * 1000, 3)
                )

            span.set_attribute("kitelogik.policy.allow", decision.allow)
            span.set_attribute("kitelogik.policy.deny", decision.deny)
            span.set_attribute("kitelogik.policy.risk_tier", decision.risk_tier.value)
            span.set_attribute("kitelogik.policy.requires_hitl", decision.requires_hitl)
            span.set_attribute("kitelogik.policy.reason", decision.reason)

            if decision.deny:
                span.set_status(Status(StatusCode.ERROR, "Hard blocked by security policy"))
                logger.warning(
                    "Tool call hard blocked by security policy",
                    extra={
                        "action": tool_call.action,
                        "session_id": context.session_id,
                        "risk_tier": decision.risk_tier,
                    },
                )
            elif not decision.allow:
                span.set_status(Status(StatusCode.ERROR, "Tool call denied by policy"))
                logger.info(
                    "Tool call denied by policy",
                    extra={
                        "action": tool_call.action,
                        "session_id": context.session_id,
                        "risk_tier": decision.risk_tier,
                        "requires_hitl": decision.requires_hitl,
                    },
                )
            else:
                logger.debug(
                    "Tool call allowed",
                    extra={"action": tool_call.action, "risk_tier": decision.risk_tier},
                )

            return decision

    async def evaluate(self, event: GovernanceEvent) -> PolicyDecision:
        """Evaluate a governance event against business rules and security policies.

        Supports all event types: ``tool_call``, ``agent.spawn``,
        ``agent.delegate``, ``agent.plan``, ``agent.budget``. Same 3-stage
        pipeline as ``evaluate_tool_call``.

        Parameters
        ----------
        event : GovernanceEvent
                The governance event to evaluate.

        Returns
        -------
        PolicyDecision
                The allow/deny decision with risk tier and reason.
        """
        with self.tracer.start_as_current_span("policy_gate.evaluate_event") as span:
            span.set_attribute("kitelogik.event_type", event.event_type)
            span.set_attribute("kitelogik.action", event.action)
            span.set_attribute("kitelogik.session_id", event.session_id)
            span.set_attribute("kitelogik.user_role", event.context.user_role)

            # Step 1: validate session credential
            if self._broker and event.context.token_id:
                token = self._broker.validate(event.context.token_id)
                if token is None:
                    span.set_attribute("kitelogik.policy.allow", False)
                    span.set_attribute("kitelogik.policy.deny", True)
                    span.set_status(Status(StatusCode.ERROR, "Invalid session token"))
                    logger.warning(
                        "Governance event rejected: invalid session token",
                        extra={
                            "token_id": event.context.token_id,
                            "session_id": event.session_id,
                            "event_type": event.event_type,
                        },
                    )
                    return _INVALID_TOKEN_DECISION

            # Step 2: schema validation (GovernanceEvent is already validated by Pydantic)

            # Step 3: OPA evaluation
            with self.tracer.start_as_current_span("policy_gate.opa_evaluate_event") as opa_span:
                _t0 = time.perf_counter()
                try:
                    decision = await self.opa.evaluate_event(event)
                except OPAConnectionError as e:
                    opa_span.set_attribute(
                        "kitelogik.duration_ms", round((time.perf_counter() - _t0) * 1000, 3)
                    )
                    opa_span.set_status(Status(StatusCode.ERROR, "OPA unreachable"))
                    logger.critical(
                        "OPA unreachable — failing closed with deny-all. session=%s error=%s",
                        event.session_id,
                        e,
                    )
                    span.set_status(Status(StatusCode.ERROR, "OPA unreachable — denied"))
                    return PolicyDecision(
                        allow=False,
                        deny=True,
                        risk_tier=RiskTier.SECURITY_CRITICAL,
                        requires_hitl=False,
                        reason=(
                            "OPA policy engine unreachable — "
                            "all actions denied until connection is restored"
                        ),
                        rule_matched="opa_connection_failure",
                    )
                opa_span.set_attribute(
                    "kitelogik.duration_ms", round((time.perf_counter() - _t0) * 1000, 3)
                )

            span.set_attribute("kitelogik.policy.allow", decision.allow)
            span.set_attribute("kitelogik.policy.deny", decision.deny)
            span.set_attribute("kitelogik.policy.risk_tier", decision.risk_tier.value)
            span.set_attribute("kitelogik.policy.requires_hitl", decision.requires_hitl)
            span.set_attribute("kitelogik.policy.reason", decision.reason)

            if decision.deny:
                span.set_status(Status(StatusCode.ERROR, "Governance event hard blocked"))
                logger.warning(
                    "Governance event hard blocked",
                    extra={
                        "event_type": event.event_type,
                        "action": event.action,
                        "session_id": event.session_id,
                    },
                )
            elif not decision.allow:
                span.set_status(Status(StatusCode.ERROR, "Governance event denied"))
                logger.info(
                    "Governance event denied by policy",
                    extra={
                        "event_type": event.event_type,
                        "action": event.action,
                        "session_id": event.session_id,
                        "requires_hitl": decision.requires_hitl,
                    },
                )
            else:
                logger.debug(
                    "Governance event allowed",
                    extra={"event_type": event.event_type, "action": event.action},
                )

            return decision

    async def evaluate_plan(
        self,
        steps: list[dict],
        context: SessionContext,
    ) -> PolicyDecision:
        """Evaluate a proposed plan (sequence of actions) before execution.

        Constructs a ``GovernanceEvent`` with ``event_type="agent.plan"``
        and sends it through the standard evaluation pipeline.

        Parameters
        ----------
        steps : list[dict]
                Proposed sequence of tool calls.
        context : SessionContext
                Session metadata for policy evaluation.

        Returns
        -------
        PolicyDecision
                The allow/deny decision for the plan as a whole.
        """
        event = GovernanceEvent(
            event_type="agent.plan",
            session_id=context.session_id,
            action="agent.plan",
            context=context,
            steps=steps,
        )
        return await self.evaluate(event)

    def sanitize_response(self, content: str) -> SanitizedResponse:
        """Sanitize a tool response before returning it to the agent context.

        Primary defence against indirect prompt injection via MCP server
        responses, database records, or external data sources.

        Parameters
        ----------
        content : str
                Raw tool output to scan and sanitize.

        Returns
        -------
        SanitizedResponse
                Sanitized content with modification flag and patterns found.
        """
        with self.tracer.start_as_current_span("policy_gate.sanitize_response") as span:
            _t0 = time.perf_counter()
            result = sanitize_tool_output(content)
            span.set_attribute(
                "kitelogik.duration_ms", round((time.perf_counter() - _t0) * 1000, 3)
            )
            span.set_attribute("kitelogik.sanitizer.was_modified", result.was_modified)
            span.set_attribute(
                "kitelogik.sanitizer.patterns_found",
                ",".join(result.injection_patterns_found),
            )
            if result.was_modified:
                logger.warning(
                    "Injection patterns redacted from tool response",
                    extra={"patterns": result.injection_patterns_found},
                )
            return result
