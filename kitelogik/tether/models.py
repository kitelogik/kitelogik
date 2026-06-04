# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from enum import StrEnum
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field


class RiskTier(StrEnum):
    """Risk classification for governance events.

    Tiers are ordered by severity. Policies use the tier to drive routing:
    ``INFORMATIONAL`` / ``OPERATIONAL`` / ``TRANSACTIONAL_LOW`` are typically
    allowed with audit; ``TRANSACTIONAL_HIGH`` often requires HITL; and
    ``DESTRUCTIVE`` / ``SECURITY_CRITICAL`` are usually hard-denied.
    """

    OPERATIONAL = "OPERATIONAL"
    INFORMATIONAL = "INFORMATIONAL"
    TRANSACTIONAL_LOW = "TRANSACTIONAL_LOW"
    TRANSACTIONAL_HIGH = "TRANSACTIONAL_HIGH"
    DESTRUCTIVE = "DESTRUCTIVE"
    SECURITY_CRITICAL = "SECURITY_CRITICAL"


class SessionContext(BaseModel):
    """Per-session identity, scope, and budget envelope passed to every gate call.

    Created once at session start and shared across all governance events for
    that session. The policy gate reads every field from this model — role
    and scopes drive authorization, ``delegation_depth`` caps child-agent
    nesting, and the ``budget_*`` fields gate ``agent.budget`` events. Treat
    as immutable during a session; use ``model_copy(update=...)`` when
    attaching a delegated token.
    """

    session_id: str
    user_role: str
    session_scopes: list[str]
    sandbox_verified: bool = False
    token_id: str = ""  # Set after CredentialBroker issues a session token
    delegation_depth: int = 0
    parent_token_id: str = ""
    parent_session_id: str = ""  # Orchestrator session ID; set when delegation_depth > 0
    tenant_id: str | None = None  # Multi-tenant isolation identifier
    # Budget enforcement — all None means no budget tracking
    budget_total_tokens: int | None = None
    budget_used_tokens: int | None = None
    budget_total_api_calls: int | None = None
    budget_used_api_calls: int | None = None
    budget_total_cost_cents: int | None = None
    budget_used_cost_cents: int | None = None


class ToolCallInput(BaseModel):
    """A single tool invocation submitted to the policy gate for evaluation.

    ``action`` is the policy-layer name (often the same as ``tool_name``, but
    may be overridden when a function's Python name differs from the tool name
    registered in Rego policies). ``resource_path`` is used by file/URL
    policies — leave ``None`` for tools that do not touch a filesystem or URL.
    """

    action: str
    tool_name: str
    args: dict
    resource_path: str | None = None


class PolicyInput(BaseModel):
    """Structured input sent to the policy engine for evaluation."""

    action: str
    tool_name: str
    args: dict
    resource_path: str | None = None
    context: SessionContext


class GovernanceEvent(BaseModel):
    """A governance event sent to the policy engine for evaluation.

    Covers all event types: ``tool_call``, ``agent.spawn``,
    ``agent.delegate``, ``agent.plan``, and ``agent.budget``.
    """

    event_type: Literal["tool_call", "agent.spawn", "agent.delegate", "agent.plan", "agent.budget"]
    session_id: str
    action: str
    tool_name: str | None = None
    args: dict = Field(default_factory=dict)
    resource_path: str | None = None
    context: SessionContext
    # agent.spawn / agent.delegate
    requested_capabilities: list[str] = Field(default_factory=list)
    delegation_target: str | None = None
    # agent.plan
    steps: list[dict] = Field(default_factory=list)
    # data classification
    data_classification: str | None = None


class ResolutionStep(BaseModel):
    """A single step in the policy resolution trace."""

    tier: str  # "global" or "project"
    allow: bool
    deny: bool
    risk_tier: str
    reason: str
    rule_matched: str | None = None


class PolicyDecision(BaseModel):
    """The outcome of a single policy evaluation.

    Three flags encode the decision axis:

    * ``allow=True, deny=False`` — proceed.
    * ``allow=False, deny=True`` — hard block; the model cannot override.
    * ``allow=False, deny=False, requires_hitl=True`` — pause for human review.
    * ``allow=False, deny=False, requires_hitl=False`` — soft-deny fallback.

    ``rule_matched`` identifies the specific Rego rule that fired and is what
    audit logs and traces anchor on. ``resolution_trace`` is populated only by
    ``HierarchicalEvaluator`` to record each tier's sub-decision.
    """

    allow: bool
    deny: bool
    risk_tier: RiskTier
    requires_hitl: bool
    reason: str
    rule_matched: str | None = None
    resolution_trace: list[ResolutionStep] = Field(default_factory=list)


class SanitizedResponse(BaseModel):
    """Sanitizer output — returned by ``PolicyGate.sanitize_response()``.

    ``was_modified`` is the cheap check callers use to decide whether the
    original content needs to be replaced. ``injection_patterns_found`` lists
    the pattern names matched during scanning so audit logs can attribute the
    redaction to a specific rule.
    """

    content: str
    was_modified: bool
    injection_patterns_found: list[str] = Field(default_factory=list)


def result_to_decision(result: dict) -> PolicyDecision:
    """Convert a policy engine result dict into a PolicyDecision.

    Shared by ``OPAClient`` (HTTP) and ``RegorusClient`` (in-process)
    to ensure identical decision parsing regardless of backend.

    Parameters
    ----------
    result : dict
            Raw result dict from OPA or regorus evaluation.

    Returns
    -------
    PolicyDecision
            Parsed decision with allow/deny, risk tier, and reason.
    """
    # OPA deny can be a boolean (from `deny if {}`) or a set of reason
    # strings (from `deny[msg] if {}`). OPA serialises Rego sets as
    # JSON objects like {"reason string": true}, and lists as arrays.
    # Normalise to a boolean + reason list for PolicyDecision.
    raw_deny = result.get("deny", False)
    is_denied = bool(raw_deny)

    # Reasons come from main.rego's `deny_reason` set when present; older or
    # hand-written rego may instead make `deny` itself set-valued. Accept both.
    raw_reasons = result.get("deny_reason", raw_deny)
    if isinstance(raw_reasons, dict):
        deny_reasons = list(raw_reasons.keys())
    elif isinstance(raw_reasons, list):
        deny_reasons = list(raw_reasons)
    else:
        deny_reasons = []

    if is_denied:
        reason = "; ".join(sorted(deny_reasons)) if deny_reasons else "Hard blocked by policy"
    elif result.get("allow"):
        reason = f"Allowed — risk tier: {result.get('risk_tier', 'OPERATIONAL')}"
    else:
        reason = f"Denied — risk tier: {result.get('risk_tier', 'OPERATIONAL')}"

    return PolicyDecision(
        allow=result.get("allow", False),
        deny=is_denied,
        risk_tier=RiskTier(result.get("risk_tier", RiskTier.OPERATIONAL.value)),
        requires_hitl=result.get("requires_hitl", False),
        reason=reason,
        rule_matched=result.get("rule_matched"),
    )


@runtime_checkable
class PolicyEvaluator(Protocol):
    """Protocol for policy evaluation backends.

    Both ``OPAClient`` (HTTP to OPA server) and ``RegorusClient``
    (in-process Rego) implement this interface. ``PolicyGate`` accepts
    any ``PolicyEvaluator``.
    """

    async def health(self) -> bool: ...

    async def evaluate(self, policy_input: PolicyInput) -> PolicyDecision: ...

    async def evaluate_event(self, event: GovernanceEvent) -> PolicyDecision: ...
