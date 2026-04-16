# SPDX-License-Identifier: Apache-2.0
"""
Property-based fuzz tests for PolicyInput and related Pydantic models.

Invariants:
- Valid inputs construct without error and round-trip through serialization.
- Invalid inputs raise ValidationError — never crash or return partial objects.
- GovernanceEvent serialization round-trips correctly.
"""

from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from kitelogik.tether.models import (
    GovernanceEvent,
    PolicyDecision,
    PolicyInput,
    RiskTier,
    SessionContext,
    ToolCallInput,
    result_to_decision,
)

# ── Strategies ──────────────────────────────────────────────────────────────

_safe_text = st.text(min_size=1, max_size=200)
_scope_list = st.lists(st.text(min_size=1, max_size=50), min_size=0, max_size=10)
_args_dict = st.dictionaries(
    keys=st.text(min_size=1, max_size=50),
    values=st.one_of(
        st.text(max_size=100), st.integers(), st.floats(allow_nan=False), st.booleans()
    ),
    max_size=10,
)

_session_context = st.builds(
    SessionContext,
    session_id=_safe_text,
    user_role=_safe_text,
    session_scopes=_scope_list,
    delegation_depth=st.integers(min_value=0, max_value=100),
)

_risk_tier = st.sampled_from(list(RiskTier))


@given(
    action=_safe_text,
    tool_name=_safe_text,
    args=_args_dict,
    context=_session_context,
)
@settings(max_examples=300)
def test_policy_input_roundtrip(
    action: str, tool_name: str, args: dict, context: SessionContext
) -> None:
    """PolicyInput must serialize and deserialize without data loss."""
    pi = PolicyInput(action=action, tool_name=tool_name, args=args, context=context)
    data = pi.model_dump()
    restored = PolicyInput(**data)
    assert restored.action == pi.action
    assert restored.tool_name == pi.tool_name
    assert restored.context.session_id == pi.context.session_id


@given(
    action=_safe_text,
    tool_name=_safe_text,
    args=_args_dict,
)
@settings(max_examples=200)
def test_tool_call_input_roundtrip(action: str, tool_name: str, args: dict) -> None:
    """ToolCallInput must serialize and deserialize without data loss."""
    tc = ToolCallInput(action=action, tool_name=tool_name, args=args)
    data = tc.model_dump()
    restored = ToolCallInput(**data)
    assert restored.action == tc.action


@given(
    event_type=st.sampled_from(
        ["tool_call", "agent.spawn", "agent.delegate", "agent.plan", "agent.budget"]
    ),
    context=_session_context,
    capabilities=_scope_list,
    steps=st.lists(
        st.fixed_dictionaries({"tool_name": _safe_text, "args": _args_dict}),
        max_size=5,
    ),
)
@settings(max_examples=300)
def test_governance_event_roundtrip(
    event_type: str,
    context: SessionContext,
    capabilities: list[str],
    steps: list[dict],
) -> None:
    """GovernanceEvent must serialize and deserialize without data loss."""
    event = GovernanceEvent(
        event_type=event_type,
        session_id=context.session_id,
        action=event_type,
        context=context,
        requested_capabilities=capabilities,
        steps=steps,
    )
    data = event.model_dump()
    restored = GovernanceEvent(**data)
    assert restored.event_type == event.event_type
    assert len(restored.steps) == len(event.steps)


@given(
    allow=st.booleans(),
    deny=st.booleans(),
    risk_tier=_risk_tier,
    requires_hitl=st.booleans(),
)
@settings(max_examples=200)
def test_result_to_decision_never_crashes(
    allow: bool, deny: bool, risk_tier: RiskTier, requires_hitl: bool
) -> None:
    """result_to_decision must produce a valid PolicyDecision for any input combo."""
    result = {
        "allow": allow,
        "deny": deny,
        "risk_tier": risk_tier.value,
        "requires_hitl": requires_hitl,
    }
    decision = result_to_decision(result)
    assert isinstance(decision, PolicyDecision)
    assert decision.allow == allow
    assert decision.deny == deny


@given(data=st.dictionaries(keys=_safe_text, values=st.text(max_size=50), max_size=5))
@settings(max_examples=200)
def test_result_to_decision_handles_arbitrary_dicts(data: dict) -> None:
    """result_to_decision must not crash on arbitrary dict inputs."""
    try:
        decision = result_to_decision(data)
        assert isinstance(decision, PolicyDecision)
    except (ValueError, KeyError):
        pass  # Invalid risk_tier values may raise — that's acceptable


@given(
    raw=st.dictionaries(
        keys=st.text(min_size=0, max_size=50),
        values=st.one_of(st.text(max_size=100), st.integers(), st.none()),
        max_size=20,
    )
)
@settings(max_examples=200)
def test_policy_input_rejects_invalid_shapes(raw: dict) -> None:
    """Arbitrary dicts must either validate or raise ValidationError — never crash."""
    try:
        PolicyInput(**raw)
    except (ValidationError, TypeError):
        pass  # Expected for invalid shapes
