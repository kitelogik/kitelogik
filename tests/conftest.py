# SPDX-License-Identifier: Apache-2.0
from unittest.mock import AsyncMock, MagicMock

import pytest

from kitelogik.agents.llm import LLMResponse
from kitelogik.observability.tracer import setup_tracer
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import PolicyDecision, RiskTier, SessionContext
from kitelogik.tether.opa_client import OPAClient


@pytest.fixture(autouse=True, scope="session")
def setup_otel():
    setup_tracer("kitelogik-test", testing=True)


@pytest.fixture
def session_context() -> SessionContext:
    return SessionContext(
        session_id="test_session_001",
        user_role="support_agent",
        session_scopes=["read_customer", "approve_refund_under_100", "send_notifications"],
    )


@pytest.fixture
def allow_decision() -> PolicyDecision:
    return PolicyDecision(
        allow=True,
        deny=False,
        risk_tier=RiskTier.INFORMATIONAL,
        requires_hitl=False,
        reason="Allowed — risk tier: INFORMATIONAL",
    )


@pytest.fixture
def deny_decision() -> PolicyDecision:
    return PolicyDecision(
        allow=False,
        deny=True,
        risk_tier=RiskTier.SECURITY_CRITICAL,
        requires_hitl=False,
        reason="Hard blocked by security policy",
    )


@pytest.fixture
def hitl_decision() -> PolicyDecision:
    return PolicyDecision(
        allow=False,
        deny=False,
        risk_tier=RiskTier.TRANSACTIONAL_HIGH,
        requires_hitl=True,
        reason="Denied — risk tier: TRANSACTIONAL_HIGH",
    )


@pytest.fixture
def mock_opa_client(allow_decision: PolicyDecision) -> OPAClient:
    client = AsyncMock(spec=OPAClient)
    client.evaluate.return_value = allow_decision
    return client


@pytest.fixture
def policy_gate(mock_opa_client: OPAClient) -> PolicyGate:
    return PolicyGate(opa_client=mock_opa_client)


# ── AgentSession test helpers ───────────────────────────────────────────────


@pytest.fixture
def agent_gate() -> PolicyGate:
    """Allow-everything gate mock for AgentSession tests.

    Returns a ``PolicyGate`` MagicMock whose ``evaluate`` and
    ``evaluate_tool_call`` return an INFORMATIONAL allow decision, and
    whose ``sanitize_response`` passes content through unchanged.
    """
    allow = PolicyDecision(
        allow=True,
        deny=False,
        risk_tier=RiskTier.INFORMATIONAL,
        requires_hitl=False,
        reason="Allowed",
    )
    g = MagicMock(spec=PolicyGate)
    g.evaluate = AsyncMock(return_value=allow)
    g.evaluate_tool_call = AsyncMock(return_value=allow)
    g.sanitize_response = MagicMock(
        side_effect=lambda x: MagicMock(content=x, was_modified=False, injection_patterns_found=[])
    )
    return g


@pytest.fixture
def agent_ctx() -> SessionContext:
    """Minimal :class:`SessionContext` for AgentSession tests."""
    return SessionContext(
        session_id="test_sess",
        user_role="tester",
        session_scopes=["read"],
    )


def make_mock_llm(
    responses: list[LLMResponse] | None = None,
    *,
    default_model: str = "claude-sonnet-4-6",
    text: str = "done",
) -> MagicMock:
    """Build a MagicMock that satisfies the ``LLMClient`` protocol.

    Parameters
    ----------
    responses : list[LLMResponse] or None, optional
        Sequence of responses ``create_message`` returns. ``None`` produces
        a single ``end_turn`` response with ``text_content=text``.
    default_model : str, optional
        Value for the mock's ``default_model`` attribute.
    text : str, optional
        Text used when ``responses`` is ``None``.

    Returns
    -------
    MagicMock
        Mock with ``create_message`` (:class:`AsyncMock`),
        ``build_tool_result_messages``, ``format_assistant_message``, and
        ``default_model`` wired up.
    """
    if responses is None:
        responses = [LLMResponse(stop_reason="end_turn", text_content=text)]

    mock = MagicMock()
    mock.default_model = default_model
    mock.create_message = AsyncMock(side_effect=list(responses))
    mock.build_tool_result_messages = MagicMock(
        side_effect=lambda pairs: [
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": tid, "content": out}
                    for tid, out in pairs
                ],
            }
        ]
    )
    mock.format_assistant_message = MagicMock(return_value={"role": "assistant", "content": ""})
    return mock


def allow_decision_for(reason: str = "Allowed") -> PolicyDecision:
    """Standalone helper — build an allow decision with INFORMATIONAL risk."""
    return PolicyDecision(
        allow=True,
        deny=False,
        risk_tier=RiskTier.INFORMATIONAL,
        requires_hitl=False,
        reason=reason,
    )


def allowed_hitl_decision_for(
    risk_tier: RiskTier = RiskTier.TRANSACTIONAL_HIGH,
) -> PolicyDecision:
    """Standalone helper — an allowed decision that policy still routes to HITL.

    What main.rego returns for e.g. a $500 refund by a manager holding
    ``approve_refund_under_1000``: ``allow`` and ``requires_hitl`` are both
    true, and the escalation must win.
    """
    return PolicyDecision(
        allow=True,
        deny=False,
        risk_tier=risk_tier,
        requires_hitl=True,
        reason=f"Allowed — risk tier: {risk_tier.value}",
    )


def deny_decision_for(
    reason: str = "denied",
    risk_tier: RiskTier = RiskTier.OPERATIONAL,
) -> PolicyDecision:
    """Standalone helper — build a deny decision."""
    return PolicyDecision(
        allow=False,
        deny=True,
        risk_tier=risk_tier,
        requires_hitl=False,
        reason=reason,
    )
