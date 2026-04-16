# SPDX-License-Identifier: Apache-2.0
from unittest.mock import AsyncMock

import pytest

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
