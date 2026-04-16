# SPDX-License-Identifier: Apache-2.0
"""Tests for the CrewAI adapter."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import PolicyDecision, RiskTier, SessionContext


@pytest.fixture
def ctx():
    return SessionContext(session_id="test", user_role="admin", session_scopes=["read"])


@pytest.fixture
def mock_gate(ctx):
    gate = MagicMock(spec=PolicyGate)
    gate.evaluate_tool_call = AsyncMock(
        return_value=PolicyDecision(
            allow=True,
            deny=False,
            risk_tier=RiskTier.INFORMATIONAL,
            requires_hitl=False,
            reason="Allowed",
        )
    )
    gate.sanitize_response = MagicMock(return_value=MagicMock(content="result", was_modified=False))
    return gate


def test_crewai_import_guard():
    """Import guard raises clear error when crewai is not installed."""
    from kitelogik.adapters.crewai import _require_crewai

    # CrewAI is likely not installed in test env
    try:
        _require_crewai()
    except ImportError as e:
        assert "crewai" in str(e).lower()


def test_crewai_adapter_register(mock_gate, ctx):
    from kitelogik.adapters.crewai import CrewAIAdapter

    adapter = CrewAIAdapter(gate=mock_gate, context=ctx)
    result = adapter.register("test_tool", lambda: "ok", description="A test tool")
    assert result is adapter  # chaining


def test_crewai_adapter_register_multiple(mock_gate, ctx):
    from kitelogik.adapters.crewai import CrewAIAdapter

    adapter = CrewAIAdapter(gate=mock_gate, context=ctx)
    adapter.register("a", lambda: "a").register("b", lambda: "b")
    assert len(adapter._tools) == 2
