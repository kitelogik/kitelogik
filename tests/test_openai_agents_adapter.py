# SPDX-License-Identifier: Apache-2.0
"""Tests for the OpenAI Agents SDK adapter."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import PolicyDecision, RiskTier, SessionContext


@pytest.fixture
def ctx():
    return SessionContext(session_id="test", user_role="admin", session_scopes=["read"])


@pytest.fixture
def mock_gate():
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


def test_openai_agents_import_guard():
    """Import guard raises clear error when openai-agents is not installed."""
    from kitelogik.adapters.openai_agents import _require_openai_agents

    try:
        _require_openai_agents()
    except ImportError as e:
        assert "openai-agents" in str(e).lower()


def test_openai_agents_adapter_register(mock_gate, ctx):
    from kitelogik.adapters.openai_agents import OpenAIAgentsAdapter

    adapter = OpenAIAgentsAdapter(gate=mock_gate, context=ctx)
    result = adapter.register("search", lambda q: f"found: {q}", description="Search")
    assert result is adapter  # chaining


def test_openai_agents_adapter_register_with_params(mock_gate, ctx):
    from kitelogik.adapters.openai_agents import OpenAIAgentsAdapter

    adapter = OpenAIAgentsAdapter(gate=mock_gate, context=ctx)
    adapter.register(
        "search",
        lambda query: f"found: {query}",
        description="Search",
        params={"query": {"type": "string"}},
    )
    assert "search" in adapter._tools
    assert adapter._tools["search"][3] == {"query": {"type": "string"}}
