# SPDX-License-Identifier: Apache-2.0
"""Tests for the RegorusClient in-process Rego evaluator.

These tests mock the regorus engine to avoid requiring regoruspy as a
test dependency. Integration tests with real policy evaluation should
be marked with @pytest.mark.integration.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from kitelogik.tether.models import (
    GovernanceEvent,
    PolicyEvaluator,
    PolicyInput,
    RiskTier,
    SessionContext,
    result_to_decision,
)

# ---------------------------------------------------------------------------
# result_to_decision (shared helper)
# ---------------------------------------------------------------------------


class TestResultToDecision:
    def test_allow_result(self):
        result = {
            "allow": True,
            "deny": False,
            "risk_tier": "INFORMATIONAL",
            "requires_hitl": False,
        }
        decision = result_to_decision(result)
        assert decision.allow is True
        assert decision.deny is False
        assert decision.risk_tier == RiskTier.INFORMATIONAL
        assert "Allowed" in decision.reason

    def test_deny_result(self):
        result = {
            "allow": False,
            "deny": True,
            "risk_tier": "SECURITY_CRITICAL",
            "requires_hitl": False,
        }
        decision = result_to_decision(result)
        assert decision.allow is False
        assert decision.deny is True
        assert decision.risk_tier == RiskTier.SECURITY_CRITICAL
        assert "Hard blocked" in decision.reason

    def test_default_deny_result(self):
        result = {
            "allow": False,
            "deny": False,
            "risk_tier": "OPERATIONAL",
            "requires_hitl": False,
        }
        decision = result_to_decision(result)
        assert decision.allow is False
        assert decision.deny is False
        assert "Denied" in decision.reason

    def test_empty_result_defaults(self):
        decision = result_to_decision({})
        assert decision.allow is False
        assert decision.deny is False
        assert decision.risk_tier == RiskTier.OPERATIONAL
        assert decision.requires_hitl is False

    def test_hitl_result(self):
        result = {
            "allow": True,
            "deny": False,
            "risk_tier": "TRANSACTIONAL_HIGH",
            "requires_hitl": True,
        }
        decision = result_to_decision(result)
        assert decision.requires_hitl is True


# ---------------------------------------------------------------------------
# RegorusClient
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_regorus_module():
    """Mock the regorus module so tests don't require regoruspy installed."""
    mock_engine_cls = MagicMock()
    mock_engine = MagicMock()
    mock_engine_cls.return_value = mock_engine

    mock_module = MagicMock()
    mock_module.Engine = mock_engine_cls

    return mock_module, mock_engine


@pytest.fixture
def mock_policy_dir(tmp_path):
    """Create a temporary policy directory with a minimal .rego file."""
    policy_file = tmp_path / "main.rego"
    policy_file.write_text("package kitelogik.main\ndefault allow := false\n")
    return tmp_path


def _make_regorus_result(value: dict) -> str:
    """Format a value as regorus eval_query JSON output."""
    return json.dumps(
        {
            "result": [
                {
                    "expressions": [
                        {
                            "value": value,
                        }
                    ],
                }
            ],
        }
    )


class TestRegorusClient:
    def test_init_loads_policies(self, mock_regorus_module, mock_policy_dir):
        mock_module, mock_engine = mock_regorus_module

        with patch.dict("sys.modules", {"regorus": mock_module}):
            from kitelogik.tether.regorus_client import RegorusClient

            client = RegorusClient(policy_dir=mock_policy_dir)

        mock_engine.add_policy_from_file.assert_called_once()
        assert client._policy_dir == mock_policy_dir

    def test_init_raises_on_empty_dir(self, mock_regorus_module, tmp_path):
        mock_module, _ = mock_regorus_module

        with patch.dict("sys.modules", {"regorus": mock_module}):
            from kitelogik.tether.regorus_client import RegorusClient

            with pytest.raises(FileNotFoundError, match="No .rego files"):
                RegorusClient(policy_dir=tmp_path)

    def test_init_raises_without_regoruspy(self, mock_policy_dir):
        from kitelogik.tether.regorus_client import _require_regorus

        with patch.dict("sys.modules", {"regorus": None}):
            with pytest.raises(ImportError, match="regoruspy is required"):
                _require_regorus()

    async def test_health_always_true(self, mock_regorus_module, mock_policy_dir):
        mock_module, mock_engine = mock_regorus_module

        with patch.dict("sys.modules", {"regorus": mock_module}):
            from kitelogik.tether.regorus_client import RegorusClient

            client = RegorusClient(policy_dir=mock_policy_dir)
            assert await client.health() is True

    async def test_evaluate_allow(self, mock_regorus_module, mock_policy_dir):
        mock_module, mock_engine = mock_regorus_module
        mock_engine.eval_query.return_value = _make_regorus_result(
            {"allow": True, "deny": False, "risk_tier": "INFORMATIONAL", "requires_hitl": False}
        )

        with patch.dict("sys.modules", {"regorus": mock_module}):
            from kitelogik.tether.regorus_client import RegorusClient

            client = RegorusClient(policy_dir=mock_policy_dir)

            policy_input = PolicyInput(
                action="read_customer",
                tool_name="read_customer",
                args={"customer_id": "cust_001"},
                context=SessionContext(
                    session_id="sess_test",
                    user_role="analyst",
                    session_scopes=["read_customer"],
                ),
            )
            decision = await client.evaluate(policy_input)

        assert decision.allow is True
        assert decision.deny is False
        assert decision.risk_tier == RiskTier.INFORMATIONAL
        mock_engine.set_input_json.assert_called_once()
        mock_engine.eval_query.assert_called_once()

    async def test_evaluate_deny(self, mock_regorus_module, mock_policy_dir):
        mock_module, mock_engine = mock_regorus_module
        mock_engine.eval_query.return_value = _make_regorus_result(
            {"allow": False, "deny": True, "risk_tier": "SECURITY_CRITICAL", "requires_hitl": False}
        )

        with patch.dict("sys.modules", {"regorus": mock_module}):
            from kitelogik.tether.regorus_client import RegorusClient

            client = RegorusClient(policy_dir=mock_policy_dir)

            policy_input = PolicyInput(
                action="delete_database",
                tool_name="delete_database",
                args={},
                context=SessionContext(
                    session_id="sess_test",
                    user_role="analyst",
                    session_scopes=[],
                ),
            )
            decision = await client.evaluate(policy_input)

        assert decision.allow is False
        assert decision.deny is True
        assert decision.risk_tier == RiskTier.SECURITY_CRITICAL

    async def test_evaluate_event(self, mock_regorus_module, mock_policy_dir):
        mock_module, mock_engine = mock_regorus_module
        mock_engine.eval_query.return_value = _make_regorus_result(
            {"allow": True, "deny": False, "risk_tier": "OPERATIONAL", "requires_hitl": False}
        )

        with patch.dict("sys.modules", {"regorus": mock_module}):
            from kitelogik.tether.regorus_client import RegorusClient

            client = RegorusClient(policy_dir=mock_policy_dir)

            event = GovernanceEvent(
                event_type="agent.spawn",
                session_id="sess_test",
                action="agent.spawn",
                context=SessionContext(
                    session_id="sess_test",
                    user_role="operator",
                    session_scopes=["spawn_agent"],
                ),
                requested_capabilities=["read_customer"],
            )
            decision = await client.evaluate_event(event)

        assert decision.allow is True

    async def test_evaluate_empty_result(self, mock_regorus_module, mock_policy_dir):
        mock_module, mock_engine = mock_regorus_module
        mock_engine.eval_query.return_value = json.dumps({"result": []})

        with patch.dict("sys.modules", {"regorus": mock_module}):
            from kitelogik.tether.regorus_client import RegorusClient

            client = RegorusClient(policy_dir=mock_policy_dir)

            policy_input = PolicyInput(
                action="unknown",
                tool_name="unknown",
                args={},
                context=SessionContext(
                    session_id="sess_test",
                    user_role="analyst",
                    session_scopes=[],
                ),
            )
            decision = await client.evaluate(policy_input)

        # Empty result = default deny
        assert decision.allow is False
        assert decision.deny is False

    def test_conforms_to_protocol(self, mock_regorus_module, mock_policy_dir):
        mock_module, _ = mock_regorus_module

        with patch.dict("sys.modules", {"regorus": mock_module}):
            from kitelogik.tether.regorus_client import RegorusClient

            client = RegorusClient(policy_dir=mock_policy_dir)
            assert isinstance(client, PolicyEvaluator)

    def test_init_with_data(self, mock_regorus_module, mock_policy_dir):
        mock_module, mock_engine = mock_regorus_module

        with patch.dict("sys.modules", {"regorus": mock_module}):
            from kitelogik.tether.regorus_client import RegorusClient

            RegorusClient(policy_dir=mock_policy_dir, data={"allowed_tools": ["read"]})

        mock_engine.add_data_json.assert_called_once()

    def test_loads_nested_rego_files(self, mock_regorus_module, tmp_path):
        mock_module, mock_engine = mock_regorus_module

        # Create nested policy files
        (tmp_path / "main.rego").write_text("package kitelogik.main\n")
        lib_dir = tmp_path / "library"
        lib_dir.mkdir()
        (lib_dir / "helpers.rego").write_text("package kitelogik.library.helpers\n")

        with patch.dict("sys.modules", {"regorus": mock_module}):
            from kitelogik.tether.regorus_client import RegorusClient

            RegorusClient(policy_dir=tmp_path)

        assert mock_engine.add_policy_from_file.call_count == 2
