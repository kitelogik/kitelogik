# SPDX-License-Identifier: Apache-2.0
"""Tests for kitelogik init scaffolding and getting-started example."""

import pytest

from kitelogik.cli import cmd_init
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import SessionContext, ToolCallInput


@pytest.fixture()
def init_project(tmp_path):
    """Scaffold a project using kitelogik init."""
    import argparse

    args = argparse.Namespace(directory=str(tmp_path))
    rc = cmd_init(args)
    assert rc == 0
    return tmp_path


class TestKitelogikInit:
    def test_init_creates_files(self, init_project):
        assert (init_project / "policies" / "policy.yaml").exists()
        assert (init_project / "policies" / "policy.rego").exists()
        assert (init_project / "agent.py").exists()
        assert (init_project / ".env.example").exists()

    def test_init_refuses_overwrite(self, init_project):
        import argparse

        args = argparse.Namespace(directory=str(init_project))
        rc = cmd_init(args)
        assert rc == 1

    def test_compiled_rego_is_valid(self, init_project):
        rego = (init_project / "policies" / "policy.rego").read_text()
        # The user's rules compile into the shared userpolicy package,
        # merge-safe: no defaults (the bundled userpolicy.rego owns them).
        assert "package kitelogik.userpolicy" in rego
        assert "default deny := false" not in rego  # set-valued deny[msg]
        assert "default allow" not in rego
        assert "default risk_tier" not in rego
        assert 'deny["Refunds over $200 require manager approval"]' in rego

    def test_init_ships_core_bundle(self, init_project):
        # The scaffold must include the full governance pipeline, not just
        # the user's compiled rules, so the project evaluates against the
        # real main package (security, delegation, HITL, event routing).
        policies = init_project / "policies"
        for module in ("main.rego", "userpolicy.rego", "financial.rego", "security.rego"):
            assert (policies / module).exists(), f"missing core module {module}"
        # Core test files are KL's own CI artefacts — not shipped to users.
        assert not list(policies.glob("*_test.rego"))


class TestExamplePolicyEvaluation:
    """Evaluate the getting-started example policy through PolicyGate."""

    @pytest.fixture()
    def gate_and_context(self, init_project):
        try:
            from kitelogik.tether.regorus_client import RegorusClient

            evaluator = RegorusClient(policy_dir=init_project / "policies")
        except ImportError:
            pytest.skip("regorus Python bindings not installed — see microsoft/regorus")
        gate = PolicyGate(opa_client=evaluator)
        context = SessionContext(
            session_id="test-001",
            user_role="support_agent",
            session_scopes=["read_customer", "approve_refund"],
        )
        return gate, context

    async def test_allow_customer_lookup(self, gate_and_context):
        gate, ctx = gate_and_context
        tc = ToolCallInput(
            action="get_customer",
            tool_name="get_customer",
            args={"customer_id": "c1"},
        )
        decision = await gate.evaluate_tool_call(tc, ctx)
        assert decision.allow is True

    async def test_allow_small_refund(self, gate_and_context):
        gate, ctx = gate_and_context
        tc = ToolCallInput(
            action="approve_refund",
            tool_name="approve_refund",
            args={"customer_id": "c1", "amount": 50},
        )
        decision = await gate.evaluate_tool_call(tc, ctx)
        assert decision.allow is True

    async def test_block_large_refund(self, gate_and_context):
        gate, ctx = gate_and_context
        tc = ToolCallInput(
            action="approve_refund",
            tool_name="approve_refund",
            args={"customer_id": "c1", "amount": 500},
        )
        decision = await gate.evaluate_tool_call(tc, ctx)
        assert decision.allow is False or decision.deny is True

    async def test_block_shell_access(self, gate_and_context):
        gate, ctx = gate_and_context
        tc = ToolCallInput(
            action="run_shell_command",
            tool_name="run_shell_command",
            args={"command": "ls"},
        )
        decision = await gate.evaluate_tool_call(tc, ctx)
        assert decision.allow is False or decision.deny is True
