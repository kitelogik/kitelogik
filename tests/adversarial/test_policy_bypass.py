# SPDX-License-Identifier: Apache-2.0
"""
Adversarial policy bypass test suite.

Runs against a REAL OPA instance — no mocks. Every test sends a crafted
PolicyInput to OPA and asserts the exact PolicyDecision returned.

Test categories:
  1. Type coercion (string/null/boolean/negative amounts)
  2. Path traversal (relative paths, double-slash, null bytes, extra extensions)
  3. Session boundary (cross-session, empty session_id, null session_id)
  4. Delegation escalation (depth cap, refund cap, depth-2 block)
  5. Scope escalation (wrong role, wrong scope, over-limit amounts)
  6. Missing context fields (sandbox_verified absent, empty session_id)
  7. Combined inputs (security + delegation deny, HITL interaction)

Tests marked xfail document confirmed policy gaps that SHOULD be fixed.
When a gap is closed, its xfail will become an xpass — promote to a regular test.

Run with:
    docker-compose up -d opa && pytest tests/adversarial/test_policy_bypass.py -v
"""

import subprocess
import time
from pathlib import Path

import httpx
import pytest

from kitelogik.tether.models import PolicyInput, RiskTier, SessionContext
from kitelogik.tether.opa_client import OPAClient

POLICIES_DIR = Path(__file__).parent.parent.parent / "kitelogik" / "policies"
OPA_TEST_PORT = 18181  # Distinct from production port 8181


# ── OPA server fixture ────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def opa_server():
    """
    Spawn a real OPA server via Docker for the test session.
    Uses a dedicated port (18181) to avoid clashing with a running dev server.
    """
    container_name = "kitelogik-opa-adversarial-test"

    # Clean up any leftover container from a previous interrupted run
    subprocess.run(
        ["docker", "rm", "-f", container_name],
        capture_output=True,
    )

    proc = subprocess.Popen(
        [
            "docker",
            "run",
            "--rm",
            "--name",
            container_name,
            "-p",
            f"{OPA_TEST_PORT}:8181",
            "-v",
            f"{POLICIES_DIR.resolve()}:/policies:ro",
            "openpolicyagent/opa:latest",
            "run",
            "--server",
            "--addr",
            ":8181",
            "--watch",
            "/policies",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    base_url = f"http://localhost:{OPA_TEST_PORT}"
    deadline = time.monotonic() + 20.0
    last_exc = None

    while time.monotonic() < deadline:
        try:
            r = httpx.get(f"{base_url}/health", timeout=1.0)
            if r.status_code == 200:
                break
        except Exception as exc:
            last_exc = exc
        time.sleep(0.5)
    else:
        proc.terminate()
        proc.wait()
        pytest.fail(f"OPA server did not become healthy within 20s: {last_exc}")

    yield base_url

    proc.terminate()
    proc.wait()


@pytest.fixture(scope="session")
def opa(opa_server: str) -> OPAClient:
    return OPAClient(base_url=opa_server)


# ── Helper ────────────────────────────────────────────────────────────────


def make_input(
    action: str,
    args: dict,
    resource_path: str | None = None,
    session_id: str = "sess-adversarial",
    user_role: str = "support_agent",
    session_scopes: list[str] | None = None,
    sandbox_verified: bool = False,
    delegation_depth: int = 0,
) -> PolicyInput:
    if session_scopes is None:
        session_scopes = ["read_customer", "approve_refund_under_100", "send_notifications"]
    return PolicyInput(
        action=action,
        tool_name=action,
        args=args,
        resource_path=resource_path,
        context=SessionContext(
            session_id=session_id,
            user_role=user_role,
            session_scopes=session_scopes,
            sandbox_verified=sandbox_verified,
            delegation_depth=delegation_depth,
        ),
    )


# ── Category 1: Type coercion ─────────────────────────────────────────────


async def test_string_amount_is_soft_denied_not_bypassed(opa: OPAClient):
    """
    String "2000" is not a number — financial allow requires amount<=100.
    OPA's structural ordering: string > number, so "2000" > 100 → allow rule fails.
    Correct outcome: soft deny + HITL (not a hard block, not an allow).
    """
    decision = await opa.evaluate(
        make_input(
            action="approve_refund",
            args={"amount": "2000"},
        )
    )
    assert decision.allow is False
    assert decision.deny is False
    assert decision.requires_hitl is True


async def test_null_amount_is_blocked_not_allowed(opa: OPAClient):
    """
    null passes `amount <= 100` because OPA orders: null < boolean < number.
    A null amount refund should NOT be approved — this is a policy gap.
    """
    decision = await opa.evaluate(
        make_input(
            action="approve_refund",
            args={"amount": None},
        )
    )
    # DESIRED: null amounts should be denied or at minimum require HITL
    assert decision.allow is False


async def test_null_amount_bypasses_delegation_cap_at_depth_1(opa: OPAClient):
    """
    At depth-1, the $50 cap fires when `amount > 50`.
    But `null > 50` is FALSE in OPA structural ordering.
    Combined with financial.allow (null <= 100 = TRUE), this is a full bypass.
    """
    decision = await opa.evaluate(
        make_input(
            action="approve_refund",
            args={"amount": None},
            delegation_depth=1,
        )
    )
    # DESIRED: a null amount at depth-1 should be denied
    assert decision.deny is True


async def test_boolean_amount_is_blocked_not_allowed(opa: OPAClient):
    """boolean `true` satisfies `true <= 100` — OPA structural ordering."""
    decision = await opa.evaluate(
        make_input(
            action="approve_refund",
            args={"amount": True},
        )
    )
    assert decision.allow is False


async def test_negative_amount_is_blocked_not_allowed(opa: OPAClient):
    """Negative refund amount: -1 <= 100 → financial.allow fires. Policy gap."""
    decision = await opa.evaluate(
        make_input(
            action="approve_refund",
            args={"amount": -1},
        )
    )
    assert decision.allow is False


async def test_negative_amount_bypasses_delegation_cap_at_depth_1(opa: OPAClient):
    """Negative amounts are 'below' the $50 cap and 'below' the $100 limit simultaneously."""
    decision = await opa.evaluate(
        make_input(
            action="approve_refund",
            args={"amount": -100},
            delegation_depth=1,
        )
    )
    assert decision.deny is True


# ── Category 2: Path traversal ────────────────────────────────────────────


async def test_relative_path_traversal_is_hard_blocked(opa: OPAClient):
    """../../../etc/passwd bypasses both system-path and extension checks."""
    decision = await opa.evaluate(
        make_input(
            action="read_file",
            args={},
            resource_path="../../../etc/passwd",
        )
    )
    assert decision.deny is True
    assert decision.risk_tier == RiskTier.SECURITY_CRITICAL


async def test_double_slash_path_is_hard_blocked(opa: OPAClient):
    """`//etc/passwd` bypasses the system path regex anchored to `^/etc`."""
    decision = await opa.evaluate(
        make_input(
            action="read_file",
            args={},
            resource_path="//etc/passwd",
        )
    )
    assert decision.deny is True
    assert decision.risk_tier == RiskTier.SECURITY_CRITICAL


async def test_null_byte_in_path_is_hard_blocked(opa: OPAClient):
    """
    `/etc/passwd\x00.txt` — the path prefix still matches `^/(etc|...)`.
    Hard block fires despite the appended `.txt` suffix after the null byte.
    """
    decision = await opa.evaluate(
        make_input(
            action="read_file",
            args={},
            resource_path="/etc/passwd\x00.txt",
        )
    )
    assert decision.deny is True
    assert decision.risk_tier == RiskTier.SECURITY_CRITICAL


async def test_env_uppercase_is_hard_blocked(opa: OPAClient):
    """Regex uses (?i) flag — `.ENV` is caught by the extension rule."""
    decision = await opa.evaluate(
        make_input(
            action="read_file",
            args={},
            resource_path="/app/config.ENV",
        )
    )
    assert decision.deny is True
    assert decision.risk_tier == RiskTier.SECURITY_CRITICAL


async def test_relative_key_file_is_hard_blocked(opa: OPAClient):
    """`secrets.key` — relative path but extension rule fires regardless of leading slash."""
    decision = await opa.evaluate(
        make_input(
            action="read_file",
            args={},
            resource_path="secrets.key",
        )
    )
    assert decision.deny is True
    assert decision.risk_tier == RiskTier.SECURITY_CRITICAL


async def test_env_with_extra_extension_is_hard_blocked(opa: OPAClient):
    """`file.env.bak` — `.env` is not the final extension, bypasses the regex."""
    decision = await opa.evaluate(
        make_input(
            action="read_file",
            args={},
            resource_path="file.env.bak",
        )
    )
    assert decision.deny is True
    assert decision.risk_tier == RiskTier.SECURITY_CRITICAL


async def test_system_path_with_sensitive_extension_is_double_blocked(opa: OPAClient):
    """/var/run/secrets.key — both the path rule and the extension rule fire."""
    decision = await opa.evaluate(
        make_input(
            action="read_file",
            args={},
            resource_path="/var/run/secrets.key",
        )
    )
    assert decision.deny is True
    assert decision.risk_tier == RiskTier.SECURITY_CRITICAL


async def test_safe_data_path_is_not_blocked(opa: OPAClient):
    decision = await opa.evaluate(
        make_input(
            action="read_file",
            args={},
            resource_path="/data/reports/q4_summary.csv",
        )
    )
    assert decision.deny is False


# ── Category 3: Session boundary ─────────────────────────────────────────


async def test_cross_session_access_is_hard_blocked(opa: OPAClient):
    """args.session_id != context.session_id → security.deny fires."""
    decision = await opa.evaluate(
        make_input(
            action="query_memory",
            args={"session_id": "victim-session"},
            session_id="attacker-session",
        )
    )
    assert decision.deny is True
    assert decision.risk_tier == RiskTier.SECURITY_CRITICAL


async def test_empty_string_session_id_in_args_is_hard_blocked(opa: OPAClient):
    """Empty string != null, and "" != "my-session" → security.deny fires."""
    decision = await opa.evaluate(
        make_input(
            action="query_memory",
            args={"session_id": ""},
            session_id="my-session",
        )
    )
    assert decision.deny is True
    assert decision.risk_tier == RiskTier.SECURITY_CRITICAL


async def test_null_session_id_in_args_does_not_trigger_cross_session_block(opa: OPAClient):
    """null != null is FALSE in Rego — the cross-session rule does not fire."""
    decision = await opa.evaluate(
        make_input(
            action="query_memory",
            args={"session_id": None},
            session_id="my-session",
        )
    )
    # Rule correctly skips the check when args.session_id is null
    assert decision.deny is False


async def test_matching_session_ids_are_not_blocked(opa: OPAClient):
    """Same session ID in args and context — no cross-session violation."""
    decision = await opa.evaluate(
        make_input(
            action="query_memory",
            args={"session_id": "my-session"},
            session_id="my-session",
        )
    )
    assert decision.deny is False


# ── Category 4: Delegation escalation ────────────────────────────────────


async def test_depth_3_is_hard_blocked(opa: OPAClient):
    """delegation.deny fires for any action at depth > 2."""
    decision = await opa.evaluate(
        make_input(
            action="read_customer_record",
            args={},
            delegation_depth=3,
        )
    )
    assert decision.deny is True
    assert decision.risk_tier == RiskTier.SECURITY_CRITICAL


async def test_depth_1_refund_over_50_is_hard_blocked(opa: OPAClient):
    """Depth-1 refund cap: amount=51 > 50 → delegation.deny fires."""
    decision = await opa.evaluate(
        make_input(
            action="approve_refund",
            args={"amount": 51},
            delegation_depth=1,
        )
    )
    assert decision.deny is True
    assert decision.risk_tier == RiskTier.SECURITY_CRITICAL


async def test_depth_1_refund_at_exactly_50_is_allowed(opa: OPAClient):
    """Boundary: amount=50 is exactly at the cap. 50 > 50 is FALSE → allowed."""
    decision = await opa.evaluate(
        make_input(
            action="approve_refund",
            args={"amount": 50},
            delegation_depth=1,
        )
    )
    assert decision.deny is False
    assert decision.allow is True


async def test_depth_2_refund_any_amount_is_hard_blocked(opa: OPAClient):
    """Depth-2+: no refunds at all. Even $0 is blocked."""
    for amount in [0, 1, 50, 100]:
        decision = await opa.evaluate(
            make_input(
                action="approve_refund",
                args={"amount": amount},
                delegation_depth=2,
            )
        )
        assert decision.deny is True, f"Expected deny for depth=2 amount={amount}"
        assert decision.risk_tier == RiskTier.SECURITY_CRITICAL


async def test_depth_2_non_refund_action_is_not_delegation_blocked(opa: OPAClient):
    """Depth-2 restricts refunds only, not all actions."""
    decision = await opa.evaluate(
        make_input(
            action="read_customer_record",
            args={},
            delegation_depth=2,
        )
    )
    assert decision.deny is False


async def test_string_amount_at_depth_1_is_hard_blocked(opa: OPAClient):
    """
    OPA structural ordering: string > number.
    "100" > 50 evaluates to TRUE → delegation cap fires.
    Documented in delegation_test.rego. The safety property holds for strings.
    """
    decision = await opa.evaluate(
        make_input(
            action="approve_refund",
            args={"amount": "100"},
            delegation_depth=1,
        )
    )
    assert decision.deny is True


# ── Category 5: Scope escalation ─────────────────────────────────────────


async def test_support_agent_cannot_approve_high_value_refund(opa: OPAClient):
    """
    support_agent is not in the `manager` role required by the high-value rule.
    Even with the high-value scope, the role check fails.
    Result: soft deny + HITL (high-value refund).
    """
    decision = await opa.evaluate(
        make_input(
            action="approve_refund",
            args={"amount": 500},
            user_role="support_agent",
            session_scopes=["approve_refund_under_1000"],
        )
    )
    assert decision.allow is False
    assert decision.deny is False
    assert decision.requires_hitl is True
    assert decision.risk_tier == RiskTier.TRANSACTIONAL_HIGH


async def test_manager_cannot_exceed_1000_limit(opa: OPAClient):
    """Amount 1001 exceeds the high-value cap. Soft deny + HITL."""
    decision = await opa.evaluate(
        make_input(
            action="approve_refund",
            args={"amount": 1001},
            user_role="manager",
            session_scopes=["approve_refund_under_1000"],
        )
    )
    assert decision.allow is False
    assert decision.deny is False
    assert decision.requires_hitl is True
    assert decision.risk_tier == RiskTier.TRANSACTIONAL_HIGH


async def test_missing_scope_prevents_low_value_refund(opa: OPAClient):
    """support_agent without approve_refund_under_100 scope: soft deny."""
    decision = await opa.evaluate(
        make_input(
            action="approve_refund",
            args={"amount": 50},
            session_scopes=["read_customer"],
        )
    )
    assert decision.allow is False
    assert decision.deny is False


async def test_unknown_role_is_not_granted_access(opa: OPAClient):
    """No financial rule matches an unknown role. Soft deny."""
    decision = await opa.evaluate(
        make_input(
            action="approve_refund",
            args={"amount": 50},
            user_role="intern",
            session_scopes=["approve_refund_under_100"],
        )
    )
    assert decision.allow is False
    assert decision.deny is False


async def test_write_memory_without_scope_is_denied(opa: OPAClient):
    decision = await opa.evaluate(
        make_input(
            action="write_memory",
            args={"key": "x", "value": "y"},
            session_scopes=["read_customer"],
        )
    )
    assert decision.allow is False


async def test_write_memory_with_scope_is_allowed(opa: OPAClient):
    decision = await opa.evaluate(
        make_input(
            action="write_memory",
            args={"key": "x", "value": "y"},
            session_scopes=["memory_write"],
        )
    )
    assert decision.allow is True
    assert decision.deny is False


# ── Category 6: Missing context fields ───────────────────────────────────


async def test_execute_code_without_sandbox_is_hard_blocked(opa: OPAClient):
    """sandbox_verified defaults to False — execute_code must be blocked."""
    decision = await opa.evaluate(
        make_input(
            action="execute_code",
            args={},
            sandbox_verified=False,
        )
    )
    assert decision.deny is True
    assert decision.risk_tier == RiskTier.SECURITY_CRITICAL


async def test_execute_code_with_sandbox_is_allowed(opa: OPAClient):
    """sandbox_verified=True lifts the hard block on code execution."""
    decision = await opa.evaluate(
        make_input(
            action="execute_code",
            args={},
            sandbox_verified=True,
            session_scopes=[],
        )
    )
    # security.deny does NOT fire; financial.allow fires (sandbox_verified=true)
    assert decision.deny is False
    assert decision.allow is True


async def test_query_memory_with_empty_session_id_is_not_allowed(opa: OPAClient):
    """
    financial.rego rule: `session_id != ""` — empty session_id fails this check.
    Result: soft deny (no hard block, but not allowed either).
    """
    decision = await opa.evaluate(
        make_input(
            action="query_memory",
            args={},
            session_id="",
        )
    )
    assert decision.allow is False
    # Not a security hard-block — no session_id rule in security.rego for this
    assert decision.deny is False


async def test_query_memory_with_valid_session_id_is_allowed(opa: OPAClient):
    decision = await opa.evaluate(
        make_input(
            action="query_memory",
            args={},
            session_id="valid-session-001",
        )
    )
    assert decision.allow is True
    assert decision.deny is False


# ── Category 7: Combined / interaction tests ──────────────────────────────


async def test_security_and_delegation_both_deny_result_is_security_critical(opa: OPAClient):
    """
    When both security.deny and delegation.deny would fire, main.deny=True
    and risk_tier must be SECURITY_CRITICAL (not ambiguous).
    """
    decision = await opa.evaluate(
        make_input(
            action="read_file",
            args={},
            resource_path="/etc/passwd",
            delegation_depth=3,
        )
    )
    assert decision.deny is True
    assert decision.risk_tier == RiskTier.SECURITY_CRITICAL
    assert decision.requires_hitl is False


async def test_high_value_refund_requires_hitl_even_when_allowed(opa: OPAClient):
    """
    Manager with high-value scope approving $500 refund:
    financial.allow=True AND requires_hitl=True (TRANSACTIONAL_HIGH always escalates).
    """
    decision = await opa.evaluate(
        make_input(
            action="approve_refund",
            args={"amount": 500},
            user_role="manager",
            session_scopes=["approve_refund_under_1000"],
        )
    )
    assert decision.allow is True
    assert decision.deny is False
    assert decision.requires_hitl is True
    assert decision.risk_tier == RiskTier.TRANSACTIONAL_HIGH


async def test_security_deny_does_not_trigger_hitl(opa: OPAClient):
    """
    Hard security blocks must not surface as HITL — no human can approve
    a sandbox escape attempt. requires_hitl must be False.
    """
    decision = await opa.evaluate(
        make_input(
            action="execute_code",
            args={},
            sandbox_verified=False,
        )
    )
    assert decision.deny is True
    assert decision.requires_hitl is False


async def test_delegation_deny_does_not_trigger_hitl(opa: OPAClient):
    """Delegation depth violations are structural, not overridable by humans."""
    decision = await opa.evaluate(
        make_input(
            action="approve_refund",
            args={"amount": 1},
            delegation_depth=3,
        )
    )
    assert decision.deny is True
    assert decision.requires_hitl is False


async def test_soft_deny_surfaces_as_hitl_for_human_review(opa: OPAClient):
    """
    A denied action that is not a hard security/delegation block should surface
    to human review (requires_hitl=True) so an approver can override if appropriate.
    """
    decision = await opa.evaluate(
        make_input(
            action="approve_refund",
            args={"amount": 50},
            session_scopes=[],  # No scope at all — soft deny
        )
    )
    assert decision.allow is False
    assert decision.deny is False
    assert decision.requires_hitl is True


async def test_read_action_risk_tier_is_informational(opa: OPAClient):
    decision = await opa.evaluate(
        make_input(
            action="read_customer_record",
            args={},
            session_scopes=["read_customer"],
        )
    )
    assert decision.allow is True
    assert decision.risk_tier == RiskTier.INFORMATIONAL
    assert decision.requires_hitl is False


async def test_opa_is_reachable_and_policy_is_loaded(opa: OPAClient):
    """Smoke test: OPA is up and the kitelogik policy bundle is loaded."""
    decision = await opa.evaluate(
        make_input(
            action="read_customer_record",
            args={},
            session_scopes=["read_customer"],
        )
    )
    # Any valid PolicyDecision confirms OPA is serving the correct policy
    assert isinstance(decision.allow, bool)
    assert isinstance(decision.deny, bool)
