#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Kite Logik — Quickstart & Guided Walkthrough

Walks through the three enforcement layers end-to-end using direct policy
gate calls — no Anthropic API key required.

  Layer 1  Tether   policy gate evaluates every tool call
  Layer 2  Anchor   HITL queue escalates high-risk actions for human review
  Layer 3  Session  scoped credentials bound to a short-lived token

Policy engine:
  docker compose up -d opa          # start OPA (recommended)

Run:
  .venv/bin/python quickstart.py
"""

import asyncio
import logging
import os
import time
from datetime import UTC, datetime

import httpx
from dotenv import load_dotenv

logging.disable(logging.CRITICAL)  # suppress gate/OPA logger output

from kitelogik import OPAClient, PolicyGate, SessionContext, ToolCallInput  # noqa: E402
from kitelogik.anchor.credentials import CredentialBroker  # noqa: E402
from kitelogik.anchor.models import ActionStatus, PendingAction  # noqa: E402
from kitelogik.anchor.queue import HITLQueue  # noqa: E402

# Try to import Regorus for zero-infrastructure mode
try:
    from kitelogik.tether.regorus_client import RegorusClient  # noqa: E402

    _HAS_REGORUS = True
except ImportError:
    _HAS_REGORUS = False

load_dotenv()

# ── Terminal colours ──────────────────────────────────────────────────────────
G = "\033[92m"
R = "\033[91m"
Y = "\033[93m"
B = "\033[94m"
DIM = "\033[2m"
BOLD = "\033[1m"
RS = "\033[0m"

W = 64  # line width


def _rule(char: str = "─") -> str:
    return char * W


def _banner(title: str) -> None:
    print(f"\n{BOLD}{_rule('═')}{RS}")
    print(f"{BOLD}  {title}{RS}")
    print(f"{BOLD}{_rule('═')}{RS}\n")


def _step(n: int, total: int, title: str) -> None:
    print(f"\n{B}{BOLD}[ Step {n} / {total} ]  {title}{RS}")
    print(f"{DIM}{_rule()}{RS}\n")


def _field(label: str, value: str, width: int = 12) -> None:
    print(f"  {label:<{width}} {value}")


def _outcome_colour(outcome: str) -> str:
    return {"ALLOW": G, "HITL": Y, "BLOCK": R}.get(outcome, "")


async def _check_opa(url: str) -> bool:
    """Return True if OPA is reachable."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.get(f"{url}/health")
            return r.status_code == 200
    except Exception:
        return False


async def _evaluate(
    gate: PolicyGate,
    context: SessionContext,
    tool: str,
    action: str,
    args: dict,
    resource_path: str | None = None,
) -> tuple:
    """Return (decision, latency_ms)."""
    tc = ToolCallInput(action=action, tool_name=tool, args=args, resource_path=resource_path)
    t0 = time.perf_counter()
    decision = await gate.evaluate_tool_call(tc, context)
    return decision, (time.perf_counter() - t0) * 1000


def _outcome(decision) -> str:
    if decision.allow:
        return "ALLOW"
    if decision.requires_hitl:
        return "HITL"
    return "BLOCK"


async def main() -> None:

    # ── Banner ────────────────────────────────────────────────────────────────
    _banner("Kite Logik  ·  Quickstart & Guided Walkthrough")

    print(
        "  Kite Logik is a governance middleware layer that sits between\n"
        "  your AI agent and the tools it calls. Every tool call passes\n"
        "  through a policy gate before it executes — the model cannot\n"
        "  override the rules, regardless of what the prompt says.\n"
        "\n"
        "  This walkthrough evaluates three tool calls and shows each\n"
        "  possible outcome:\n"
        "\n"
        f"  {G}{BOLD}ALLOW{RS}    read-only lookup     — auto-approved by policy\n"
        f"  {Y}{BOLD}HITL{RS}     high-value refund    — escalated for human review\n"
        f"  {R}{BOLD}BLOCK{RS}    unsandboxed shell    — hard denied, no override\n"
    )

    # ── Step 1: Policy engine + session token ───────────────────────────────
    _step(1, 4, "Connect to policy engine and issue a session token")

    opa_url = os.getenv("OPA_BASE_URL", "http://localhost:8181")
    engine = None
    engine_name = None

    # Try OPA first (if explicitly configured or running), then fall back to Regorus
    opa_reachable = await _check_opa(opa_url)

    if opa_reachable:
        engine = OPAClient(base_url=opa_url)
        engine_name = f"OPA at {opa_url}"
        print(f"  Policy engine: {G}OPA{RS} at {B}{opa_url}{RS}")
    elif _HAS_REGORUS:
        engine = RegorusClient(policy_dir="kitelogik/policies/")
        engine_name = "Regorus (in-process)"
        print(f"  Policy engine: {G}Regorus{RS} (in-process, no OPA needed)")
    else:
        print(f"  {R}No policy engine available.{RS}\n")
        print("  Start OPA: docker compose up -d opa\n\n  Then re-run this script.\n")
        return

    print(f"  {DIM}Engine: {engine_name}{RS}\n")

    # Credential broker issues a scoped, short-lived token for this session.
    # The model cannot grant itself scopes that aren't in this token.
    broker = CredentialBroker()
    token = broker.issue(
        session_id="qs_001",
        scopes=["read_customer", "approve_refund_under_100"],
        ttl_seconds=300,
    )
    context = SessionContext(
        session_id="qs_001",
        user_role="support_agent",
        session_scopes=token.scopes,
        token_id=token.token_id,
    )
    gate = PolicyGate(opa_client=engine, credential_broker=broker)
    queue = HITLQueue()
    await queue.setup()

    print("  Session token issued\n")
    _field("Token ID", f"{DIM}{token.token_id}{RS}")
    _field("Role", context.user_role)
    _field("Scopes", ", ".join(token.scopes))
    _field("Expires", token.expires_at.strftime("%H:%M:%S UTC"))
    print(
        f"\n  {DIM}These scopes are the ceiling of what this agent can do.\n"
        f"  OPA checks every tool call against them at the infrastructure\n"
        f"  level — no prompt instruction can expand them.{RS}"
    )

    results: list[tuple] = []  # (tool, outcome, risk_tier, latency_ms)

    # ── Step 2: auto-allowed read ─────────────────────────────────────────────
    _step(2, 4, "Auto-allowed — read-only tool call")

    print(
        "  Scenario\n"
        "  ────────\n"
        "  The agent looks up transaction history for customer cust_001.\n"
        "  This is a read-only action — no money moves, no state changes.\n"
        "  The session token carries the 'read_customer' scope.\n"
        "\n"
        "  What to expect\n"
        "  ─────────────\n"
        "  financial.rego allows 'list_transactions' for any session with\n"
        "  the read_customer scope. OPA should approve this in < 10 ms.\n"
    )

    decision, ms = await _evaluate(
        gate,
        context,
        tool="list_transactions",
        action="list_transactions",
        args={"customer_id": "cust_001", "limit": 10},
    )
    oc = _outcome(decision)
    c = _outcome_colour(oc)
    print("  Gate decision\n  ─────────────")
    _field("Tool", "list_transactions")
    _field("Decision", f"{c}{BOLD}{oc}{RS}")
    _field("Risk tier", decision.risk_tier)
    _field("Latency", f"{ms:.1f} ms")
    results.append(("list_transactions", oc, decision.risk_tier, ms))
    print(
        f"\n  {DIM}The gate added {ms:.1f} ms to this tool call — the overhead of\n"
        f"  a round-trip to OPA. Warm latency is typically 3–8 ms;\n"
        f"  the first call may be higher as OPA initialises its bundle.{RS}"
    )

    # ── Step 3: HITL escalation ───────────────────────────────────────────────
    _step(3, 4, "HITL escalation — high-value refund")

    print(
        "  Scenario\n"
        "  ────────\n"
        "  The agent wants to approve a $5,000 refund for customer cust_001.\n"
        "  The session token only carries 'approve_refund_under_100'.\n"
        "  Financial policy requires human review for amounts over $1,000.\n"
        "\n"
        "  What to expect\n"
        "  ─────────────\n"
        "  No financial.rego allow rule matches (amount far exceeds $100).\n"
        "  main.rego classifies the action as TRANSACTIONAL_HIGH and sets\n"
        "  requires_hitl=true. The agent is paused until a human decides.\n"
    )

    decision, ms = await _evaluate(
        gate,
        context,
        tool="approve_refund",
        action="approve_refund",
        args={"customer_id": "cust_001", "amount": 5000.00},
    )
    oc = _outcome(decision)
    c = _outcome_colour(oc)
    print("  Gate decision\n  ─────────────")
    _field("Tool", "approve_refund")
    _field("Args", "amount=$5,000")
    _field("Decision", f"{c}{BOLD}{oc}{RS}")
    _field("Risk tier", decision.risk_tier)
    _field("Latency", f"{ms:.1f} ms")
    results.append(("approve_refund", oc, decision.risk_tier, ms))

    # Enqueue to the HITL queue and auto-resolve after a short pause.
    # In production the HITL queue handles this — the agent awaits the event.
    pending = PendingAction(
        id="",
        session_id=context.session_id,
        tool_name="approve_refund",
        args={"customer_id": "cust_001", "amount": 5000.00},
        risk_tier=decision.risk_tier,
        status=ActionStatus.PENDING,
        created_at=datetime.now(UTC),
    )
    action_id = await queue.enqueue(pending)

    print(
        f"\n  Action queued — agent is now paused\n"
        f"  {'Action ID':<12} {DIM}{action_id}{RS}\n"
        f"  {'Status':<12} {Y}PENDING{RS}\n"
        "\n"
        f"  In production, use the HITL queue API to approve or deny.\n"
        f"  Auto-approving in 2 s to demonstrate the resolution flow...\n"
    )

    await asyncio.sleep(2)
    await queue.approve(action_id, decided_by="quickstart_demo")

    print(
        f"  {'Status':<12} {G}APPROVED — by quickstart_demo{RS}\n"
        "\n"
        f"  {DIM}The agent receives the decision signal and resumes. Every\n"
        f"  approval is stored with the reviewer identity and timestamp\n"
        f"  for the audit log.{RS}"
    )

    # ── Step 4: hard block ────────────────────────────────────────────────────
    _step(4, 4, "Hard block — unsandboxed shell execution")

    print(
        "  Scenario\n"
        "  ────────\n"
        "  The agent calls 'execute_shell' to run a command on the host.\n"
        "  The session was not launched inside a MicroVM sandbox, so\n"
        "  sandbox_verified=False on the session context.\n"
        "\n"
        "  What to expect\n"
        "  ─────────────\n"
        "  security.rego hard-denies any shell/code execution without a\n"
        "  verified sandbox. This decision is final — no scope, role, or\n"
        "  human approval can override a hard deny.\n"
    )

    decision, ms = await _evaluate(
        gate,
        context,
        tool="execute_shell",
        action="execute_shell",
        args={"cmd": "cat /etc/passwd"},
    )
    oc = _outcome(decision)
    c = _outcome_colour(oc)
    print("  Gate decision\n  ─────────────")
    _field("Tool", "execute_shell")
    _field("Args", 'cmd="cat /etc/passwd"')
    _field("Decision", f"{c}{BOLD}{oc}{RS}")
    _field("Risk tier", decision.risk_tier)
    _field("Latency", f"{ms:.1f} ms")
    results.append(("execute_shell", oc, decision.risk_tier, ms))
    print(
        f"\n  {DIM}Hard denies go directly to the audit log. The HITL queue is\n"
        f"  bypassed — there is no escalation path for security.deny rules.\n"
        f"  To allow code execution, the session must be launched inside a\n"
        f"  Firecracker MicroVM with sandbox_verified=True.{RS}"
    )

    # ── Summary ───────────────────────────────────────────────────────────────
    _banner("Summary")

    col = (26, 8, 22, 0)
    print(f"  {BOLD}{'Tool':<{col[0]}} {'Outcome':<{col[1]}} {'Risk tier':<{col[2]}} Latency{RS}")
    print(f"  {DIM}{_rule('─')}{RS}")

    total_ms = 0.0
    for tool, oc, tier, ms in results:
        c = _outcome_colour(oc)
        print(f"  {tool:<{col[0]}} {c}{BOLD}{oc:<{col[1]}}{RS} {tier:<{col[2]}} {ms:.1f} ms")
        total_ms += ms

    print(f"\n  3 tool calls evaluated  ·  total gate latency {total_ms:.1f} ms\n")

    print(
        f"  {BOLD}Next steps{RS}\n"
        f"  {_rule('─')}\n"
        f"  {B}python explore.py{RS}\n"
        f"    Run 8 scenarios covering delegation, injection defence, and more.\n"
        "\n"
        f"  {B}policies/financial.rego{RS}\n"
        f"    Adjust approval thresholds, roles, and scopes.\n"
        "\n"
        f"  {B}policies/security.rego{RS}\n"
        f"    Add or remove hard-block rules for shell, file, and path access.\n"
        "\n"
        f"  {B}policies/examples/{RS}\n"
        f"    Annotated example policies for financial, RBAC, and tool allowlists.\n"
    )


if __name__ == "__main__":
    asyncio.run(main())
