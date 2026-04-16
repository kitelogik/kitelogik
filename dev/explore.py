#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
explore.py — What is Kite Logik? Who is it for?

Run this to see the core enforcement layer in action.
No Anthropic API key needed. No mock MCP server needed.

Only prerequisite: OPA running
  docker-compose up -d opa

────────────────────────────────────────────────────────────

WHAT IS KITE LOGIK?

  Kite Logik is governance middleware for companies that deploy AI agents.

  When you give an AI agent tools (read customer data, approve refunds,
  execute code, write files), you expose yourself to real risk:
    - The agent hallucinates and approves a $50,000 refund
    - Malicious instructions embedded in a document make the agent leak secrets
    - A worker agent spawned by an orchestrator inherits too many permissions

  You could try to fix this with better prompts. But prompts are not a
  security boundary. A determined adversary, a confused model, or a bad
  day can bypass any system prompt.

  Kite Logik enforces rules at the infrastructure level, not the prompt level.
  The policy engine intercepts every tool call before it executes and applies
  deterministic business rules (written in Rego, evaluated by OPA). The model
  cannot override them. The user cannot override them. They just… don't run.

WHO IS IT FOR?

  Target: enterprise platform / infrastructure teams
    - Banks, insurers, healthcare companies deploying AI agents in production
    - Teams that need compliance evidence (PCI-DSS, SOC 2, HIPAA)
    - Engineering orgs that want to let agents do real work without a liability bomb

  Two audiences within the enterprise:
    1. Platform engineers — integrate Kite Logik, write the Rego policies
    2. Compliance / ops teams — review escalations and audit trails

  Not for: government agencies, individual developers, consumer apps.

────────────────────────────────────────────────────────────
"""

import asyncio
import os

from dotenv import load_dotenv

from kitelogik.anchor.credentials import CredentialBroker
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import SessionContext, ToolCallInput
from kitelogik.tether.opa_client import OPAClient, OPAConnectionError

load_dotenv()

# ── ANSI colours ──────────────────────────────────────────────────────────────
G = "\033[92m"  # green
Y = "\033[93m"  # yellow
R = "\033[91m"  # red
C = "\033[96m"  # cyan
M = "\033[95m"  # magenta
B = "\033[1m"  # bold
D = "\033[2m"  # dim
RS = "\033[0m"  # reset
W = 68


def line(char="─"):
    return char * W


def bold(s):
    return f"{B}{s}{RS}"


def dim(s):
    return f"{D}{s}{RS}"


def header(text: str) -> None:
    print(f"\n{bold('═' * W)}")
    print(f"{bold('  ' + text)}")
    print(f"{bold('═' * W)}\n")


def scenario(n: int, title: str, context_label: str) -> None:
    print(f"\n  {C}{bold(f'#{n}')}{RS}  {bold(title)}")
    print(f"  {dim(f'Context: {context_label}')}")
    print(f"  {dim(line())}")


def show_decision(tool: str, args: dict, decision, ms: float) -> None:
    if decision.deny:
        badge = f"{R}{bold('✗ BLOCKED')}{RS}"
        color = R
    elif decision.requires_hitl:
        badge = f"{Y}{bold('⏳ ESCALATED')}{RS}"
        color = Y
    else:
        badge = f"{G}{bold('✓ ALLOWED')}{RS}"
        color = G

    args_str = "  ".join(f"{k}={v}" for k, v in args.items())
    print(f"\n     tool  {bold(tool)}  {dim(args_str)}")
    print(f"   result  {badge}  {color}{decision.risk_tier.value}{RS}  {dim(f'{ms:.0f}ms')}")
    print(f"   reason  {dim(decision.reason)}")
    if decision.rule_matched:
        print(f"   policy  {dim(decision.rule_matched)}")


async def check(
    gate: PolicyGate,
    context: SessionContext,
    tool_name: str,
    args: dict,
) -> None:
    resource_path = args.get("path") or args.get("file") or args.get("resource_path")
    tool_call = ToolCallInput(
        action=tool_name, tool_name=tool_name, args=args, resource_path=resource_path
    )
    t0 = asyncio.get_event_loop().time()
    decision = await gate.evaluate_tool_call(tool_call, context)
    ms = (asyncio.get_event_loop().time() - t0) * 1000
    show_decision(tool_name, args, decision, ms)


# ── Main ──────────────────────────────────────────────────────────────────────


async def main() -> None:
    opa_url = os.getenv("OPA_BASE_URL", "http://localhost:8181")
    opa = OPAClient(base_url=opa_url)
    broker = CredentialBroker()
    gate = PolicyGate(opa_client=opa, credential_broker=broker)

    # Test the OPA connection before anything else
    try:
        await opa.health()
    except OPAConnectionError:
        print(f"\n{R}OPA is not running.{RS}")
        print(f"Start it with:  {bold('docker-compose up -d opa')}\n")
        return

    header("KITE LOGIK — Policy Engine Explorer")
    print(dim("  Calling gate.evaluate_tool_call() directly."))
    print(dim("  No LLM, no mock server, no API key required."))
    print(dim(f"  OPA: {opa_url}"))

    # ── Session 1: normal support agent ───────────────────────────────────────
    # This is what a typical enterprise deployment looks like.
    # A customer support agent has been issued a session token with specific scopes.
    # Those scopes define what it can and cannot do — not a system prompt.
    agent_ctx = SessionContext(
        session_id="explore_agent_001",
        user_role="support_agent",
        session_scopes=[
            "read_customer",
            "approve_refund_under_100",
            "send_notifications",
            "memory_write",
        ],
        sandbox_verified=False,  # no sandbox attached to this session
    )

    print(
        f"\n  {bold('Session A')} — support_agent, scopes: {dim(', '.join(agent_ctx.session_scopes))}"  # noqa: E501
    )

    # ── Scenario 1 ────────────────────────────────────────────────────────────
    scenario(1, "Read customer data", "has read_customer scope")
    print(f"  {dim('Normal operation. Agent has the scope. Should pass.')}")
    await check(gate, agent_ctx, "list_transactions", {"customer_id": "cust_001"})

    # ── Scenario 2 ────────────────────────────────────────────────────────────
    scenario(2, "Approve a $50 refund", "approve_refund_under_100 scope, amount within limit")
    print(f"  {dim('Under the $100 auto-approve threshold. No human needed.')}")
    await check(gate, agent_ctx, "approve_refund", {"customer_id": "cust_001", "amount": 50.0})

    # ── Scenario 3 ────────────────────────────────────────────────────────────
    scenario(3, "Approve a $350 refund", "approve_refund_under_100 scope, amount OVER limit")
    print(f"  {dim('Exceeds $100. Policy escalates to human review (HITL).')}")
    print(f"  {dim('The agent pauses. A human must approve or deny via the HITL queue.')}")
    await check(gate, agent_ctx, "approve_refund", {"customer_id": "cust_001", "amount": 350.0})

    # ── Scenario 4 ────────────────────────────────────────────────────────────
    scenario(4, "Read a secrets file", "has read_customer scope, but NOT file access")
    print(f"  {dim('Indirect prompt injection: malicious doc told agent to read .env')}")
    print(f"  {dim('Blocked by the sensitive-file blocklist in security.rego.')}")
    await check(gate, agent_ctx, "read_file", {"path": "/app/.env"})

    # ── Scenario 5 ────────────────────────────────────────────────────────────
    scenario(5, "Execute code (no sandbox)", "no sandbox_verified=True on this session")
    print(f"  {dim('Agent tries to run arbitrary code. Session has no verified sandbox.')}")
    print(f"  {dim('security.rego: execute_code requires sandbox_verified=true.')}")
    await check(gate, agent_ctx, "execute_code", {"code": "print(42)"})

    # ── Scenario 6 ────────────────────────────────────────────────────────────
    # Simulate a worker agent spawned by an orchestrator at delegation depth 1.
    # In Kite Logik, child agents get a subset of the parent's scopes.
    # But even within scope, the delegation policy applies extra caps.
    scenario(6, "Execute code (with sandbox)", "sandbox_verified=True")
    ctx_with_sandbox = agent_ctx.model_copy(update={"sandbox_verified": True})
    print(f"  {dim('Same agent, but sandbox_verified=True on the session context.')}")
    print(f"  {dim('security.rego permits code execution when sandbox is verified.')}")
    await check(gate, ctx_with_sandbox, "execute_code", {"code": "print(42)"})

    # ── Session B: delegated worker agent (multi-agent scenario) ──────────────
    print(f"\n\n  {bold('Session B')} — worker_agent at delegation depth 1")
    print(
        f"  {dim('Spawned by an orchestrator. Child token is a strict subset of parent scopes.')}"
    )

    worker_ctx = SessionContext(
        session_id="explore_worker_001",
        user_role="worker_agent",
        session_scopes=["read_customer", "approve_refund_under_100"],
        delegation_depth=1,  # this is a worker, not the root agent
        parent_session_id="explore_agent_001",
    )

    # ── Scenario 7 ────────────────────────────────────────────────────────────
    scenario(7, "Worker approves a $30 refund", "delegation_depth=1, amount within delegated cap")
    print(f"  {dim('delegation.rego caps depth-1 agents at $50.')}")
    print(f"  {dim('$30 is under the cap — allowed.')}")
    await check(gate, worker_ctx, "approve_refund", {"customer_id": "cust_002", "amount": 30.0})

    # ── Scenario 8 ────────────────────────────────────────────────────────────
    scenario(8, "Worker approves a $200 refund", "delegation_depth=1, amount OVER delegated cap")
    print(f"  {dim('delegation.rego: depth-1 agents are hard-capped at $50.')}")
    print(f"  {dim('The worker cannot approve more than the parent permits, even if it tries.')}")
    print(
        f"  {dim('This is structural — not a prompt instruction. The model cannot override it.')}"
    )
    await check(gate, worker_ctx, "approve_refund", {"customer_id": "cust_002", "amount": 200.0})

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n\n  {dim(line('─'))}")
    print(f"\n  {bold('What you just saw:')}\n")
    print(f"  {G}✓{RS}  Allowed calls executed instantly (within policy scope)")
    print(f"  {Y}⏳{RS}  HITL calls pause the agent — a human must decide via the queue API")
    print(f"  {R}✗{RS}  Blocked calls are rejected before the tool ever runs\n")
    print(f"  {dim('Rules are enforced by the infrastructure (OPA + Rego policies).')}")
    print(f"  {dim('The model cannot prompt-inject its way past them.')}\n")


if __name__ == "__main__":
    asyncio.run(main())
