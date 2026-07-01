#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Example 07 — Plan-before-execute governance.

Submit a multi-step plan to the policy gate *before* any step runs.
If the plan contains a tool that would be denied, the whole plan is
blocked — step 1 never executes.  This is the defence against
"safe prefix, unsafe tail" attacks.

Prerequisite:
    docker compose up -d opa    # OPA at http://localhost:8181

Run:
    python examples/07_plan_gate.py
"""

from __future__ import annotations

import asyncio

from kitelogik import OPAClient, PolicyGate, SessionContext


async def main() -> None:
    gate = PolicyGate(OPAClient())
    context = SessionContext(
        session_id="plan-demo",
        user_role="support_agent",
        session_scopes=["read_ticket", "read_account", "send_summary"],
    )

    # --- Allowed plan: every tool is within the session scopes ---
    allowed_plan = [
        {"tool_name": "read_ticket", "args": {"ticket_id": "T-1001"}},
        {"tool_name": "read_account", "args": {"account_id": "A-2002"}},
        {"tool_name": "send_summary", "args": {"recipient": "agent@company.com"}},
    ]

    print("=== Plan 1: allowed plan ===")
    for i, step in enumerate(allowed_plan, 1):
        print(f"  step {i}: {step['tool_name']}")
    decision = await gate.evaluate_plan(allowed_plan, context)
    print(f"Decision: {'ALLOW' if decision.allow else 'DENY'}\n")

    # --- Blocked plan: contains a tool that is not allowed ---
    blocked_plan = [
        {"tool_name": "read_ticket", "args": {"ticket_id": "T-1001"}},
        {"tool_name": "drop_database", "args": {"name": "customers"}},
        {"tool_name": "send_summary", "args": {"recipient": "agent@company.com"}},
    ]

    print("=== Plan 2: blocked plan ===")
    for i, step in enumerate(blocked_plan, 1):
        print(f"  step {i}: {step['tool_name']}")
    decision = await gate.evaluate_plan(blocked_plan, context)
    print(f"Decision: {'ALLOW' if decision.allow else 'DENY'}")

    print(
        "\n✅ Plan 1 is allowed (all steps scoped). "
        "Plan 2 is denied before step 1 — no side effects happen."
    )


if __name__ == "__main__":
    asyncio.run(main())
