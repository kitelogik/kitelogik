#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Adversarial demo — runaway agent exhausting its budget.

Attack class: an agent (looping on its own bad reasoning, or steered by
injected instructions) keeps calling tools until it has burned far more
tokens / API calls / spend than the task could ever justify. Unbounded
consumption is both a denial-of-wallet attack and a sign of a loop that
has gone off the rails.

What Kite Logik does: each turn emits an `agent.budget` governance event
carrying the session's consumption so far. `agent_budget.rego` denies
once a budget is exhausted, halting the loop at the infrastructure layer
regardless of what the model wants to do next.

Why a prompt/output guardrail misses this: cumulative resource use is
session state that spans many turns. A tool that scans one prompt or one
response has no concept of "this session has already spent its budget".

Run (needs OPA — `docker compose up -d opa`):
    python examples/adversarial/budget_exhaustion_runaway.py
"""

from __future__ import annotations

import asyncio

from kitelogik import OPAClient, PolicyGate, SessionContext
from kitelogik.tether.models import GovernanceEvent


def _budget_check(session_id: str, used: int, total: int) -> GovernanceEvent:
    return GovernanceEvent(
        event_type="agent.budget",
        session_id=session_id,
        action="agent.budget",
        context=SessionContext(
            session_id=session_id,
            user_role="research_agent",
            session_scopes=["search"],
            budget_total_tokens=total,
            budget_used_tokens=used,
        ),
    )


async def main() -> None:
    gate = PolicyGate(opa_client=OPAClient())
    total = 10_000

    # Simulate a loop: each iteration spends more tokens. The gate is
    # consulted before each turn; the loop halts the moment the budget
    # is exhausted.
    print(f"Token budget: {total}")
    used = 0
    for turn in range(1, 8):
        used = turn * 1_800
        decision = await gate.evaluate(_budget_check("runaway-001", used, total))
        state = "DENY — halt" if decision.deny else "allow"
        print(f"  turn {turn}: used={used:>6} / {total}  -> {state}")
        if decision.deny:
            break
    else:
        raise AssertionError("expected the budget to be exhausted and the loop halted")

    assert used >= total, "loop should only halt once the budget is exhausted"
    print(
        "\nThe loop was stopped at the infrastructure layer once it crossed "
        "its token budget. Prompt- and output-level guardrails have no view "
        "of cumulative spend across a session, so a runaway loop runs free."
    )

    await gate.opa.aclose()


if __name__ == "__main__":
    asyncio.run(main())
