#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Adversarial demo — delegation scope escalation.

Attack class: a parent agent spawns a child and tries to grant it a
capability the parent itself was never given. If the child can hold a
broader scope than its parent, an attacker who compromises the parent's
reasoning can quietly widen privileges one delegation at a time.

What Kite Logik does: the `agent.delegate` governance event is evaluated
against `agent_lifecycle.rego` *before* the child exists. The child's
requested capabilities must be a subset of the parent's session scopes;
anything broader is a hard deny.

Why a prompt/output guardrail misses this: there is no malicious *text*
here. "Delegate a billing task to a sub-agent" is an ordinary request.
The violation is the structural relationship between the parent's scopes
and the child's — invisible to a tool that only scans prompts or
validates model output.

Run (needs OPA — `docker compose up -d opa`):
    python examples/adversarial/delegation_scope_escalation.py
"""

from __future__ import annotations

import asyncio

from kitelogik import OPAClient, PolicyGate, SessionContext
from kitelogik.tether.models import GovernanceEvent


async def main() -> None:
    gate = PolicyGate(opa_client=OPAClient())

    # The parent agent holds two scopes — and nothing else.
    parent = SessionContext(
        session_id="parent-001",
        user_role="billing_agent",
        session_scopes=["read_invoice", "send_receipt"],
        delegation_depth=0,
    )

    # It tries to delegate a child that asks for `transfer_funds` — a
    # capability the parent was never granted.
    escalation = GovernanceEvent(
        event_type="agent.delegate",
        session_id=parent.session_id,
        action="agent.delegate",
        context=parent,
        delegation_target="child-collections-agent",
        requested_capabilities=["read_invoice", "transfer_funds"],
    )

    decision = await gate.evaluate(escalation)

    print("Parent scopes :", parent.session_scopes)
    print("Child requests:", escalation.requested_capabilities, "(transfer_funds exceeds parent)")
    print("Decision      :", "DENY" if decision.deny else "ALLOW")
    assert decision.deny, "expected the scope escalation to be hard-denied"

    # A legitimate subset delegation is allowed, for contrast.
    legitimate = GovernanceEvent(
        event_type="agent.delegate",
        session_id=parent.session_id,
        action="agent.delegate",
        context=parent,
        delegation_target="child-collections-agent",
        requested_capabilities=["read_invoice"],
    )
    ok = await gate.evaluate(legitimate)
    print("\nSubset delegation (read_invoice):", "ALLOW" if ok.allow else "DENY")
    assert ok.allow, "a subset delegation should be allowed"

    print(
        "\nA prompt-injection firewall sees only ordinary delegation text. "
        "Kite Logik blocked the privilege widening at the infrastructure "
        "layer — the child can never hold a scope the parent lacked."
    )

    await gate.opa.aclose()


if __name__ == "__main__":
    asyncio.run(main())
