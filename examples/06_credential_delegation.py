#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Example 06 — Credential delegation with subset-only scope.

Multi-agent systems spawn child agents from a parent. Kite Logik's
CredentialBroker enforces that the child's scopes are a strict subset of
the parent's, so a sub-agent cannot do anything the parent couldn't —
even if the model believes it should.

This example walks through:

    1. Issue a parent token with three scopes.
    2. Delegate a child with two of those scopes — succeeds.
    3. Try to delegate a child that asks for a scope the parent doesn't
       hold — blocked with ValueError ("forbidden scopes").
    4. Revoke the child — subsequent validate() returns None.
    5. Confirm the parent is still valid after the child is revoked.

No OPA required — the broker is pure in-process Python.

Run:
    python examples/06_credential_delegation.py
"""

from __future__ import annotations

from kitelogik import CredentialBroker


def main() -> None:
    broker = CredentialBroker()

    # 1. Issue a parent token — typically the orchestrator does this when the
    #    user signs in or starts an agent run.
    parent = broker.issue(
        session_id="parent_agent_session",
        scopes=["read:account", "issue_refund:lt_500", "read:order_history"],
        ttl_seconds=300,
    )
    print(f"Parent issued: token_id={parent.token_id} scopes={parent.scopes}")

    # 2. Spawn a child agent — delegate a strict subset of the parent's scopes.
    #    The broker enforces subset semantics so a sub-agent cannot exceed the
    #    parent's authority.
    child = broker.delegate(
        parent_token_id=parent.token_id,
        requested_scopes=["read:account", "read:order_history"],
        session_id="child_agent_session",
    )
    print(
        f"Child issued: token_id={child.token_id} "
        f"scopes={child.scopes} delegation_depth={child.delegation_depth}"
    )

    # 3. Escalation attempt — request a scope the parent doesn't hold.
    #    CredentialBroker raises ValueError; the rogue child token is never
    #    created.
    try:
        broker.delegate(
            parent_token_id=parent.token_id,
            requested_scopes=["read:account", "lock_account"],
            session_id="rogue_child_session",
        )
        raise AssertionError("Delegation should have raised — escalation was not blocked")
    except ValueError as exc:
        print(f"Escalation blocked: {exc}")

    # 4. Revoke the child explicitly — for example, at sub-agent completion.
    #    revoke() is idempotent and only affects the named token.
    broker.revoke(child.token_id)

    # 5. Confirm: revoked child is now invalid; the parent's scopes are intact.
    #    Revocation does not cascade from child up to parent (or vice versa).
    print(
        f"Child revoked. validate(child) = {broker.validate(child.token_id)}  "
        f"validate(parent).scopes = {broker.validate(parent.token_id).scopes}"
    )


if __name__ == "__main__":
    main()
