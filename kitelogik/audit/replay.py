# SPDX-License-Identifier: Apache-2.0
"""
PolicyReplayer — re-evaluate historical audit records against the current policy.

Used for:
  - Compliance testing: verify that policy changes don't silently alter past decisions
  - Policy development: preview the blast radius of a proposed Rego change before deploy
  - Incident investigation: determine which historical calls a new rule would have blocked

Usage:
    replayer = PolicyReplayer(gate)
    results = await replayer.replay_session(audit_store, session_id)
    changed = [r for r in results if r.outcome_changed]
    print(f"{len(changed)} decisions would differ under the current policy")
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from kitelogik.tether.models import SessionContext, ToolCallInput

if TYPE_CHECKING:
    from kitelogik.audit.store import AuditRecord, AuditStore
    from kitelogik.tether.gate import PolicyGate


@dataclass
class ReplayResult:
    record_id: str
    tool_name: str
    args: dict
    session_id: str
    timestamp: str
    original_outcome: str
    original_risk_tier: str | None
    replayed_outcome: str
    replayed_risk_tier: str | None
    replayed_reason: str | None
    outcome_changed: bool


def _decision_to_outcome(decision) -> str:
    """Map a PolicyDecision to the canonical outcome vocabulary."""
    if decision.deny:
        return "denied"
    if decision.requires_hitl:
        return "pending_review"
    return "allowed"


class PolicyReplayer:
    """
    Re-evaluates historical audit records against the live policy gate.

    Each record is submitted to PolicyGate.evaluate_tool_call() using the
    original session context reconstructed from the stored context_json.
    The replayed decision is compared to the recorded outcome so callers
    can identify any records where the current policy would decide differently.

    The gate's OPA instance must be reachable at replay time; if OPA is
    unavailable, evaluate_tool_call() will return a deny-all decision and
    every non-denied record will show as outcome_changed=True.
    """

    def __init__(self, gate: "PolicyGate") -> None:
        self._gate = gate

    async def replay_record(self, record: "AuditRecord") -> ReplayResult:
        """Re-evaluate a single audit record against the current policy."""
        ctx = record.context
        context = SessionContext(
            session_id=ctx.get("session_id", ""),
            user_role=ctx.get("user_role", "agent"),
            session_scopes=ctx.get("session_scopes", []),
            token_id=ctx.get("token_id", ""),
            delegation_depth=ctx.get("delegation_depth", 0),
            parent_token_id=ctx.get("parent_token_id", ""),
            sandbox_verified=ctx.get("sandbox_verified", False),
        )
        tool_call = ToolCallInput(
            action=record.tool_name,
            tool_name=record.tool_name,
            args=record.args,
            resource_path=None,
        )

        decision = await self._gate.evaluate_tool_call(tool_call, context)
        replayed_outcome = _decision_to_outcome(decision)
        original_risk_tier = record.policy_decision.get("risk_tier")
        replayed_risk_tier = decision.risk_tier.value if decision.risk_tier else None

        return ReplayResult(
            record_id=record.id,
            tool_name=record.tool_name,
            args=record.args,
            session_id=record.session_id,
            timestamp=record.timestamp,
            original_outcome=record.outcome,
            original_risk_tier=original_risk_tier,
            replayed_outcome=replayed_outcome,
            replayed_risk_tier=replayed_risk_tier,
            replayed_reason=decision.reason,
            outcome_changed=(record.outcome != replayed_outcome),
        )

    async def replay_session(
        self,
        audit_store: "AuditStore",
        session_id: str,
    ) -> list[ReplayResult]:
        """
        Replay all records for a session against the current policy.

        Returns results in chronological order (oldest first).
        """
        records = await audit_store.query(session_id=session_id, limit=10_000)
        # query() returns newest-first; reverse for chronological replay
        records = list(reversed(records))
        return [await self.replay_record(r) for r in records]

    async def replay_records(
        self,
        records: "list[AuditRecord]",
    ) -> list[ReplayResult]:
        """Replay an arbitrary list of audit records (e.g. from export_session)."""
        return [await self.replay_record(r) for r in records]
