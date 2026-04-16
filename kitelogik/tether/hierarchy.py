# SPDX-License-Identifier: Apache-2.0
"""
2-tier policy hierarchy: global + project.

The HierarchicalEvaluator wraps two PolicyEvaluator backends and merges
their decisions with deny-overrides semantics:

    1. Global policies are evaluated first (org-wide security rules).
    2. Project policies are evaluated second (team/project-specific rules).
    3. A global deny always wins — project policies can only further restrict,
       never loosen.
    4. Every decision includes a resolution trace showing what each tier said.

Usage::

    from kitelogik.tether.hierarchy import HierarchicalEvaluator

    global_opa = OPAClient(base_url="http://opa:8181", package="kitelogik.global")
    project_opa = OPAClient(base_url="http://opa:8181", package="kitelogik.project")

    evaluator = HierarchicalEvaluator(
        global_evaluator=global_opa,
        project_evaluator=project_opa,
    )

    # Use as a drop-in PolicyEvaluator:
    gate = PolicyGate(opa_client=evaluator)
"""

from __future__ import annotations

import logging

from .models import (
    GovernanceEvent,
    PolicyDecision,
    PolicyEvaluator,
    PolicyInput,
    ResolutionStep,
    RiskTier,
)

logger = logging.getLogger(__name__)

# Risk tier severity ordering — higher index = more severe.
_RISK_SEVERITY = {
    RiskTier.INFORMATIONAL: 0,
    RiskTier.OPERATIONAL: 1,
    RiskTier.TRANSACTIONAL_LOW: 2,
    RiskTier.TRANSACTIONAL_HIGH: 3,
    RiskTier.DESTRUCTIVE: 4,
    RiskTier.SECURITY_CRITICAL: 5,
}


def _higher_risk(a: RiskTier, b: RiskTier) -> RiskTier:
    """Return the more severe of two risk tiers."""
    return a if _RISK_SEVERITY.get(a, 0) >= _RISK_SEVERITY.get(b, 0) else b


def _merge_decisions(
    global_d: PolicyDecision,
    project_d: PolicyDecision,
) -> PolicyDecision:
    """Merge two policy decisions with deny-overrides semantics.

    Rules
    -----
    - If either tier denies, the merged result is deny.
    - Allow requires both tiers to allow (or the denying tier to not deny).
    - Risk tier is the higher of the two.
    - HITL required if either tier requires it.
    - Resolution trace records what each tier decided.

    Parameters
    ----------
    global_d : PolicyDecision
            Decision from the global (org-wide) policy tier.
    project_d : PolicyDecision
            Decision from the project-specific policy tier.

    Returns
    -------
    PolicyDecision
            Merged decision with resolution trace.
    """
    trace = [
        ResolutionStep(
            tier="global",
            allow=global_d.allow,
            deny=global_d.deny,
            risk_tier=global_d.risk_tier.value,
            reason=global_d.reason,
            rule_matched=global_d.rule_matched,
        ),
        ResolutionStep(
            tier="project",
            allow=project_d.allow,
            deny=project_d.deny,
            risk_tier=project_d.risk_tier.value,
            reason=project_d.reason,
            rule_matched=project_d.rule_matched,
        ),
    ]

    # Deny-overrides: either tier can deny, neither can un-deny.
    merged_deny = global_d.deny or project_d.deny
    # Allow requires: not denied, and at least one tier allows.
    merged_allow = not merged_deny and (global_d.allow or project_d.allow)
    merged_risk = _higher_risk(global_d.risk_tier, project_d.risk_tier)
    merged_hitl = global_d.requires_hitl or project_d.requires_hitl

    # Build reason from the most relevant tier.
    if global_d.deny:
        reason = f"[global] {global_d.reason}"
        rule_matched = global_d.rule_matched
    elif project_d.deny:
        reason = f"[project] {project_d.reason}"
        rule_matched = project_d.rule_matched
    elif merged_allow:
        # Prefer the tier that explicitly allowed.
        if global_d.allow:
            reason = f"[global] {global_d.reason}"
            rule_matched = global_d.rule_matched
        else:
            reason = f"[project] {project_d.reason}"
            rule_matched = project_d.rule_matched
    else:
        reason = f"[global] {global_d.reason}"
        rule_matched = global_d.rule_matched

    return PolicyDecision(
        allow=merged_allow,
        deny=merged_deny,
        risk_tier=merged_risk,
        requires_hitl=merged_hitl,
        reason=reason,
        rule_matched=rule_matched,
        resolution_trace=trace,
    )


class HierarchicalEvaluator:
    """2-tier policy evaluator: global policies + project policies.

    Implements the ``PolicyEvaluator`` protocol so it can be used as a
    drop-in replacement anywhere a ``PolicyEvaluator`` is expected.

    Parameters
    ----------
    global_evaluator : PolicyEvaluator
            Evaluator for org-wide global policies.
    project_evaluator : PolicyEvaluator
            Evaluator for project/team-specific policies.
    """

    def __init__(
        self,
        global_evaluator: PolicyEvaluator,
        project_evaluator: PolicyEvaluator,
    ) -> None:
        self._global = global_evaluator
        self._project = project_evaluator

    async def health(self) -> bool:
        """Both evaluators must be healthy."""
        g = await self._global.health()
        p = await self._project.health()
        return g and p

    async def evaluate(self, policy_input: PolicyInput) -> PolicyDecision:
        """Evaluate against both tiers and merge with deny-overrides."""
        global_d = await self._global.evaluate(policy_input)

        # Short-circuit: if global hard-denies, skip project evaluation.
        if global_d.deny:
            logger.debug("Global policy denied — skipping project evaluation")
            return PolicyDecision(
                allow=False,
                deny=True,
                risk_tier=global_d.risk_tier,
                requires_hitl=global_d.requires_hitl,
                reason=f"[global] {global_d.reason}",
                rule_matched=global_d.rule_matched,
                resolution_trace=[
                    ResolutionStep(
                        tier="global",
                        allow=global_d.allow,
                        deny=global_d.deny,
                        risk_tier=global_d.risk_tier.value,
                        reason=global_d.reason,
                        rule_matched=global_d.rule_matched,
                    ),
                    ResolutionStep(
                        tier="project",
                        allow=False,
                        deny=False,
                        risk_tier=RiskTier.OPERATIONAL.value,
                        reason="Skipped — global deny",
                    ),
                ],
            )

        project_d = await self._project.evaluate(policy_input)
        return _merge_decisions(global_d, project_d)

    async def evaluate_event(self, event: GovernanceEvent) -> PolicyDecision:
        """Evaluate a governance event against both tiers."""
        global_d = await self._global.evaluate_event(event)

        if global_d.deny:
            logger.debug("Global policy denied event — skipping project evaluation")
            return PolicyDecision(
                allow=False,
                deny=True,
                risk_tier=global_d.risk_tier,
                requires_hitl=global_d.requires_hitl,
                reason=f"[global] {global_d.reason}",
                rule_matched=global_d.rule_matched,
                resolution_trace=[
                    ResolutionStep(
                        tier="global",
                        allow=global_d.allow,
                        deny=global_d.deny,
                        risk_tier=global_d.risk_tier.value,
                        reason=global_d.reason,
                        rule_matched=global_d.rule_matched,
                    ),
                    ResolutionStep(
                        tier="project",
                        allow=False,
                        deny=False,
                        risk_tier=RiskTier.OPERATIONAL.value,
                        reason="Skipped — global deny",
                    ),
                ],
            )

        project_d = await self._project.evaluate_event(event)
        return _merge_decisions(global_d, project_d)
