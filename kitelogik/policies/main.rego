package kitelogik.main

import data.kitelogik.agent_budget
import data.kitelogik.agent_lifecycle
import data.kitelogik.agent_plan
import data.kitelogik.data_classification
import data.kitelogik.delegation
import data.kitelogik.financial
import data.kitelogik.security
import data.kitelogik.userpolicy
import future.keywords.if
import future.keywords.in

default allow := false

default deny := false

default risk_tier := "OPERATIONAL"

default requires_hitl := false

# Hard deny from security policy overrides all allow rules
deny if {
	security.deny
}

# Delegation depth/scope restrictions
deny if {
	delegation.deny
}

# Allow if a sub-policy grants access and security does not deny
allow if {
	not deny
	financial.allow
}

# Allow if the compiled user policy (kitelogik.userpolicy) grants access
allow if {
	not deny
	userpolicy.allow
}

# Propagate user-policy hard denies (`then: deny` in YAML). The compiler
# emits set-valued `deny[reason] if {...}`; iterating membership keeps
# this type-safe whether or not the set has members.
deny if {
	some msg
	userpolicy.deny[msg]
}

# Propagate user-policy HITL routes (`then: hitl` in YAML). Routes the
# action to human review without hard-denying it.
requires_hitl if {
	some msg
	userpolicy.hitl[msg]
}

# --- Agent lifecycle event routing ---

# Route agent.spawn and agent.delegate to agent_lifecycle policy
allow if {
	not deny
	input.event_type in {"agent.spawn", "agent.delegate"}
	agent_lifecycle.allow
}

deny if {
	input.event_type in {"agent.spawn", "agent.delegate"}
	agent_lifecycle.deny
}

# Route agent.plan to agent_plan policy
allow if {
	not deny
	input.event_type == "agent.plan"
	agent_plan.allow
}

deny if {
	input.event_type == "agent.plan"
	agent_plan.deny
}

# Route agent.budget to agent_budget policy
allow if {
	not deny
	input.event_type == "agent.budget"
	agent_budget.allow
}

deny if {
	input.event_type == "agent.budget"
	agent_budget.deny
}

# Budget enforcement on tool_call events (deny if budget exhausted)
deny if {
	agent_budget.deny
}

# Data classification enforcement (any event type)
allow if {
	not deny
	data_classification.allow
}

deny if {
	data_classification.deny
}

# --- Deny reasons ---
# Human-readable reasons for a hard deny, surfaced in PolicyDecision.reason.
# Mirrors the deny rules above so a denied action carries an accurate
# explanation instead of a generic fallback. A deny with no matching reason
# here still denies — the Python layer falls back to a generic message.

# User-policy (compiled YAML) carries its own `reason:` strings.
deny_reason[msg] if {
	some msg
	userpolicy.deny[msg]
}

deny_reason["Hard blocked by security policy"] if {
	security.deny
}

deny_reason["Delegation denied — exceeds depth limit or requests a scope the parent does not hold"] if {
	delegation.deny
}

deny_reason["Agent lifecycle denied — spawn/delegate exceeds the depth limit or requests an ungranted capability"] if {
	input.event_type in {"agent.spawn", "agent.delegate"}
	agent_lifecycle.deny
}

deny_reason["Plan denied — exceeds the step limit or contains a blocked tool"] if {
	input.event_type == "agent.plan"
	agent_plan.deny
}

deny_reason["Resource budget exhausted"] if {
	agent_budget.deny
}

deny_reason["Data classification policy denied this flow"] if {
	data_classification.deny
}

# --- Risk tier classification ---

risk_tier := "SECURITY_CRITICAL" if {
	security.deny
}

risk_tier := "SECURITY_CRITICAL" if {
	delegation.deny
}

risk_tier := "TRANSACTIONAL_HIGH" if {
	not security.deny
	not delegation.deny
	input.action == "approve_refund"
	is_number(input.args.amount)
	input.args.amount > 100
}

risk_tier := "TRANSACTIONAL_LOW" if {
	not security.deny
	not delegation.deny
	input.action == "approve_refund"
	is_number(input.args.amount)
	input.args.amount <= 100
}

risk_tier := "INFORMATIONAL" if {
	not security.deny
	not delegation.deny
	input.action in {"read_customer_record", "list_transactions", "query_memory"}
}

# --- HITL escalation rules ---

# High-value transactions require human approval — unless the action is
# already denied, in which case the deny stands and there is nothing for
# a human to approve. Keeps deny and requires_hitl from both being true.
requires_hitl if {
	not deny
	risk_tier == "TRANSACTIONAL_HIGH"
}

# Soft-deny fallback: actions that are neither allowed nor explicitly
# hard-denied surface to human review, so policy gaps fail safe rather
# than silently deny. An explicit user-policy `then: deny` is a hard
# deny, not a gap, so it is excluded here — alongside the security and
# delegation hard denies — and stays a pure deny with no HITL route.
requires_hitl if {
	not allow
	not security.deny
	not delegation.deny
	not _userpolicy_hard_deny
}

_userpolicy_hard_deny if {
	some msg
	userpolicy.deny[msg]
}
