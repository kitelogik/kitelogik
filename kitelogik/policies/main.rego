package kitelogik.main

import data.kitelogik.agent_budget
import data.kitelogik.agent_lifecycle
import data.kitelogik.agent_plan
import data.kitelogik.data_classification
import data.kitelogik.delegation
import data.kitelogik.financial
import data.kitelogik.security
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

# High-value transactions always require human approval
requires_hitl if {
	risk_tier == "TRANSACTIONAL_HIGH"
}

# Denied (but non-security-critical, non-delegation) actions surface to human review
requires_hitl if {
	not allow
	not security.deny
	not delegation.deny
}
