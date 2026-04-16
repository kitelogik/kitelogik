# SPDX-License-Identifier: Apache-2.0
package kitelogik.agent_budget

import future.keywords.if

default allow := false
default deny := false

# Allow when no budget is set (all budget fields are null/absent)
allow if {
	input.event_type == "agent.budget"
	not _has_any_budget
}

# Allow when all set budgets are within limits
allow if {
	input.event_type == "agent.budget"
	_has_any_budget
	not _token_budget_exhausted
	not _api_call_budget_exhausted
	not _cost_budget_exhausted
}

# Deny when token budget is exhausted
deny if {
	input.event_type == "agent.budget"
	_token_budget_exhausted
}

# Deny when API call budget is exhausted
deny if {
	input.event_type == "agent.budget"
	_api_call_budget_exhausted
}

# Deny when cost budget is exhausted
deny if {
	input.event_type == "agent.budget"
	_cost_budget_exhausted
}

# --- Also check budget on tool_call events if budget fields are present ---

deny if {
	input.event_type == "tool_call"
	_token_budget_exhausted
}

deny if {
	input.event_type == "tool_call"
	_api_call_budget_exhausted
}

deny if {
	input.event_type == "tool_call"
	_cost_budget_exhausted
}

# --- helpers ---

_has_any_budget if {
	input.context.budget_total_tokens != null
}

_has_any_budget if {
	input.context.budget_total_api_calls != null
}

_has_any_budget if {
	input.context.budget_total_cost_cents != null
}

_token_budget_exhausted if {
	input.context.budget_total_tokens != null
	input.context.budget_used_tokens != null
	input.context.budget_used_tokens >= input.context.budget_total_tokens
}

_api_call_budget_exhausted if {
	input.context.budget_total_api_calls != null
	input.context.budget_used_api_calls != null
	input.context.budget_used_api_calls >= input.context.budget_total_api_calls
}

_cost_budget_exhausted if {
	input.context.budget_total_cost_cents != null
	input.context.budget_used_cost_cents != null
	input.context.budget_used_cost_cents >= input.context.budget_total_cost_cents
}
