# SPDX-License-Identifier: Apache-2.0
package kitelogik.agent_budget_test

import data.kitelogik.agent_budget
import future.keywords.if

_base_context := {
	"session_id": "s1",
	"user_role": "admin",
	"session_scopes": [],
	"delegation_depth": 0,
}

test_allow_no_budget_set if {
	agent_budget.allow with input as {
		"event_type": "agent.budget",
		"action": "agent.budget",
		"context": object.union(_base_context, {
			"budget_total_tokens": null,
			"budget_used_tokens": null,
			"budget_total_api_calls": null,
			"budget_used_api_calls": null,
			"budget_total_cost_cents": null,
			"budget_used_cost_cents": null,
		}),
	}
}

test_allow_within_token_budget if {
	agent_budget.allow with input as {
		"event_type": "agent.budget",
		"action": "agent.budget",
		"context": object.union(_base_context, {
			"budget_total_tokens": 10000,
			"budget_used_tokens": 5000,
			"budget_total_api_calls": null,
			"budget_used_api_calls": null,
			"budget_total_cost_cents": null,
			"budget_used_cost_cents": null,
		}),
	}
}

test_deny_token_budget_exhausted if {
	agent_budget.deny with input as {
		"event_type": "agent.budget",
		"action": "agent.budget",
		"context": object.union(_base_context, {
			"budget_total_tokens": 10000,
			"budget_used_tokens": 10000,
			"budget_total_api_calls": null,
			"budget_used_api_calls": null,
			"budget_total_cost_cents": null,
			"budget_used_cost_cents": null,
		}),
	}
}

test_deny_token_budget_exceeded if {
	agent_budget.deny with input as {
		"event_type": "agent.budget",
		"action": "agent.budget",
		"context": object.union(_base_context, {
			"budget_total_tokens": 10000,
			"budget_used_tokens": 12000,
			"budget_total_api_calls": null,
			"budget_used_api_calls": null,
			"budget_total_cost_cents": null,
			"budget_used_cost_cents": null,
		}),
	}
}

test_deny_cost_budget_exhausted if {
	agent_budget.deny with input as {
		"event_type": "agent.budget",
		"action": "agent.budget",
		"context": object.union(_base_context, {
			"budget_total_tokens": null,
			"budget_used_tokens": null,
			"budget_total_api_calls": null,
			"budget_used_api_calls": null,
			"budget_total_cost_cents": 500,
			"budget_used_cost_cents": 500,
		}),
	}
}

test_deny_api_call_budget_exhausted if {
	agent_budget.deny with input as {
		"event_type": "agent.budget",
		"action": "agent.budget",
		"context": object.union(_base_context, {
			"budget_total_tokens": null,
			"budget_used_tokens": null,
			"budget_total_api_calls": 100,
			"budget_used_api_calls": 100,
			"budget_total_cost_cents": null,
			"budget_used_cost_cents": null,
		}),
	}
}

test_deny_tool_call_when_budget_exhausted if {
	agent_budget.deny with input as {
		"event_type": "tool_call",
		"action": "read_file",
		"context": object.union(_base_context, {
			"budget_total_tokens": 10000,
			"budget_used_tokens": 10000,
			"budget_total_api_calls": null,
			"budget_used_api_calls": null,
			"budget_total_cost_cents": null,
			"budget_used_cost_cents": null,
		}),
	}
}

test_no_deny_tool_call_within_budget if {
	not agent_budget.deny with input as {
		"event_type": "tool_call",
		"action": "read_file",
		"context": object.union(_base_context, {
			"budget_total_tokens": 10000,
			"budget_used_tokens": 5000,
			"budget_total_api_calls": null,
			"budget_used_api_calls": null,
			"budget_total_cost_cents": null,
			"budget_used_cost_cents": null,
		}),
	}
}
