# SPDX-License-Identifier: Apache-2.0
package kitelogik.agent_lifecycle_test

import data.kitelogik.agent_lifecycle
import future.keywords.if

# --- agent.spawn tests ---

test_allow_spawn_within_depth_limit if {
	agent_lifecycle.allow with input as {
		"event_type": "agent.spawn",
		"action": "agent.spawn",
		"context": {
			"session_id": "s1",
			"user_role": "admin",
			"session_scopes": ["read", "write"],
			"delegation_depth": 0,
		},
		"requested_capabilities": ["read"],
	}
}

test_allow_spawn_at_depth_2 if {
	agent_lifecycle.allow with input as {
		"event_type": "agent.spawn",
		"action": "agent.spawn",
		"context": {
			"session_id": "s1",
			"user_role": "admin",
			"session_scopes": ["read"],
			"delegation_depth": 2,
		},
		"requested_capabilities": ["read"],
	}
}

test_deny_spawn_exceeding_depth if {
	agent_lifecycle.deny with input as {
		"event_type": "agent.spawn",
		"action": "agent.spawn",
		"context": {
			"session_id": "s1",
			"user_role": "admin",
			"session_scopes": ["read"],
			"delegation_depth": 3,
		},
		"requested_capabilities": ["read"],
	}
}

test_deny_spawn_unauthorized_capabilities if {
	agent_lifecycle.deny with input as {
		"event_type": "agent.spawn",
		"action": "agent.spawn",
		"context": {
			"session_id": "s1",
			"user_role": "worker",
			"session_scopes": ["read"],
			"delegation_depth": 0,
		},
		"requested_capabilities": ["write", "delete"],
	}
}

test_allow_spawn_empty_capabilities if {
	agent_lifecycle.allow with input as {
		"event_type": "agent.spawn",
		"action": "agent.spawn",
		"context": {
			"session_id": "s1",
			"user_role": "worker",
			"session_scopes": ["read"],
			"delegation_depth": 0,
		},
		"requested_capabilities": [],
	}
}

# --- agent.delegate tests ---

test_allow_delegate_within_depth if {
	agent_lifecycle.allow with input as {
		"event_type": "agent.delegate",
		"action": "agent.delegate",
		"context": {
			"session_id": "s1",
			"user_role": "admin",
			"session_scopes": ["read", "write", "approve_refund"],
			"delegation_depth": 0,
		},
		"requested_capabilities": ["read"],
	}
}

test_deny_delegate_exceeding_depth if {
	agent_lifecycle.deny with input as {
		"event_type": "agent.delegate",
		"action": "agent.delegate",
		"context": {
			"session_id": "s1",
			"user_role": "admin",
			"session_scopes": ["read"],
			"delegation_depth": 2,
		},
		"requested_capabilities": ["read"],
	}
}

test_deny_delegate_scope_escalation if {
	agent_lifecycle.deny with input as {
		"event_type": "agent.delegate",
		"action": "agent.delegate",
		"context": {
			"session_id": "s1",
			"user_role": "worker",
			"session_scopes": ["read"],
			"delegation_depth": 0,
		},
		"requested_capabilities": ["write", "delete"],
	}
}

# --- no-match tests ---

test_no_allow_for_tool_call_event if {
	not agent_lifecycle.allow with input as {
		"event_type": "tool_call",
		"action": "read_file",
		"context": {
			"session_id": "s1",
			"user_role": "admin",
			"session_scopes": ["read"],
			"delegation_depth": 0,
		},
	}
}
