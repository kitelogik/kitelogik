# Run with: opa test policies/ -v
package kitelogik.financial_test

import data.kitelogik.financial
import future.keywords.if

# ── Read customer record / list transactions ──────────────────────────────

test_allow_read_customer_record if {
	financial.allow with input as {
		"action": "read_customer_record",
		"args": {},
		"context": {
			"session_scopes": ["read_customer"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_allow_list_transactions if {
	financial.allow with input as {
		"action": "list_transactions",
		"args": {},
		"context": {
			"session_scopes": ["read_customer"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_deny_read_customer_record_missing_scope if {
	not financial.allow with input as {
		"action": "read_customer_record",
		"args": {},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_deny_list_transactions_empty_scopes if {
	not financial.allow with input as {
		"action": "list_transactions",
		"args": {},
		"context": {
			"session_scopes": [],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

# ── Low-value refunds (approve_refund_under_100) ──────────────────────────

test_allow_refund_support_agent_under_100 if {
	financial.allow with input as {
		"action": "approve_refund",
		"args": {"amount": 50},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_allow_refund_support_agent_exactly_100 if {
	# Boundary: 100 is allowed (rule uses <=)
	financial.allow with input as {
		"action": "approve_refund",
		"args": {"amount": 100},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_allow_refund_manager_under_100 if {
	financial.allow with input as {
		"action": "approve_refund",
		"args": {"amount": 75},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "manager",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_deny_refund_support_agent_over_100 if {
	# 101 exceeds the low-value limit and support_agent has no high-value scope
	not financial.allow with input as {
		"action": "approve_refund",
		"args": {"amount": 101},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_deny_refund_wrong_role if {
	# "analyst" is not in the allowed role set
	not financial.allow with input as {
		"action": "approve_refund",
		"args": {"amount": 50},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "analyst",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_deny_refund_missing_scope if {
	not financial.allow with input as {
		"action": "approve_refund",
		"args": {"amount": 50},
		"context": {
			"session_scopes": ["read_customer"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_deny_refund_string_amount if {
	# String "50" fails is_number() guard — type mismatch does not grant access
	not financial.allow with input as {
		"action": "approve_refund",
		"args": {"amount": "50"},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_deny_refund_null_amount if {
	# null passes `null <= 100` (OPA structural: null < number) without is_number guard
	not financial.allow with input as {
		"action": "approve_refund",
		"args": {"amount": null},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_deny_refund_boolean_amount if {
	# true passes `true <= 100` (OPA structural: bool < number) without is_number guard
	not financial.allow with input as {
		"action": "approve_refund",
		"args": {"amount": true},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_deny_refund_negative_amount if {
	# Negative amounts satisfy `amount <= 100` without the >= 0 guard
	not financial.allow with input as {
		"action": "approve_refund",
		"args": {"amount": -1},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_deny_refund_negative_amount_high_value if {
	not financial.allow with input as {
		"action": "approve_refund",
		"args": {"amount": -999},
		"context": {
			"session_scopes": ["approve_refund_under_1000"],
			"user_role": "manager",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

# ── High-value refunds (approve_refund_under_1000) ────────────────────────

test_allow_refund_manager_under_1000 if {
	financial.allow with input as {
		"action": "approve_refund",
		"args": {"amount": 500},
		"context": {
			"session_scopes": ["approve_refund_under_1000"],
			"user_role": "manager",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_allow_refund_manager_exactly_1000 if {
	financial.allow with input as {
		"action": "approve_refund",
		"args": {"amount": 1000},
		"context": {
			"session_scopes": ["approve_refund_under_1000"],
			"user_role": "manager",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_deny_refund_support_agent_high_scope if {
	# support_agent is not allowed for the high-value rule
	not financial.allow with input as {
		"action": "approve_refund",
		"args": {"amount": 500},
		"context": {
			"session_scopes": ["approve_refund_under_1000"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_deny_refund_manager_over_1000 if {
	not financial.allow with input as {
		"action": "approve_refund",
		"args": {"amount": 1001},
		"context": {
			"session_scopes": ["approve_refund_under_1000"],
			"user_role": "manager",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

# ── Notifications ─────────────────────────────────────────────────────────

test_allow_send_notification if {
	financial.allow with input as {
		"action": "send_notification",
		"args": {},
		"context": {
			"session_scopes": ["send_notifications"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_deny_send_notification_missing_scope if {
	not financial.allow with input as {
		"action": "send_notification",
		"args": {},
		"context": {
			"session_scopes": ["read_customer"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_deny_send_notification_empty_scopes if {
	not financial.allow with input as {
		"action": "send_notification",
		"args": {},
		"context": {
			"session_scopes": [],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

# ── Memory reads ──────────────────────────────────────────────────────────

test_allow_query_memory if {
	financial.allow with input as {
		"action": "query_memory",
		"args": {},
		"context": {
			"session_scopes": [],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_deny_query_memory_empty_session_id if {
	# Empty session_id means no active session — deny
	not financial.allow with input as {
		"action": "query_memory",
		"args": {},
		"context": {
			"session_scopes": [],
			"user_role": "support_agent",
			"session_id": "",
			"sandbox_verified": false,
		},
	}
}

# ── Memory writes ─────────────────────────────────────────────────────────

test_allow_write_memory if {
	financial.allow with input as {
		"action": "write_memory",
		"args": {},
		"context": {
			"session_scopes": ["memory_write"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_deny_write_memory_missing_scope if {
	not financial.allow with input as {
		"action": "write_memory",
		"args": {},
		"context": {
			"session_scopes": ["read_customer"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

# ── Execute code in sandbox ───────────────────────────────────────────────

test_allow_execute_code_sandbox_verified if {
	financial.allow with input as {
		"action": "execute_code",
		"args": {},
		"context": {
			"session_scopes": [],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": true,
		},
	}
}

test_deny_execute_code_no_sandbox if {
	not financial.allow with input as {
		"action": "execute_code",
		"args": {},
		"context": {
			"session_scopes": [],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
		},
	}
}

test_deny_unknown_action if {
	not financial.allow with input as {
		"action": "delete_database",
		"args": {},
		"context": {
			"session_scopes": ["read_customer", "approve_refund_under_100", "send_notifications", "memory_write"],
			"user_role": "manager",
			"session_id": "s1",
			"sandbox_verified": true,
		},
	}
}

# ── Delegated worker_agent ────────────────────────────────────────────────────

test_allow_worker_agent_refund_under_cap if {
	financial.allow with input as {
		"action": "approve_refund",
		"args": {"amount": 30.0, "customer_id": "cust_002"},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "worker_agent",
			"session_id": "w1",
			"delegation_depth": 1,
			"sandbox_verified": false,
		},
	}
}

test_deny_worker_agent_refund_over_financial_cap if {
	not financial.allow with input as {
		"action": "approve_refund",
		"args": {"amount": 150.0, "customer_id": "cust_002"},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "worker_agent",
			"session_id": "w1",
			"delegation_depth": 1,
			"sandbox_verified": false,
		},
	}
}
