# Run with: opa test policies/ -v
package kitelogik.main_test

import data.kitelogik.main
import future.keywords.if

# ── deny propagation ──────────────────────────────────────────────────────

test_deny_when_security_blocks if {
	# execute_code without sandbox_verified — security.deny fires
	main.deny with input as {
		"action": "execute_code",
		"resource_path": null,
		"args": {"session_id": null},
		"context": {
			"session_scopes": [],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_deny_when_security_blocks_path if {
	# Sensitive file path — security.deny fires
	main.deny with input as {
		"action": "read_file",
		"resource_path": "/etc/passwd",
		"args": {"session_id": null},
		"context": {
			"session_scopes": ["read_customer"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_deny_when_delegation_blocks_depth if {
	# Delegation depth > 2 — delegation.deny fires
	main.deny with input as {
		"action": "read_customer_record",
		"resource_path": null,
		"args": {"session_id": null},
		"context": {
			"session_scopes": ["read_customer"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 3,
		},
	}
}

test_deny_when_delegation_blocks_refund_cap if {
	# Depth-1 refund > $50 — delegation.deny fires
	main.deny with input as {
		"action": "approve_refund",
		"resource_path": null,
		"args": {"amount": 100, "session_id": null},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 1,
		},
	}
}

test_no_deny_clean_request if {
	not main.deny with input as {
		"action": "read_customer_record",
		"resource_path": null,
		"args": {"session_id": null},
		"context": {
			"session_scopes": ["read_customer"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

# ── allow propagation ─────────────────────────────────────────────────────

test_allow_when_financial_grants_read if {
	main.allow with input as {
		"action": "read_customer_record",
		"resource_path": null,
		"args": {"session_id": null},
		"context": {
			"session_scopes": ["read_customer"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_allow_when_financial_grants_low_refund if {
	main.allow with input as {
		"action": "approve_refund",
		"resource_path": null,
		"args": {"amount": 30, "session_id": null},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_no_allow_when_security_denies if {
	# security.deny=true sets main.deny=true which short-circuits allow
	not main.allow with input as {
		"action": "read_file",
		"resource_path": "/etc/passwd",
		"args": {"session_id": null},
		"context": {
			"session_scopes": ["read_customer"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_no_allow_when_delegation_denies if {
	# delegation.deny=true sets main.deny=true which short-circuits allow
	not main.allow with input as {
		"action": "approve_refund",
		"resource_path": null,
		"args": {"amount": 100, "session_id": null},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 3,
		},
	}
}

test_no_allow_when_no_financial_grant if {
	# No scope — financial.allow is false, main.allow stays false
	not main.allow with input as {
		"action": "approve_refund",
		"resource_path": null,
		"args": {"amount": 50, "session_id": null},
		"context": {
			"session_scopes": [],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

# ── risk_tier classification ──────────────────────────────────────────────

test_risk_tier_security_critical_for_security_deny if {
	main.risk_tier == "SECURITY_CRITICAL" with input as {
		"action": "execute_code",
		"resource_path": null,
		"args": {"session_id": null},
		"context": {
			"session_scopes": [],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_risk_tier_security_critical_for_delegation_deny if {
	main.risk_tier == "SECURITY_CRITICAL" with input as {
		"action": "approve_refund",
		"resource_path": null,
		"args": {"amount": 1, "session_id": null},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 3,
		},
	}
}

test_risk_tier_transactional_high if {
	# approve_refund > 100, no security/delegation deny
	main.risk_tier == "TRANSACTIONAL_HIGH" with input as {
		"action": "approve_refund",
		"resource_path": null,
		"args": {"amount": 500, "session_id": null},
		"context": {
			"session_scopes": ["approve_refund_under_1000"],
			"user_role": "manager",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_risk_tier_transactional_low if {
	# approve_refund <= 100, no security/delegation deny
	main.risk_tier == "TRANSACTIONAL_LOW" with input as {
		"action": "approve_refund",
		"resource_path": null,
		"args": {"amount": 50, "session_id": null},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_risk_tier_informational_read if {
	main.risk_tier == "INFORMATIONAL" with input as {
		"action": "read_customer_record",
		"resource_path": null,
		"args": {"session_id": null},
		"context": {
			"session_scopes": ["read_customer"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_risk_tier_informational_list_transactions if {
	main.risk_tier == "INFORMATIONAL" with input as {
		"action": "list_transactions",
		"resource_path": null,
		"args": {"session_id": null},
		"context": {
			"session_scopes": ["read_customer"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_risk_tier_informational_query_memory if {
	main.risk_tier == "INFORMATIONAL" with input as {
		"action": "query_memory",
		"resource_path": null,
		"args": {"session_id": null},
		"context": {
			"session_scopes": [],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_risk_tier_null_amount_falls_to_operational if {
	# null amount must NOT classify as TRANSACTIONAL_LOW via OPA structural ordering
	# (null <= 100 is TRUE in OPA — is_number() guard prevents this)
	main.risk_tier == "OPERATIONAL" with input as {
		"action": "approve_refund",
		"resource_path": null,
		"args": {"amount": null, "session_id": null},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_risk_tier_boolean_amount_falls_to_operational if {
	# false <= 100 is TRUE in OPA structural ordering — is_number() must block this
	main.risk_tier == "OPERATIONAL" with input as {
		"action": "approve_refund",
		"resource_path": null,
		"args": {"amount": false, "session_id": null},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_risk_tier_string_amount_falls_to_operational if {
	# String amount must not match either transactional tier
	main.risk_tier == "OPERATIONAL" with input as {
		"action": "approve_refund",
		"resource_path": null,
		"args": {"amount": "100", "session_id": null},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_risk_tier_operational_default if {
	# send_notification matches no specific risk tier rule — falls through to default
	main.risk_tier == "OPERATIONAL" with input as {
		"action": "send_notification",
		"resource_path": null,
		"args": {"session_id": null},
		"context": {
			"session_scopes": ["send_notifications"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_risk_tier_not_security_critical_when_allowed if {
	# A clean allowed action must NOT classify as SECURITY_CRITICAL
	not (main.risk_tier == "SECURITY_CRITICAL") with input as {
		"action": "read_customer_record",
		"resource_path": null,
		"args": {"session_id": null},
		"context": {
			"session_scopes": ["read_customer"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

# ── requires_hitl escalation ──────────────────────────────────────────────

test_hitl_for_transactional_high if {
	# High-value refund — allowed but still requires human review
	main.requires_hitl with input as {
		"action": "approve_refund",
		"resource_path": null,
		"args": {"amount": 500, "session_id": null},
		"context": {
			"session_scopes": ["approve_refund_under_1000"],
			"user_role": "manager",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_hitl_for_soft_deny if {
	# Not allowed by financial policy, but not a hard security/delegation block
	# Should surface to human review, not be silently dropped
	main.requires_hitl with input as {
		"action": "approve_refund",
		"resource_path": null,
		"args": {"amount": 50, "session_id": null},
		"context": {
			"session_scopes": [],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_no_hitl_for_security_deny if {
	# Hard security block — no human can approve a sandbox escape attempt
	not main.requires_hitl with input as {
		"action": "execute_code",
		"resource_path": null,
		"args": {"session_id": null},
		"context": {
			"session_scopes": [],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_no_hitl_for_delegation_deny if {
	# Hard delegation block — depth violations are not overridable via HITL
	not main.requires_hitl with input as {
		"action": "approve_refund",
		"resource_path": null,
		"args": {"amount": 1, "session_id": null},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 3,
		},
	}
}

test_no_hitl_for_allowed_low_risk_action if {
	# Allowed, low-risk read — should not trigger HITL
	not main.requires_hitl with input as {
		"action": "read_customer_record",
		"resource_path": null,
		"args": {"session_id": null},
		"context": {
			"session_scopes": ["read_customer"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_no_hitl_for_allowed_notification if {
	not main.requires_hitl with input as {
		"action": "send_notification",
		"resource_path": null,
		"args": {"session_id": null},
		"context": {
			"session_scopes": ["send_notifications"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

# ── Interaction: deny overrides allow ────────────────────────────────────

test_deny_overrides_financial_allow if {
	# Financial policy would allow this refund, but security.deny blocks it
	# because the resource_path hits the /etc prefix
	main.deny with input as {
		"action": "approve_refund",
		"resource_path": "/etc/refund_config",
		"args": {"amount": 50, "session_id": null},
		"context": {
			"session_scopes": ["approve_refund_under_100"],
			"user_role": "support_agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_security_critical_overrides_transactional_tier if {
	# Cross-session access attempt on a refund should be SECURITY_CRITICAL, not TRANSACTIONAL
	main.risk_tier == "SECURITY_CRITICAL" with input as {
		"action": "approve_refund",
		"resource_path": null,
		"args": {"amount": 500, "session_id": "other-session"},
		"context": {
			"session_scopes": ["approve_refund_under_1000"],
			"user_role": "manager",
			"session_id": "my-session",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}
