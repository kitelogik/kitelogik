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
	not main.risk_tier == "SECURITY_CRITICAL" with input as {
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

# ── userpolicy aggregation (compiled YAML → kitelogik.userpolicy) ──────────
# userpolicy is mocked via `with` so these tests don't depend on a compiled
# policy file being present. They prove main.rego aggregates a user's
# compiled YAML the way the gate expects.

_clean_input := {
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

test_userpolicy_then_deny_hard_denies if {
	# `then: deny` in YAML must hard-block.
	main.deny with input as _clean_input
		with data.kitelogik.userpolicy as {"allow": false, "deny": {"blocked by user policy"}}
}

test_userpolicy_then_deny_does_not_route_to_hitl if {
	# The core fix: a `then: deny` is a hard deny, NOT a soft-deny → HITL.
	# Before this fix the soft-deny fallback caught it and escalated to a
	# human, so a deny that nobody approved would time through.
	not main.requires_hitl with input as _clean_input
		with data.kitelogik.userpolicy as {"allow": false, "deny": {"blocked by user policy"}}
}

test_userpolicy_then_hitl_routes_to_review if {
	# `then: hitl` escalates without hard-denying.
	main.requires_hitl with input as _clean_input
		with data.kitelogik.userpolicy as {"allow": false, "hitl": {"needs treasury approval"}}
}

test_userpolicy_then_hitl_does_not_hard_deny if {
	not main.deny with input as _clean_input
		with data.kitelogik.userpolicy as {"allow": false, "hitl": {"needs treasury approval"}}
}

test_userpolicy_then_allow_grants if {
	# `then: allow` grants even for an action no core sub-policy covers.
	main.allow with input as {
		"action": "generate_report",
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
		with data.kitelogik.userpolicy as {"allow": true}
}

test_userpolicy_deny_overrides_its_own_allow if {
	# A user policy that both allows and denies the same event must deny —
	# deny precedence holds for userpolicy just like the core sub-policies.
	main.deny with input as _clean_input
		with data.kitelogik.userpolicy as {"allow": true, "deny": {"blocked"}}
}

test_userpolicy_deny_blocks_allow if {
	not main.allow with input as _clean_input
		with data.kitelogik.userpolicy as {"allow": true, "deny": {"blocked"}}
}

test_userpolicy_deny_on_high_value_does_not_require_hitl if {
	# A high-value refund the user policy hard-denies must stay a pure
	# deny — the TRANSACTIONAL_HIGH HITL rule must not also fire, or the
	# decision is both "blocked" and "awaiting approval" at once.
	high_value_refund := {
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

	main.deny with input as high_value_refund
		with data.kitelogik.userpolicy as {"allow": false, "deny": {"over policy cap"}}
	not main.requires_hitl with input as high_value_refund
		with data.kitelogik.userpolicy as {"allow": false, "deny": {"over policy cap"}}
}

# ── deny_reason — accurate explanation per deny source ────────────────────

test_deny_reason_security if {
	main.deny_reason["Hard blocked by security policy"] with input as {
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

test_deny_reason_plan_blocked_tool if {
	main.deny_reason["Plan denied — exceeds the step limit or contains a blocked tool"] with input as {
		"event_type": "agent.plan",
		"action": "agent.plan",
		"args": {},
		"steps": [{"tool_name": "drop_database"}],
		"context": {
			"session_scopes": [],
			"user_role": "agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
}

test_deny_reason_budget if {
	main.deny_reason["Resource budget exhausted"] with input as {
		"event_type": "agent.budget",
		"action": "agent.budget",
		"args": {},
		"context": {
			"session_scopes": [],
			"user_role": "agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
			"budget_total_tokens": 100,
			"budget_used_tokens": 100,
		},
	}
}

test_deny_reason_userpolicy_carries_yaml_reason if {
	main.deny_reason["Refunds over 500 are blocked"] with input as {
		"action": "approve_refund",
		"resource_path": null,
		"args": {"amount": 900, "session_id": null},
		"context": {
			"session_scopes": [],
			"user_role": "agent",
			"session_id": "s1",
			"sandbox_verified": false,
			"delegation_depth": 0,
		},
	}
		with data.kitelogik.userpolicy as {"allow": false, "deny": {"Refunds over 500 are blocked"}}
}

test_no_deny_reason_when_allowed if {
	reasons := {r | some r; main.deny_reason[r]} with input as {
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
	count(reasons) == 0
}
