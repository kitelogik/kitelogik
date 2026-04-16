# Run with: opa test policies/ -v
package kitelogik.delegation_test

import data.kitelogik.delegation
import future.keywords.if

# ── Depth cap (depth > 2 is always denied) ───────────────────────────────

test_deny_depth_3 if {
	delegation.deny with input as {
		"action": "read_customer_record",
		"args": {},
		"context": {"delegation_depth": 3, "session_id": "s1"},
	}
}

test_deny_depth_5 if {
	delegation.deny with input as {
		"action": "send_notification",
		"args": {},
		"context": {"delegation_depth": 5, "session_id": "s1"},
	}
}

test_allow_depth_0_non_refund if {
	not delegation.deny with input as {
		"action": "read_customer_record",
		"args": {},
		"context": {"delegation_depth": 0, "session_id": "s1"},
	}
}

test_allow_depth_1_non_refund if {
	not delegation.deny with input as {
		"action": "send_notification",
		"args": {},
		"context": {"delegation_depth": 1, "session_id": "s1"},
	}
}

test_allow_depth_2_non_refund if {
	# Depth 2 is permitted for non-refund actions
	not delegation.deny with input as {
		"action": "query_memory",
		"args": {},
		"context": {"delegation_depth": 2, "session_id": "s1"},
	}
}

test_allow_missing_depth_non_refund if {
	# Missing delegation_depth — undefined field evaluates as false in depth comparisons
	not delegation.deny with input as {
		"action": "read_customer_record",
		"args": {},
		"context": {"session_id": "s1"},
	}
}

# ── Depth-1 refund cap ($50) ──────────────────────────────────────────────

test_deny_depth1_refund_over_50 if {
	delegation.deny with input as {
		"action": "approve_refund",
		"args": {"amount": 51},
		"context": {"delegation_depth": 1, "session_id": "s1"},
	}
}

test_deny_depth1_refund_100 if {
	delegation.deny with input as {
		"action": "approve_refund",
		"args": {"amount": 100},
		"context": {"delegation_depth": 1, "session_id": "s1"},
	}
}

test_allow_depth1_refund_exactly_50 if {
	# Boundary: 50 is at the cap limit — should pass
	not delegation.deny with input as {
		"action": "approve_refund",
		"args": {"amount": 50},
		"context": {"delegation_depth": 1, "session_id": "s1"},
	}
}

test_allow_depth1_refund_under_50 if {
	not delegation.deny with input as {
		"action": "approve_refund",
		"args": {"amount": 25},
		"context": {"delegation_depth": 1, "session_id": "s1"},
	}
}

test_allow_depth0_refund_any_amount if {
	# Root session (depth 0) has no delegation cap
	not delegation.deny with input as {
		"action": "approve_refund",
		"args": {"amount": 999},
		"context": {"delegation_depth": 0, "session_id": "s1"},
	}
}

test_deny_depth1_string_amount if {
	# OPA structural type ordering: strings > numbers always.
	# "100" > 50 evaluates to TRUE because string > number in OPA's ordering.
	# This means string amounts are ALWAYS denied at depth 1 — a safe property
	# (no string can ever satisfy the numeric cap), but also a false-positive risk
	# if callers pass string amounts. Validated: real OPA enforces this.
	delegation.deny with input as {
		"action": "approve_refund",
		"args": {"amount": "100"},
		"context": {"delegation_depth": 1, "session_id": "s1"},
	}
}

test_deny_depth1_null_amount if {
	# null < 0 in OPA structural ordering → amount < 0 rule fires
	delegation.deny with input as {
		"action": "approve_refund",
		"args": {"amount": null},
		"context": {"delegation_depth": 1, "session_id": "s1"},
	}
}

test_deny_depth1_negative_amount if {
	# Negative amounts are below the cap but still invalid for refunds at depth-1
	delegation.deny with input as {
		"action": "approve_refund",
		"args": {"amount": -100},
		"context": {"delegation_depth": 1, "session_id": "s1"},
	}
}

test_deny_depth1_boolean_amount if {
	# boolean < number in OPA structural ordering → bool < 0 rule fires
	delegation.deny with input as {
		"action": "approve_refund",
		"args": {"amount": true},
		"context": {"delegation_depth": 1, "session_id": "s1"},
	}
}

# ── Depth-2+ no refunds at all ────────────────────────────────────────────

test_deny_depth2_any_refund if {
	delegation.deny with input as {
		"action": "approve_refund",
		"args": {"amount": 1},
		"context": {"delegation_depth": 2, "session_id": "s1"},
	}
}

test_deny_depth2_zero_amount_refund if {
	# Even a $0 refund is denied at depth 2 — action type matters, not amount
	delegation.deny with input as {
		"action": "approve_refund",
		"args": {"amount": 0},
		"context": {"delegation_depth": 2, "session_id": "s1"},
	}
}

test_deny_depth3_any_refund if {
	# Depth 3 hits both the depth cap AND the no-refund rule
	delegation.deny with input as {
		"action": "approve_refund",
		"args": {"amount": 1},
		"context": {"delegation_depth": 3, "session_id": "s1"},
	}
}

test_allow_depth1_non_refund_action if {
	# Depth 1 is only restricted for approve_refund > 50
	not delegation.deny with input as {
		"action": "read_customer_record",
		"args": {},
		"context": {"delegation_depth": 1, "session_id": "s1"},
	}
}

test_deny_depth2_string_amount_refund if {
	# Depth-2 rule blocks on action name alone (no amount comparison) — string amounts don't help
	delegation.deny with input as {
		"action": "approve_refund",
		"args": {"amount": "50"},
		"context": {"delegation_depth": 2, "session_id": "s1"},
	}
}
