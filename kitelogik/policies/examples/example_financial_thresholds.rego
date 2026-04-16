# ─────────────────────────────────────────────────────────────────────────────
# example_financial_thresholds.rego
#
# What this does:
#   Controls which monetary transactions an agent can approve, and at what
#   amounts — without any prompting. The thresholds are enforced by OPA at
#   the infrastructure level. The model cannot override them.
#
# Threshold tiers (customise to match your business rules):
#   $0–$100      Auto-approved   support_agent or manager with correct scope
#   $100–$1,000  Auto-approved   manager only, elevated scope required
#   > $1,000     HITL escalated  no agent role can auto-approve; human must decide
#
# To use:
#   1. Copy to policies/financial.rego (or load alongside it)
#   2. Adjust the threshold values and role names to match your org
#   3. Test: python -m kitelogik.policy_tester --policy policies/financial.rego \
#            --input policies/examples/test_financial.json
#
# OPA input schema:
#   {
#     "action":  "approve_refund",          -- the tool being called
#     "args":    { "amount": 250.0 },       -- tool arguments
#     "context": {
#       "user_role":       "support_agent", -- role assigned at session creation
#       "session_scopes":  ["approve_refund_under_100"]  -- scopes on the token
#     }
#   }
# ─────────────────────────────────────────────────────────────────────────────

package kitelogik.examples.financial

import future.keywords.if
import future.keywords.in

# ── REQUIRED: deny-by-default ─────────────────────────────────────────────────
# All rules must be additive (allow IF conditions). Never use default allow := true.
default allow := false

# ── Tier 1: auto-approve small refunds ($0–$100) ─────────────────────────────
# Conditions that ALL must hold:
#   - The action is a refund
#   - The agent's session token carries the correct scope
#   - The agent's role is authorised for auto-approval
#   - The amount is within the tier limit
allow if {
    input.action == "approve_refund"

    # The scope must be explicitly granted at session creation.
    # Agents cannot grant themselves scopes.
    "approve_refund_under_100" in input.context.session_scopes

    # Role check: both support agents and managers can auto-approve tier 1
    input.context.user_role in {"support_agent", "manager"}

    # Amount must be a number and within the $100 ceiling
    is_number(input.args.amount)
    input.args.amount >= 0
    input.args.amount <= 100    # ← change this threshold to match your policy
}

# ── Tier 2: auto-approve larger refunds ($100–$1,000) ────────────────────────
# Only managers with an elevated scope can auto-approve tier 2.
# support_agent cannot reach this rule even with the right scope.
allow if {
    input.action == "approve_refund"
    "approve_refund_under_1000" in input.context.session_scopes
    input.context.user_role == "manager"   # ← tighten to specific manager sub-roles if needed
    is_number(input.args.amount)
    input.args.amount > 100
    input.args.amount <= 1000   # ← change this threshold to match your policy
}

# ── Tier 3: amounts above $1,000 ─────────────────────────────────────────────
# No allow rule covers amounts > $1,000, so OPA returns allow=false.
# The Kite Logik gate treats no-allow + hitl_trigger as HITL escalation
# (see main.rego hitl rule). A human must approve or deny in the dashboard.

# ── Read-only tools ───────────────────────────────────────────────────────────
# Agents with read_customer scope can look up records — no approval needed.
allow if {
    input.action in {"list_transactions", "get_customer_record"}
    "read_customer" in input.context.session_scopes
}

# ── Notifications ─────────────────────────────────────────────────────────────
allow if {
    input.action == "send_notification"
    "send_notifications" in input.context.session_scopes
}

# ── Common mistakes ────────────────────────────────────────────────────────────
#
# MISTAKE 1: Forgetting is_number() lets malformed input reach amount comparisons.
#   BAD:   input.args.amount <= 100
#   GOOD:  is_number(input.args.amount); input.args.amount <= 100
#
# MISTAKE 2: Using default allow := true for a "permissive mode" test.
#   This disables the deny-by-default guarantee entirely. Test with real inputs
#   instead. The tester CLI makes this easy.
#
# MISTAKE 3: Overlapping tiers with no gap between them.
#   Tier 1 ends at 100, Tier 2 starts at > 100. If you use >= on both sides
#   an amount of exactly 100 matches neither rule. Use > on one side.
#
# MISTAKE 4: Relying only on amount — forgetting to check the scope.
#   A session token might have the wrong scope but the right amount. Always
#   check both scope AND amount. The combination is the actual business rule.

# ── Embedded OPA tests (run with: opa test policies/examples/ -v) ──────────────

test_tier1_allow_support_agent if {
    allow with input as {
        "action": "approve_refund",
        "args": {"amount": 50},
        "context": {
            "user_role": "support_agent",
            "session_scopes": ["approve_refund_under_100"],
        },
    }
}

test_tier1_deny_wrong_scope if {
    not allow with input as {
        "action": "approve_refund",
        "args": {"amount": 50},
        "context": {
            "user_role": "support_agent",
            "session_scopes": ["read_customer"],
        },
    }
}

test_tier2_allow_manager if {
    allow with input as {
        "action": "approve_refund",
        "args": {"amount": 500},
        "context": {
            "user_role": "manager",
            "session_scopes": ["approve_refund_under_1000"],
        },
    }
}

test_tier2_deny_support_agent if {
    not allow with input as {
        "action": "approve_refund",
        "args": {"amount": 500},
        "context": {
            "user_role": "support_agent",
            "session_scopes": ["approve_refund_under_1000"],
        },
    }
}

test_over_threshold_no_allow if {
    # Amounts over $1,000 have no allow rule — gate escalates to HITL
    not allow with input as {
        "action": "approve_refund",
        "args": {"amount": 5000},
        "context": {
            "user_role": "manager",
            "session_scopes": ["approve_refund_under_1000"],
        },
    }
}

test_read_action_allowed if {
    allow with input as {
        "action": "list_transactions",
        "args": {},
        "context": {
            "user_role": "support_agent",
            "session_scopes": ["read_customer"],
        },
    }
}

test_unknown_action_denied if {
    not allow with input as {
        "action": "delete_all_records",
        "args": {},
        "context": {
            "user_role": "manager",
            "session_scopes": ["approve_refund_under_1000", "read_customer"],
        },
    }
}
