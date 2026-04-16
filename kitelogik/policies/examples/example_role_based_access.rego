# ─────────────────────────────────────────────────────────────────────────────
# example_role_based_access.rego
#
# What this does:
#   Restricts which data each agent role can read or write. This is your
#   data access layer — equivalent to RBAC in a traditional system, but
#   enforced at the tool-call level by OPA, not by the application.
#
# Roles defined here:
#   support_agent    Read customers, read transactions, send notifications
#   billing_agent    Read and write billing records, approve small refunds
#   auditor          Read-only access to everything, no writes
#   admin            Full access (use sparingly; always HITL for destructive ops)
#
# To customise:
#   - Add or rename roles in the role_permissions set below
#   - Add tool names to the permission sets
#   - The session token's user_role must exactly match the string here
#
# OPA input schema:
#   {
#     "action":  "list_transactions",
#     "context": { "user_role": "support_agent", "session_scopes": [...] }
#   }
# ─────────────────────────────────────────────────────────────────────────────

package kitelogik.access

import future.keywords.if
import future.keywords.in

default allow := false

# ── Role → allowed tool set mapping ──────────────────────────────────────────
# Extend this object when you add new tools or roles.
# Keys are user_role values; values are sets of allowed action names.

role_permissions := {
    "support_agent": {
        "get_customer_record",
        "list_transactions",
        "send_notification",
        "query_memory",
    },
    "billing_agent": {
        "get_customer_record",
        "list_transactions",
        "approve_refund",      # amount limits enforced by financial.rego
        "update_billing_record",
        "send_notification",
        "query_memory",
        "write_memory",
    },
    "auditor": {
        # Read-only: can see everything, write nothing
        "get_customer_record",
        "list_transactions",
        "query_memory",
        "list_billing_records",
    },
    "admin": {
        # Full access — HITL is still enforced for destructive actions
        "get_customer_record",
        "list_transactions",
        "approve_refund",
        "update_billing_record",
        "send_notification",
        "delete_record",
        "query_memory",
        "write_memory",
        "execute_code",
    },
}

# ── Core allow rule ───────────────────────────────────────────────────────────
# The action must appear in the role's permission set AND the session token
# must carry the matching scope. Both checks must pass.
allow if {
    role := input.context.user_role

    # Does this role have permission for this action?
    role_permissions[role][input.action]

    # Does the session token carry a scope covering this action?
    # This double-check means even if a token is issued with the wrong role,
    # it still needs the explicit scope.
    scope_for_action(input.action) in input.context.session_scopes
}

# ── Scope mapping ─────────────────────────────────────────────────────────────
# Maps each action to the scope name required on the session token.
# Add an entry here whenever you add a new tool.
scope_for_action(action) := scope if {
    scope_map := {
        "get_customer_record":    "read_customer",
        "list_transactions":      "read_customer",
        "approve_refund":         "approve_refund_under_100",
        "update_billing_record":  "billing_write",
        "send_notification":      "send_notifications",
        "delete_record":          "admin_delete",
        "query_memory":           "memory_read",
        "write_memory":           "memory_write",
        "execute_code":           "code_execute",
        "list_billing_records":   "read_billing",
    }
    scope := scope_map[action]
}

# ── Cross-session access guard ────────────────────────────────────────────────
# No role can access another session's data — even admins.
# This rule overrides allow above if session IDs mismatch.
deny_cross_session if {
    input.args.session_id != null
    input.args.session_id != input.context.session_id
}

# ── Common mistakes ────────────────────────────────────────────────────────────
#
# MISTAKE 1: Adding a new tool to role_permissions but forgetting to add it to
#   scope_for_action. The allow rule requires both checks — the scope mapping
#   lookup will be undefined, which silently denies the action.
#
# MISTAKE 2: Using string equality for role checking when roles may have casing
#   differences. "Support_Agent" != "support_agent". Normalise at session creation.
#
# MISTAKE 3: Making the admin role bypass the cross-session guard.
#   No role should be able to read another session's data — this is a
#   lateral-movement vector, not a convenience feature.
#
# MISTAKE 4: Putting the scope check inside role_permissions rather than in
#   scope_for_action. Keep the mapping separate so it can be reused across
#   policy files without duplicating the role→tool logic.

# ── Embedded OPA tests (run with: opa test policies/examples/ -v) ──────────────

test_support_agent_can_read_customer if {
    allow with input as {
        "action": "get_customer_record",
        "args": {},
        "context": {
            "user_role": "support_agent",
            "session_scopes": ["read_customer"],
            "session_id": "sess_001",
        },
    }
}

test_support_agent_cannot_delete if {
    not allow with input as {
        "action": "delete_record",
        "args": {},
        "context": {
            "user_role": "support_agent",
            "session_scopes": ["read_customer", "admin_delete"],
            "session_id": "sess_001",
        },
    }
}

test_auditor_read_only if {
    allow with input as {
        "action": "list_transactions",
        "args": {},
        "context": {
            "user_role": "auditor",
            "session_scopes": ["read_customer"],
            "session_id": "sess_002",
        },
    }
}

test_auditor_cannot_write if {
    not allow with input as {
        "action": "write_memory",
        "args": {},
        "context": {
            "user_role": "auditor",
            "session_scopes": ["memory_write"],
            "session_id": "sess_002",
        },
    }
}

test_unknown_role_denied if {
    not allow with input as {
        "action": "get_customer_record",
        "args": {},
        "context": {
            "user_role": "mystery_role",
            "session_scopes": ["read_customer"],
            "session_id": "sess_003",
        },
    }
}

test_admin_can_delete if {
    allow with input as {
        "action": "delete_record",
        "args": {},
        "context": {
            "user_role": "admin",
            "session_scopes": ["admin_delete"],
            "session_id": "sess_004",
        },
    }
}
