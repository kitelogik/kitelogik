# ─────────────────────────────────────────────────────────────────────────────
# example_tool_allowlist.rego
#
# What this does:
#   Enforces a strict allowlist of which tools each agent type can call.
#   Any tool NOT on the list is blocked — the agent is structurally unable
#   to call it, regardless of what the model wants or what the prompt says.
#
# This is the first policy to load in a new deployment. Start here.
# Build role_tools for your agent types, then layer financial.rego and
# security.rego on top.
#
# Use cases:
#   - Customer-service bots that should never touch billing tools
#   - Read-only research agents that must not write anything
#   - Restricted workers spawned by an orchestrator at delegation depth > 0
#
# OPA input schema:
#   {
#     "action":  "approve_refund",
#     "context": {
#       "user_role":      "support_agent",
#       "session_scopes": ["read_customer"]
#     }
#   }
# ─────────────────────────────────────────────────────────────────────────────

package kitelogik.allowlist

import future.keywords.if
import future.keywords.in

default allow := false

# ── Tool allowlists per agent role ────────────────────────────────────────────
# Only tools listed here can be called by agents with that role.
# A tool absent from this list is implicitly denied — you do not need an
# explicit deny rule for it.

role_tools := {
    # Basic customer service — no money movement, no data writes
    "support_agent": {
        "get_customer_record",
        "list_transactions",
        "send_notification",
        "query_memory",
        "write_memory",
    },

    # Billing agent — can approve small refunds, cannot delete or execute code
    "billing_agent": {
        "get_customer_record",
        "list_transactions",
        "approve_refund",
        "update_billing_record",
        "send_notification",
        "query_memory",
        "write_memory",
    },

    # Read-only research agent — no side effects at all
    "research_agent": {
        "get_customer_record",
        "list_transactions",
        "query_memory",
        "fetch_web_page",        # read-only external tool
        "search_knowledge_base", # read-only internal tool
    },

    # Code execution agent — has sandbox, but cannot touch customer data
    "code_agent": {
        "execute_code",
        "read_file",    # within sandbox only; security.rego blocks sensitive paths
        "write_file",   # within sandbox only
        "query_memory",
        "write_memory",
    },

    # Orchestrator — can spawn workers and call coordination tools
    "orchestrator": {
        "get_customer_record",
        "list_transactions",
        "send_notification",
        "query_memory",
        "write_memory",
        "delegate_task",   # creates a child agent session
    },

    # Spawned worker agent (delegation depth >= 1) — minimal permissions
    # The orchestrator further restricts this via CredentialBroker.delegate()
    "worker_agent": {
        "get_customer_record",
        "list_transactions",
        "query_memory",
    },
}

# ── Core allow rule ───────────────────────────────────────────────────────────
# The action must appear in the role's allowlist.
# If the role has no entry in role_tools, nothing is allowed.
allow if {
    role  := input.context.user_role
    tools := role_tools[role]   # undefined if role not in map → rule body fails → deny
    input.action in tools
}

# ── Catch-all: unknown roles ──────────────────────────────────────────────────
# If the user_role is not in role_tools, allow remains false (default above).
# No explicit deny rule needed — absence of a matching allow is sufficient.

# ── How to add a new tool ─────────────────────────────────────────────────────
# 1. Add the tool name to the relevant role sets above
# 2. Add a scope check in example_role_based_access.rego if access should
#    require an explicit session scope (recommended for any sensitive tool)
# 3. Add an amount/risk-tier rule in example_financial_thresholds.rego if
#    the tool involves money or destructive operations
# 4. Test: python -m kitelogik.policy_tester \
#          --policy policies/examples/example_tool_allowlist.rego \
#          --input '{"action": "new_tool", "context": {"user_role": "support_agent"}}'

# ── Common mistakes ────────────────────────────────────────────────────────────
#
# MISTAKE 1: Adding a tool to role_tools but not adding it to the MCP server's
#   BOM (bill of materials). The allowlist controls whether the gate passes the
#   call, but the MCP client must also know the tool exists.
#
# MISTAKE 2: Giving worker_agent the same tool set as orchestrator.
#   Spawned workers should have a minimal set. The orchestrator further restricts
#   them via CredentialBroker.delegate() — the policy is a ceiling, not a floor.
#
# MISTAKE 3: Putting sensitive tools (execute_code, delete_*) in roles that
#   don't need them "just in case". Least-privilege means no speculative access.
#   If a role doesn't demonstrably need a tool today, don't add it.
#
# MISTAKE 4: Using a single "agent" role for everything. Fine for a demo,
#   not for production. Each distinct task type should have its own role with
#   its own tool set so a compromised session has minimal blast radius.

# ── Embedded OPA tests (run with: opa test policies/examples/ -v) ──────────────

test_support_agent_allowed_tool if {
    allow with input as {
        "action": "get_customer_record",
        "context": {"user_role": "support_agent"},
    }
}

test_support_agent_blocked_tool if {
    not allow with input as {
        "action": "execute_code",
        "context": {"user_role": "support_agent"},
    }
}

test_code_agent_can_execute if {
    allow with input as {
        "action": "execute_code",
        "context": {"user_role": "code_agent"},
    }
}

test_code_agent_cannot_read_customer if {
    not allow with input as {
        "action": "get_customer_record",
        "context": {"user_role": "code_agent"},
    }
}

test_research_agent_read_only if {
    allow with input as {
        "action": "fetch_web_page",
        "context": {"user_role": "research_agent"},
    }
}

test_research_agent_no_writes if {
    not allow with input as {
        "action": "write_memory",
        "context": {"user_role": "research_agent"},
    }
}

test_worker_minimal_set if {
    allow with input as {
        "action": "list_transactions",
        "context": {"user_role": "worker_agent"},
    }
}

test_worker_cannot_delegate if {
    not allow with input as {
        "action": "delegate_task",
        "context": {"user_role": "worker_agent"},
    }
}

test_unknown_role_denied if {
    not allow with input as {
        "action": "get_customer_record",
        "context": {"user_role": "rogue_agent"},
    }
}
