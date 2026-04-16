# SPDX-License-Identifier: Apache-2.0
package kitelogik.agent_lifecycle

import future.keywords.if
import future.keywords.in
import future.keywords.every

default allow := false
default deny := false

# --- agent.spawn rules ---

# Allow spawn when within depth limit and capabilities are valid
allow if {
	input.event_type == "agent.spawn"
	input.context.delegation_depth <= 2
	_capabilities_valid
}

# Deny spawn when delegation depth exceeds limit
deny if {
	input.event_type == "agent.spawn"
	input.context.delegation_depth > 2
}

# Deny spawn when requesting capabilities not in session scopes
deny if {
	input.event_type == "agent.spawn"
	not _capabilities_valid
	count(input.requested_capabilities) > 0
}

# --- agent.delegate rules ---

# Allow delegation when within depth limit and requested scopes are subset of parent
allow if {
	input.event_type == "agent.delegate"
	input.context.delegation_depth <= 1
	_delegate_scopes_valid
}

# Deny delegation that would exceed depth limit
deny if {
	input.event_type == "agent.delegate"
	input.context.delegation_depth > 1
}

# Deny delegation with scopes not in parent's session_scopes
deny if {
	input.event_type == "agent.delegate"
	not _delegate_scopes_valid
	count(input.requested_capabilities) > 0
}

# --- helpers ---

# All requested capabilities must be in the session's scopes
_capabilities_valid if {
	every cap in input.requested_capabilities {
		cap in input.context.session_scopes
	}
}

# Delegation: all requested capabilities must be subset of parent scopes
_delegate_scopes_valid if {
	every scope in input.requested_capabilities {
		scope in input.context.session_scopes
	}
}
