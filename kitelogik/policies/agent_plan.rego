# SPDX-License-Identifier: Apache-2.0
package kitelogik.agent_plan

import future.keywords.if
import future.keywords.in
import future.keywords.every

default allow := false
default deny := false

# Maximum number of steps allowed in a plan
_max_steps := 50

# Tools that are never allowed in any plan
_blocked_tools := {"execute_shell", "run_command", "drop_database", "delete_all"}

# Allow a plan when it has steps, is within the step limit, and contains no blocked tools
allow if {
	input.event_type == "agent.plan"
	count(input.steps) > 0
	count(input.steps) <= _max_steps
	not _has_blocked_tool
}

# Deny plans with no steps
deny if {
	input.event_type == "agent.plan"
	count(input.steps) == 0
}

# Deny plans exceeding the step limit
deny if {
	input.event_type == "agent.plan"
	count(input.steps) > _max_steps
}

# Deny plans containing blocked tools
deny if {
	input.event_type == "agent.plan"
	_has_blocked_tool
}

# --- helpers ---

_has_blocked_tool if {
	some step in input.steps
	step.tool_name in _blocked_tools
}
