# SPDX-License-Identifier: Apache-2.0
package kitelogik.agent_plan_test

import data.kitelogik.agent_plan
import future.keywords.if

test_allow_valid_plan if {
	agent_plan.allow with input as {
		"event_type": "agent.plan",
		"action": "agent.plan",
		"context": {"session_id": "s1", "user_role": "admin", "session_scopes": []},
		"steps": [
			{"tool_name": "read_file", "args": {"path": "/data/report.csv"}},
			{"tool_name": "summarize", "args": {"text": "..."}},
		],
	}
}

test_deny_empty_plan if {
	agent_plan.deny with input as {
		"event_type": "agent.plan",
		"action": "agent.plan",
		"context": {"session_id": "s1", "user_role": "admin", "session_scopes": []},
		"steps": [],
	}
}

test_deny_plan_too_many_steps if {
	# Build a plan with 51 steps (exceeds _max_steps=50)
	agent_plan.deny with input as {
		"event_type": "agent.plan",
		"action": "agent.plan",
		"context": {"session_id": "s1", "user_role": "admin", "session_scopes": []},
		"steps": [{"tool_name": "noop", "args": {}} | _ = numbers.range(1, 51)[_]],
	}
}

test_deny_plan_with_blocked_tool if {
	agent_plan.deny with input as {
		"event_type": "agent.plan",
		"action": "agent.plan",
		"context": {"session_id": "s1", "user_role": "admin", "session_scopes": []},
		"steps": [
			{"tool_name": "read_file", "args": {}},
			{"tool_name": "execute_shell", "args": {"cmd": "rm -rf /"}},
		],
	}
}

test_no_match_for_tool_call if {
	not agent_plan.allow with input as {
		"event_type": "tool_call",
		"action": "read_file",
		"context": {"session_id": "s1", "user_role": "admin", "session_scopes": []},
	}
}
