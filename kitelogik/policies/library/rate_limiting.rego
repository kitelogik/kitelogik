# SPDX-License-Identifier: Apache-2.0
# Starter Policy: Rate Limiting
#
# Denies tool calls when the session's API call budget is exceeded.
# Requires budget_total_api_calls and budget_used_api_calls on the context.
#
# Usage: Set budget fields on SessionContext before creating the agent session.

package kitelogik.library.rate_limiting

import future.keywords.if

default allow := false
default deny := false

# Default max calls per session (override via context budget fields)
_max_calls := 200

# Allow when no budget is set
allow if {
	input.context.budget_total_api_calls == null
}

# Allow when within budget
allow if {
	input.context.budget_total_api_calls != null
	input.context.budget_used_api_calls != null
	input.context.budget_used_api_calls < input.context.budget_total_api_calls
}

# Deny when budget exhausted
deny if {
	input.context.budget_total_api_calls != null
	input.context.budget_used_api_calls != null
	input.context.budget_used_api_calls >= input.context.budget_total_api_calls
}
