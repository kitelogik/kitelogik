# SPDX-License-Identifier: Apache-2.0
# Starter Policy: Cost Cap
#
# Denies actions when the session's cost budget is exhausted.
# Requires budget_total_cost_cents and budget_used_cost_cents on the context.
#
# Usage: Set budget_total_cost_cents on SessionContext to enforce a spending limit.

package kitelogik.library.cost_cap

import future.keywords.if

default allow := false
default deny := false

# Allow when no cost budget is configured
allow if {
	input.context.budget_total_cost_cents == null
}

# Allow when within cost budget
allow if {
	input.context.budget_total_cost_cents != null
	input.context.budget_used_cost_cents != null
	input.context.budget_used_cost_cents < input.context.budget_total_cost_cents
}

# Deny when cost budget exhausted
deny if {
	input.context.budget_total_cost_cents != null
	input.context.budget_used_cost_cents != null
	input.context.budget_used_cost_cents >= input.context.budget_total_cost_cents
}
