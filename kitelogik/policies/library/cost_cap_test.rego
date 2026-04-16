# SPDX-License-Identifier: Apache-2.0
package kitelogik.library.cost_cap_test

import data.kitelogik.library.cost_cap
import future.keywords.if

test_allow_no_budget if {
	cost_cap.allow with input as {
		"context": {"budget_total_cost_cents": null, "budget_used_cost_cents": null},
	}
}

test_allow_within_budget if {
	cost_cap.allow with input as {
		"context": {"budget_total_cost_cents": 1000, "budget_used_cost_cents": 500},
	}
}

test_deny_budget_exhausted if {
	cost_cap.deny with input as {
		"context": {"budget_total_cost_cents": 1000, "budget_used_cost_cents": 1000},
	}
}

test_deny_budget_exceeded if {
	cost_cap.deny with input as {
		"context": {"budget_total_cost_cents": 1000, "budget_used_cost_cents": 1500},
	}
}
