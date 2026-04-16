# SPDX-License-Identifier: Apache-2.0
package kitelogik.library.rate_limiting_test

import data.kitelogik.library.rate_limiting
import future.keywords.if

test_allow_no_budget_set if {
	rate_limiting.allow with input as {
		"context": {"budget_total_api_calls": null, "budget_used_api_calls": null},
	}
}

test_allow_within_budget if {
	rate_limiting.allow with input as {
		"context": {"budget_total_api_calls": 100, "budget_used_api_calls": 50},
	}
}

test_deny_budget_exhausted if {
	rate_limiting.deny with input as {
		"context": {"budget_total_api_calls": 100, "budget_used_api_calls": 100},
	}
}

test_deny_budget_exceeded if {
	rate_limiting.deny with input as {
		"context": {"budget_total_api_calls": 100, "budget_used_api_calls": 150},
	}
}
