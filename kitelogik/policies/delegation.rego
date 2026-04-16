package kitelogik.delegation

import future.keywords.if
import future.keywords.in

default deny := false

# Hard cap: no delegation chain deeper than 2
deny if {
	input.context.delegation_depth > 2
}

# Depth-1 delegates (direct sub-agents): refund cap is $50
deny if {
	input.action == "approve_refund"
	input.context.delegation_depth == 1
	input.args.amount > 50
}

# Depth-1 delegates: non-numeric and negative amounts are always blocked.
# OPA structural ordering (null < bool < number) means null and booleans satisfy
# `amount > 50` as FALSE, silently bypassing the cap. Negative amounts likewise.
# This rule catches all three cases: `null < 0`, `false < 0`, `true < 0`, `-n < 0`.
deny if {
	input.action == "approve_refund"
	input.context.delegation_depth == 1
	input.args.amount < 0
}

# Depth-2+ delegates: no refunds at all
deny if {
	input.action == "approve_refund"
	input.context.delegation_depth >= 2
}
