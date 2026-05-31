# Run with: opa test policies/ -v
package kitelogik.userpolicy_test

import data.kitelogik.userpolicy
import future.keywords.if

# With no compiled YAML rules loaded, the stub leaves the package in a
# safe empty state: allow defaults to false, deny and hitl have no
# members. main.rego depends on this so an empty userpolicy contributes
# neither an allow, a deny, nor a HITL route.

test_default_allow_false if {
	userpolicy.allow == false
}

test_no_deny_by_default if {
	not _has_deny
}

test_no_hitl_by_default if {
	not _has_hitl
}

_has_deny if {
	some msg
	userpolicy.deny[msg]
}

_has_hitl if {
	some msg
	userpolicy.hitl[msg]
}
