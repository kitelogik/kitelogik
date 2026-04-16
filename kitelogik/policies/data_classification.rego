# SPDX-License-Identifier: Apache-2.0
package kitelogik.data_classification

import future.keywords.if
import future.keywords.in

default allow := false
default deny := false

# Allow when no classification is set
allow if {
	input.data_classification == null
}

# Allow public data always
allow if {
	input.data_classification == "public"
}

# Allow internal data in any session
allow if {
	input.data_classification == "internal"
}

# Allow confidential data only in primary sessions (not delegated)
allow if {
	input.data_classification == "confidential"
	input.context.delegation_depth == 0
}

# Allow restricted data only when the session has the "restricted_data" scope
allow if {
	input.data_classification == "restricted"
	"restricted_data" in input.context.session_scopes
}

# Deny confidential data in delegated sessions
deny if {
	input.data_classification == "confidential"
	input.context.delegation_depth > 0
}

# Deny restricted data without the required scope
deny if {
	input.data_classification == "restricted"
	not "restricted_data" in input.context.session_scopes
}
