# SPDX-License-Identifier: Apache-2.0
package kitelogik.data_classification_test

import data.kitelogik.data_classification
import future.keywords.if

_primary_context := {
	"session_id": "s1",
	"user_role": "admin",
	"session_scopes": ["read", "write"],
	"delegation_depth": 0,
}

_delegated_context := {
	"session_id": "s2",
	"user_role": "worker",
	"session_scopes": ["read"],
	"delegation_depth": 1,
}

test_allow_no_classification if {
	data_classification.allow with input as {
		"data_classification": null,
		"context": _primary_context,
	}
}

test_allow_public_data if {
	data_classification.allow with input as {
		"data_classification": "public",
		"context": _primary_context,
	}
}

test_allow_internal_data if {
	data_classification.allow with input as {
		"data_classification": "internal",
		"context": _primary_context,
	}
}

test_allow_confidential_in_primary_session if {
	data_classification.allow with input as {
		"data_classification": "confidential",
		"context": _primary_context,
	}
}

test_deny_confidential_in_delegated_session if {
	data_classification.deny with input as {
		"data_classification": "confidential",
		"context": _delegated_context,
	}
}

test_allow_restricted_with_scope if {
	data_classification.allow with input as {
		"data_classification": "restricted",
		"context": {
			"session_id": "s1",
			"user_role": "admin",
			"session_scopes": ["read", "restricted_data"],
			"delegation_depth": 0,
		},
	}
}

test_deny_restricted_without_scope if {
	data_classification.deny with input as {
		"data_classification": "restricted",
		"context": _primary_context,
	}
}

test_allow_public_in_delegated_session if {
	data_classification.allow with input as {
		"data_classification": "public",
		"context": _delegated_context,
	}
}
