# SPDX-License-Identifier: Apache-2.0
package kitelogik.library.pii_protection_test

import data.kitelogik.library.pii_protection
import future.keywords.if

test_allow_pii_tool_with_scope if {
	pii_protection.allow with input as {
		"tool_name": "export_customer_data",
		"context": {"session_scopes": ["read", "handle_pii"]},
	}
}

test_deny_pii_tool_without_scope if {
	pii_protection.deny with input as {
		"tool_name": "export_customer_data",
		"context": {"session_scopes": ["read"]},
	}
}

test_allow_non_pii_tool if {
	pii_protection.allow with input as {
		"tool_name": "read_file",
		"context": {"session_scopes": ["read"]},
	}
}

test_deny_lookup_ssn_without_scope if {
	pii_protection.deny with input as {
		"tool_name": "lookup_ssn",
		"context": {"session_scopes": ["read"]},
	}
}
