# SPDX-License-Identifier: Apache-2.0
# Starter Policy: PII Protection
#
# Blocks tools that handle PII unless the session has the "handle_pii" scope.
# Customize `_pii_tools` to match your data-handling tools.
#
# Usage: Copy to policies/ and edit _pii_tools.

package kitelogik.library.pii_protection

import future.keywords.if
import future.keywords.in

default allow := false
default deny := false

# Tools that handle personally identifiable information
_pii_tools := {
	"export_customer_data",
	"send_email_with_customer_info",
	"generate_report_with_names",
	"lookup_ssn",
	"query_personal_records",
}

# Allow PII tools only with explicit scope
allow if {
	input.tool_name in _pii_tools
	"handle_pii" in input.context.session_scopes
}

# Allow non-PII tools always (from this policy's perspective)
allow if {
	not input.tool_name in _pii_tools
}

# Deny PII tools without scope
deny if {
	input.tool_name in _pii_tools
	not "handle_pii" in input.context.session_scopes
}
