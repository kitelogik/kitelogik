# SPDX-License-Identifier: Apache-2.0
# Starter Policy: Read-Only Mode
#
# Allows read operations, denies all writes. Useful for agents that should
# only observe and report, never modify state.
#
# Usage: Copy to policies/ and customize _read_tools and _write_tools.

package kitelogik.library.read_only

import future.keywords.if
import future.keywords.in

default allow := false
default deny := false

_read_tools := {
	"read_file",
	"list_directory",
	"search_code",
	"query_memory",
	"read_customer_record",
	"list_transactions",
	"get_status",
}

_write_tools := {
	"write_file",
	"delete_file",
	"write_memory",
	"approve_refund",
	"send_email",
	"execute_code",
	"execute_shell",
	"update_record",
	"create_record",
	"delete_record",
}

allow if {
	input.tool_name in _read_tools
}

deny if {
	input.tool_name in _write_tools
}
