# SPDX-License-Identifier: Apache-2.0
package kitelogik.library.read_only_test

import data.kitelogik.library.read_only
import future.keywords.if

test_allow_read_file if {
	read_only.allow with input as {"tool_name": "read_file"}
}

test_allow_list_directory if {
	read_only.allow with input as {"tool_name": "list_directory"}
}

test_deny_write_file if {
	read_only.deny with input as {"tool_name": "write_file"}
}

test_deny_delete_file if {
	read_only.deny with input as {"tool_name": "delete_file"}
}

test_deny_execute_code if {
	read_only.deny with input as {"tool_name": "execute_code"}
}

test_no_match_unknown_tool if {
	not read_only.allow with input as {"tool_name": "unknown_tool"}
	not read_only.deny with input as {"tool_name": "unknown_tool"}
}
