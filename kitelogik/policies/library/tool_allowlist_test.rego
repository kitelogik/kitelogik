# SPDX-License-Identifier: Apache-2.0
package kitelogik.library.tool_allowlist_test

import data.kitelogik.library.tool_allowlist
import future.keywords.if

test_allow_listed_tool if {
	tool_allowlist.allow with input as {"tool_name": "read_file"}
}

test_allow_another_listed_tool if {
	tool_allowlist.allow with input as {"tool_name": "query_memory"}
}

test_deny_unlisted_tool if {
	not tool_allowlist.allow with input as {"tool_name": "execute_shell"}
}

test_deny_empty_tool_name if {
	not tool_allowlist.allow with input as {"tool_name": ""}
}
