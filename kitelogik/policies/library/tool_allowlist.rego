# SPDX-License-Identifier: Apache-2.0
# Starter Policy: Tool Allowlist
#
# Only allows tool calls that are explicitly listed. Everything else is denied.
# Customize `_allowed_tools` to match your agent's required capabilities.
#
# Usage: Copy to policies/ and edit _allowed_tools.

package kitelogik.library.tool_allowlist

import future.keywords.if
import future.keywords.in

default allow := false

# Add the tool names your agent is permitted to call
_allowed_tools := {
	"read_file",
	"write_file",
	"list_directory",
	"search_code",
	"query_memory",
	"write_memory",
}

allow if {
	input.tool_name in _allowed_tools
}
