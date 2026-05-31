package kitelogik.financial

import future.keywords.if
import future.keywords.in

default allow := false

# Allow read-only customer and transaction lookups
allow if {
	input.action in {"read_customer_record", "list_transactions"}
	"read_customer" in input.context.session_scopes
}

# Allow low-value refunds for support agents and delegated workers with correct scope
allow if {
	input.action == "approve_refund"
	input.context.user_role in {"support_agent", "manager", "worker_agent"}
	"approve_refund_under_100" in input.context.session_scopes
	is_number(input.args.amount)
	input.args.amount >= 0
	input.args.amount <= 100
}

# Allow higher-value refunds for managers with elevated scope
allow if {
	input.action == "approve_refund"
	input.context.user_role == "manager"
	"approve_refund_under_1000" in input.context.session_scopes
	is_number(input.args.amount)
	input.args.amount >= 0
	input.args.amount <= 1000
}

# Allow notifications with correct scope
allow if {
	input.action == "send_notification"
	"send_notifications" in input.context.session_scopes
}

# Allow memory reads for any active session
allow if {
	input.action == "query_memory"
	input.context.session_id != ""
}

# Allow memory writes with explicit scope
allow if {
	input.action == "write_memory"
	"memory_write" in input.context.session_scopes
}

# Allow code execution inside a verified sandbox
allow if {
	input.action == "execute_code"
	input.context.sandbox_verified == true
}
