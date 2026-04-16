package kitelogik.security

import future.keywords.if

default deny := false

# Hard block: sensitive file extensions (including mid-name, e.g. file.env.bak)
deny if {
	input.resource_path != null
	regex.match(`(?i)\.(env|pem|key|secret|crt|p12|pfx|passwd|shadow)(\.|$)`, input.resource_path)
}

# Hard block: sensitive system paths (handles double-slash prefix, e.g. //etc/passwd)
deny if {
	input.resource_path != null
	regex.match(`^/+(etc|proc|sys|root|var/run)(/|$)`, input.resource_path)
}

# Hard block: path traversal sequences (e.g. ../../../etc/passwd, /safe/../escape)
deny if {
	input.resource_path != null
	regex.match(`(^|/)\.\.(/|$)`, input.resource_path)
}

# Hard block: code/shell execution without a verified sandbox
deny if {
	input.action in {"execute_shell", "run_command", "eval_code", "execute_code"}
	not input.context.sandbox_verified
}

# Hard block: accessing another session's namespace
deny if {
	input.args.session_id != null
	input.args.session_id != input.context.session_id
}
