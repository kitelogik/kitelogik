# Run with: opa test policies/ -v
package kitelogik.security_test

import data.kitelogik.security
import future.keywords.if

# ── File extension blocking ───────────────────────────────────────────────

test_deny_env_file if {
	security.deny with input as {
		"action": "read_file",
		"resource_path": "/config/.env",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_pem_file if {
	security.deny with input as {
		"action": "read_file",
		"resource_path": "/certs/server.pem",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_key_file if {
	security.deny with input as {
		"action": "read_file",
		"resource_path": "/keys/id_rsa.key",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_secret_file if {
	security.deny with input as {
		"action": "read_file",
		"resource_path": "/vault/db.secret",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_crt_file if {
	security.deny with input as {
		"action": "read_file",
		"resource_path": "/tls/cert.crt",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_p12_file if {
	security.deny with input as {
		"action": "read_file",
		"resource_path": "/certs/client.p12",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_pfx_file if {
	security.deny with input as {
		"action": "read_file",
		"resource_path": "/certs/client.pfx",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_passwd_extension if {
	# .passwd extension (distinct from /etc/passwd path — the regex requires a dot prefix)
	security.deny with input as {
		"action": "read_file",
		"resource_path": "/backup/db.passwd",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_shadow_extension if {
	security.deny with input as {
		"action": "read_file",
		"resource_path": "/backup/auth.shadow",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_env_uppercase if {
	# Regex uses (?i) flag — case-insensitive
	security.deny with input as {
		"action": "read_file",
		"resource_path": "/config/app.ENV",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_allow_txt_file if {
	not security.deny with input as {
		"action": "read_file",
		"resource_path": "/data/report.txt",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_allow_json_file if {
	not security.deny with input as {
		"action": "read_file",
		"resource_path": "/config/settings.json",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_allow_py_file if {
	not security.deny with input as {
		"action": "read_file",
		"resource_path": "/app/main.py",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_allow_null_resource_path if {
	# Null resource_path skips both extension and path rules
	not security.deny with input as {
		"action": "read_file",
		"resource_path": null,
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

# ── System path blocking ──────────────────────────────────────────────────

test_deny_etc_path if {
	security.deny with input as {
		"action": "read_file",
		"resource_path": "/etc/hosts",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_etc_subdir if {
	security.deny with input as {
		"action": "read_file",
		"resource_path": "/etc/ssl/certs/ca-bundle.crt",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_proc_path if {
	security.deny with input as {
		"action": "read_file",
		"resource_path": "/proc/1/status",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_sys_path if {
	security.deny with input as {
		"action": "read_file",
		"resource_path": "/sys/kernel/debug",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_root_home if {
	security.deny with input as {
		"action": "read_file",
		"resource_path": "/root/.bashrc",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_var_run_path if {
	security.deny with input as {
		"action": "read_file",
		"resource_path": "/var/run/docker.sock",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_double_slash_etc_path if {
	# //etc/passwd bypassed the old `^/` regex — fixed by `^/+`
	security.deny with input as {
		"action": "read_file",
		"resource_path": "//etc/passwd",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_triple_slash_etc_path if {
	security.deny with input as {
		"action": "read_file",
		"resource_path": "///etc/shadow",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_env_mid_name_extension if {
	# file.env.bak bypassed `\.env$` — fixed by `\.env(\.|$)`
	security.deny with input as {
		"action": "read_file",
		"resource_path": "config/secrets.env.bak",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_key_mid_name_extension if {
	security.deny with input as {
		"action": "read_file",
		"resource_path": "/keys/id_rsa.key.backup",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_relative_path_traversal if {
	# ../../../etc/passwd bypassed `^/(etc|...)` — caught by new traversal rule
	security.deny with input as {
		"action": "read_file",
		"resource_path": "../../../etc/passwd",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_mid_path_traversal if {
	security.deny with input as {
		"action": "read_file",
		"resource_path": "/safe/subdir/../../etc/passwd",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_allow_home_user_path if {
	not security.deny with input as {
		"action": "read_file",
		"resource_path": "/home/user/data.csv",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_allow_var_log_path if {
	not security.deny with input as {
		"action": "read_file",
		"resource_path": "/var/log/app.log",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_allow_tmp_path if {
	not security.deny with input as {
		"action": "read_file",
		"resource_path": "/tmp/output.csv",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

# ── Code/shell execution without sandbox ─────────────────────────────────

test_deny_execute_shell_no_sandbox if {
	security.deny with input as {
		"action": "execute_shell",
		"resource_path": null,
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_run_command_no_sandbox if {
	security.deny with input as {
		"action": "run_command",
		"resource_path": null,
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_eval_code_no_sandbox if {
	security.deny with input as {
		"action": "eval_code",
		"resource_path": null,
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_deny_execute_code_no_sandbox if {
	security.deny with input as {
		"action": "execute_code",
		"resource_path": null,
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

test_allow_execute_code_with_sandbox if {
	# sandbox_verified=true lifts the execution block
	not security.deny with input as {
		"action": "execute_code",
		"resource_path": null,
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": true},
	}
}

test_allow_read_file_no_sandbox if {
	# read_file is not in the execution action set — sandbox not required
	not security.deny with input as {
		"action": "read_file",
		"resource_path": "/data/report.csv",
		"args": {},
		"context": {"session_id": "s1", "sandbox_verified": false},
	}
}

# ── Cross-session access ──────────────────────────────────────────────────

test_deny_cross_session if {
	security.deny with input as {
		"action": "query_memory",
		"resource_path": null,
		"args": {"session_id": "other-session"},
		"context": {"session_id": "my-session", "sandbox_verified": false},
	}
}

test_allow_same_session if {
	not security.deny with input as {
		"action": "query_memory",
		"resource_path": null,
		"args": {"session_id": "my-session"},
		"context": {"session_id": "my-session", "sandbox_verified": false},
	}
}

test_allow_null_args_session_id if {
	# Null session_id in args — condition `args.session_id != null` is false, rule skips
	not security.deny with input as {
		"action": "query_memory",
		"resource_path": null,
		"args": {"session_id": null},
		"context": {"session_id": "my-session", "sandbox_verified": false},
	}
}

test_allow_missing_args_session_id if {
	# No session_id in args at all — undefined field, rule does not fire
	not security.deny with input as {
		"action": "query_memory",
		"resource_path": null,
		"args": {},
		"context": {"session_id": "my-session", "sandbox_verified": false},
	}
}
