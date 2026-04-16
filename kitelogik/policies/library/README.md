# Starter Policy Library

Ready-to-use OPA/Rego policies for common governance patterns. Copy any policy to `policies/` and customize to fit your needs.

## Policies

| Policy             | File                  | What It Does                                                             |
|--------------------|-----------------------|--------------------------------------------------------------------------|
| **Tool Allowlist** | `tool_allowlist.rego` | Only allows explicitly listed tools. Everything else is denied.          |
| **Rate Limiting**  | `rate_limiting.rego`  | Denies calls when the session's API call budget is exceeded.             |
| **PII Protection** | `pii_protection.rego` | Blocks PII-handling tools unless the session has the `handle_pii` scope. |
| **Read-Only Mode** | `read_only.rego`      | Allows reads, denies all writes. For observation-only agents.            |
| **Cost Cap**       | `cost_cap.rego`       | Denies actions when the session's cost budget is exhausted.              |

## Usage

1. Copy the policy file to `policies/`:
   ```bash
   cp policies/library/tool_allowlist.rego policies/
   ```

2. Edit the policy to match your requirements (e.g., update `_allowed_tools`).

3. Import it in `policies/main.rego`:
   ```rego
   import data.kitelogik.library.tool_allowlist
   ```

4. Run OPA tests to verify:
   ```bash
   opa test kitelogik/policies/ -v
   ```

## Writing Your Own

Every policy should:

- Start with `default allow := false` (deny-by-default)
- Use `import future.keywords.if` and `import future.keywords.in`
- Include a `_test.rego` file with at least 3 test cases
- Document what it does in a comment header
