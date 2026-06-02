# Industry Starter Templates

Domain-shaped YAML policies to start from instead of a blank page. Unlike
the Rego modules in [`../policies/library/`](../policies/library/) (which
you copy and `import` into `main.rego`), a template is a complete
**`policy.yaml`** — drop it in and compile.

| Template | File | What it governs |
|---|---|---|
| **Financial refunds** | `financial-refunds.yaml` | Tiers refunds by amount (allow / human-review / deny), blocks sanctioned destinations. |
| **Healthcare PHI access** | `healthcare-phi-access.yaml` | Clinician-gated record reads, human sign-off on record changes, hard-block on special-category (GDPR Art. 9) queries. |
| **Code-execution restrictions** | `code-execution-restrictions.yaml` | Blocks shell/eval and raw network egress, confines file writes to a workspace, gates `execute_code` on a scope. |

## Use one

```bash
kitelogik init my-agent
cp "$(python -c 'import kitelogik, os; print(os.path.dirname(kitelogik.__file__))')/policy_templates/financial-refunds.yaml" \
   my-agent/policies/policy.yaml
cd my-agent
kitelogik compile policies/policy.yaml      # → policies/policy.rego
```

Then edit the thresholds, roles, scopes, and action names to match your
business. The compiled rules land in the `kitelogik.userpolicy` package
and are aggregated by the core bundle alongside the built-in security,
delegation, and HITL policies.

## How the outcomes map

Each rule's `then:` is one of:

- `allow` — the action runs.
- `hitl` — routed to a human reviewer (`requires_hitl`); the action does
  not run until approved.
- `deny` — hard-blocked; no human can override it.

Anything a template does not explicitly allow or deny falls through to
the soft-deny → human-review fallback in `main.rego`, so gaps fail safe.

## Limits to know

- The YAML frontend matches on `action`, `role` (→ `user_role`), `scope`
  (→ `session_scopes`), and `args` fields. It cannot yet read arbitrary
  `context` fields. The code-execution template's `execute_code` grant,
  for example, pairs with the core security module's `sandbox_verified`
  check — the scope is the policy-side half; the verified-sandbox flag is
  enforced in Rego. Both must hold.
- `risk_tier:` set in YAML is parsed but not yet honored by the gate, so
  the templates don't use it. Risk tiers come from `main.rego`.

For the full YAML reference, see the "Writing Policies" section of the
project README.
