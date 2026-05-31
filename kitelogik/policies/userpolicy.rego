package kitelogik.userpolicy

import future.keywords.if
import future.keywords.in

# Compiled YAML policies (`kitelogik compile`) land in this package.
# This stub guarantees the package always resolves so main.rego can
# aggregate userpolicy.allow / userpolicy.deny / userpolicy.hitl even
# when no YAML has been compiled yet.
#
# Compiled files add incremental `allow if {...}` rules and set-valued
# `deny[reason] if {...}` / `hitl[reason] if {...}` rules into this same
# package. This file owns the `allow` default so those compiled files
# stay defaults-free and therefore merge without conflict. `deny` and
# `hitl` are left undefined-when-empty (idiomatic partial sets) — the
# same pattern main.rego already relies on for the other sub-policies.

default allow := false
