# Contributing to Kite Logik

Thank you for contributing. This guide covers everything you need to make a successful contribution — from first setup to getting your PR merged.

## Table of Contents

- [Development Setup](#development-setup)
- [What We Accept](#what-we-accept)
- [Adding a Policy Rule](#adding-a-policy-rule) ← start here
- [Worked Example: healthcare.rego](#worked-example-healthcarerego)
- [Code Style](#code-style)
- [Running Tests](#running-tests)
- [Pull Request Process](#pull-request-process)

---

## Development Setup

```bash
git clone https://github.com/kitelogik/kitelogik.git
cd kitelogik

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
docker compose up -d opa           # start OPA policy engine

cp .env.example .env               # add ANTHROPIC_API_KEY if you need the LLM demo
```

Verify everything works:

```bash
pytest -q                          # 681+ unit tests, no Docker required
opa test kitelogik/policies/ -v              # OPA embedded tests (requires opa binary)
kitelogik compliance               # governance compliance audit
```

**Policy engine for local development:** Start OPA with `docker compose up -d opa`. This is the recommended path for running tests and the quickstart.

---

## What We Accept

| Type | Welcome? | Notes |
|---|:---:|---|
| New OPA policy rules (Rego or YAML) | Yes | Must have OPA tests + Python integration test |
| New framework adapter | Yes | Must inherit `BaseGovernedAdapter`, include tests |
| Bug fixes | Yes | Include a test that would have caught the bug |
| Performance improvements | Yes | Include benchmark numbers |
| New sanitizer patterns | Yes | Include a test with the injection payload |
| New demo scenarios | Yes | Should demonstrate a non-obvious governance case |
| Dependency additions | Ask first | Open an issue before adding new packages |
| Architectural changes | Ask first | Discuss in an issue before writing code |

---

## Adding a Policy Rule

This is the highest-value contribution type. You can write policies in **YAML** (simpler) or **Rego** (full control).

### Option A: YAML policy (no Rego required)

```
1. Create a YAML file in kitelogik/policies/ (see kitelogik/policies/examples/example_rules.yaml)
2. Compile to Rego: kitelogik compile kitelogik/policies/your_rules.yaml
3. Validate: kitelogik validate
4. Run: opa test kitelogik/policies/ -v
5. Add a Python integration test in tests/test_gate.py
6. Run: pytest tests/test_gate.py -v
7. Submit PR
```

### Option B: Rego policy (full control)

```
1. Edit or create a .rego file in kitelogik/policies/
2. Write OPA tests in the same file (test_ prefix):
       test_your_rule_name if {
           your_policy.allow with input as { ... }
       }
3. Run: opa test kitelogik/policies/ -v
4. Add a Python integration test in tests/test_gate.py
5. Run: pytest tests/test_gate.py -v
6. Submit PR — CI runs all test suites automatically
```

### Policy file requirements

Every `.rego` file in `kitelogik/policies/` must:

- Start with `default allow := false` — deny-by-default is non-negotiable
- Use `import future.keywords.if` and `import future.keywords.in`
- Include at least one `test_*` rule that can be run with `opa test kitelogik/policies/ -v`
- Use the `kitelogik.<domain>` package namespace (e.g. `package kitelogik.healthcare`)

### What OPA input looks like

```json
{
  "action":  "view_patient_record",
  "args":    { "patient_id": "p_001" },
  "context": {
    "user_role":       "clinician",
    "session_scopes":  ["read_patient"],
    "session_id":      "sess_abc",
    "delegation_depth": 0
  }
}
```

The policy gate (`kitelogik/tether/gate.py`) constructs this input from the session context and tool call. Your rule only needs to evaluate `input` — the gate handles the rest.

---

## Worked Example: healthcare.rego

Here is a complete, minimal policy that gates access to patient records. This example touches every file that needs to change when you add a new domain policy.

### 1. `kitelogik/policies/healthcare.rego` (new file)

```rego
# SPDX-License-Identifier: Apache-2.0
package kitelogik.healthcare

import future.keywords.if
import future.keywords.in

default allow := false

# Clinicians can view their own assigned patient records.
# Requires an explicit scope on the session token — the role alone is not enough.
allow if {
    input.action == "view_patient_record"
    "read_patient" in input.context.session_scopes
    input.context.user_role in {"clinician", "charge_nurse"}
}

# Read-only audit access — no writes, no treatment actions.
allow if {
    input.action in {"list_patients", "view_patient_record"}
    "audit_read" in input.context.session_scopes
    input.context.user_role == "auditor"
}

# ── Tests ─────────────────────────────────────────────────────────────────────

test_clinician_can_view if {
    allow with input as {
        "action": "view_patient_record",
        "args": {"patient_id": "p_001"},
        "context": {
            "user_role": "clinician",
            "session_scopes": ["read_patient"],
            "session_id": "sess_001",
        },
    }
}

test_clinician_blocked_without_scope if {
    not allow with input as {
        "action": "view_patient_record",
        "args": {"patient_id": "p_001"},
        "context": {
            "user_role": "clinician",
            "session_scopes": [],
            "session_id": "sess_002",
        },
    }
}

test_auditor_can_list if {
    allow with input as {
        "action": "list_patients",
        "args": {},
        "context": {
            "user_role": "auditor",
            "session_scopes": ["audit_read"],
            "session_id": "sess_003",
        },
    }
}

test_unknown_action_denied if {
    not allow with input as {
        "action": "delete_patient_record",
        "args": {},
        "context": {
            "user_role": "admin",
            "session_scopes": ["read_patient", "audit_read"],
            "session_id": "sess_004",
        },
    }
}
```

Run OPA tests to confirm:

```bash
opa test kitelogik/policies/ -v
# PASS: 4/4 tests in data.kitelogik.healthcare
```

### 2. `tests/test_gate.py` (add to existing file)

```python
@pytest.mark.asyncio
async def test_healthcare_clinician_allow(gate, broker):
    token = broker.issue(
        session_id="sess_hc_001",
        scopes=["read_patient"],
        ttl_seconds=60,
    )
    ctx = SessionContext(
        session_id="sess_hc_001",
        user_role="clinician",
        session_scopes=token.scopes,
        token_id=token.token_id,
    )
    call = ToolCallInput(action="view_patient_record", args={"patient_id": "p_001"}, context=ctx)
    decision = await gate.evaluate(call)
    assert decision.allow
    assert not decision.deny
    broker.revoke(token.token_id)


@pytest.mark.asyncio
async def test_healthcare_missing_scope_deny(gate, broker):
    token = broker.issue(
        session_id="sess_hc_002",
        scopes=[],
        ttl_seconds=60,
    )
    ctx = SessionContext(
        session_id="sess_hc_002",
        user_role="clinician",
        session_scopes=token.scopes,
        token_id=token.token_id,
    )
    call = ToolCallInput(action="view_patient_record", args={"patient_id": "p_001"}, context=ctx)
    decision = await gate.evaluate(call)
    assert not decision.allow
    broker.revoke(token.token_id)
```

### 3. `kitelogik/policies/main.rego` (add risk-tier entry)

If your new action should have a specific risk tier, add it to the `tier_map` in `main.rego`:

```rego
# In the tier_map object:
"view_patient_record":   "OPERATIONAL",
"list_patients":         "INFORMATIONAL",
```

### 4. Run the full suite

```bash
opa test kitelogik/policies/ -v
pytest tests/test_gate.py -v
pytest -q                          # full unit suite
```

All four files changed. That is the complete diff for a new policy domain.

---

## Adding a Framework Adapter

Framework adapters live in `kitelogik/adapters/`. All adapters inherit from `BaseGovernedAdapter` (`kitelogik/adapters/_base.py`), which centralizes the security-critical governance pipeline (evaluate → check → execute → sanitize).

```
1. Create kitelogik/adapters/your_framework.py
2. Inherit from BaseGovernedAdapter
3. Add a lazy import guard (_require_your_framework)
4. Add a framework-specific output method (e.g., your_framework_tools())
5. Add import to kitelogik/adapters/__init__.py
6. Add parametrized tests in tests/test_new_adapters.py
7. Run: pytest tests/test_new_adapters.py -v
```

See `kitelogik/adapters/google_adk.py` for a minimal example (~30 LOC on top of the base class).

---

## Code Style

All Python code is linted with [ruff](https://docs.astral.sh/ruff/). The CI job runs:

```bash
ruff check .
ruff format --check .
```

Rules in use (`pyproject.toml`):

| Rule set | What it checks | Example fix |
|---|---|---|
| `E` / `F` | pyflakes + pycodestyle basics | Remove unused imports, fix indentation |
| `I` | Import order (isort) | `import os` before `import httpx` |
| `UP` | pyupgrade — modern Python syntax | `Union[str, int]` → `str \| int` |
| `CPY001` | SPDX license header on every `.py` file | Add `# SPDX-License-Identifier: Apache-2.0` as line 1 |

Fix all ruff issues before pushing:

```bash
ruff check . --fix          # auto-fix what's fixable
ruff format .               # reformat
```

The SPDX header (`CPY001`) cannot be auto-fixed — add it manually to new files.

---

## Running Tests

```bash
# Unit tests — 681+ tests, no Docker required
pytest -q

# Specific modules
pytest tests/test_gate.py -v
pytest tests/test_hierarchy.py -v
pytest tests/test_new_adapters.py -v
pytest tests/test_e2e_flows.py -v

# Fuzz tests (property-based via Hypothesis)
pytest tests/fuzz/ -v

# OPA policy tests (requires opa binary)
opa test kitelogik/policies/ -v

# Integration tests (requires Docker + OPA)
pytest -m integration -v

# Governance compliance audit
kitelogik compliance

# With coverage
pytest --cov=. --cov-report=term-missing -q
```

The CI matrix runs Python 3.11 and 3.12. Test locally on both if your change touches version-specific behaviour.

---

## Developer Certificate of Origin (DCO)

All contributions must include a `Signed-off-by` line in the commit message, certifying that you wrote or have the right to submit the code under the Apache-2.0 license. This is the [Developer Certificate of Origin](https://developercertificate.org/).

Add it automatically with `git commit -s`:

```bash
git commit -s -m "feat: add healthcare policy"
# Produces: Signed-off-by: Your Name <your.email@example.com>
```

If you forget, amend the last commit: `git commit --amend -s`.

---

## Pull Request Process

1. **Fork and branch** — branch names should be descriptive: `feat/healthcare-policy`, `fix/hitl-timeout-race`, `docs/architecture-threat-model`

2. **One concern per PR** — a policy change and a refactor are two PRs

3. **Checklist before opening:**
   - [ ] `ruff check . && ruff format --check .` passes
   - [ ] `pytest -q` passes (681+ tests)
   - [ ] `opa test kitelogik/policies/ -v` passes (if you changed any `.rego` file)
   - [ ] `kitelogik compliance` shows no regressions (if you changed policies)
   - [ ] New code has `# SPDX-License-Identifier: Apache-2.0` header
   - [ ] All commits are signed off (`git commit -s`)
   - [ ] PR description explains *why*, not just *what*

4. **What reviewers look at:**
   - Security boundaries — does the change weaken any deny-by-default guarantee?
   - Test coverage — is there a test that fails without this change?
   - Least privilege — does new code request more access than it needs?

5. **Merging** — we squash-merge. Your commit history in the branch doesn't matter; the PR title and description become the commit message, so write them carefully.

---

## Questions

Open a [GitHub Discussion](https://github.com/kitelogik/kitelogik/discussions) for anything that doesn't fit in a bug report or PR. We respond to discussions within a few days.
