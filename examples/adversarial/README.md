# Adversarial demos — lifecycle attacks

Four runnable demonstrations of attacks that target the **agent
lifecycle** — what an agent delegates, plans, consumes, and remembers —
rather than the text of a single prompt or response.

This is the layer most "AI guardrails" tools don't cover. Prompt-injection
firewalls, output validators, and dialog filters operate on the model's
input/output. None of them see a delegation that widens scope, a plan
whose third step is destructive, a loop burning its budget, or a tool
result poisoning memory for a later turn. Kite Logik governs those events
at the infrastructure layer, where the model cannot talk its way past a
deny.

Each script is self-contained, prints what happened, and asserts the
expected outcome. Demos 1–3 evaluate a real policy and need OPA running
(`docker compose up -d opa`); demo 4 is pure in-process.

## The taxonomy

| Demo | Attack | Governance event | What a prompt/output guardrail misses |
|---|---|---|---|
| [`delegation_scope_escalation.py`](delegation_scope_escalation.py) | A parent agent grants a child a capability it never held itself — privilege creep one hop at a time. | `agent.delegate` → `agent_lifecycle.rego` (child scopes must be a subset of the parent's) | There's no malicious text; the violation is the structural scope relationship between parent and child. |
| [`plan_step_injection.py`](plan_step_injection.py) | A multi-step plan reads as routine but a later step calls a destructive tool. | `agent.plan` → `agent_plan.rego` (whole plan denied if it contains a blocked tool) | An output validator inspects each result *after* it runs; the safe prefix has already executed before it sees the bad step. |
| [`budget_exhaustion_runaway.py`](budget_exhaustion_runaway.py) | A looping or steered agent keeps spending until it exhausts its token / call / cost budget (denial-of-wallet). | `agent.budget` → `agent_budget.rego` (deny once a budget is exhausted) | Cumulative consumption is session state across many turns; per-prompt scanning has no view of it. |
| [`memory_poisoning_minja.py`](memory_poisoning_minja.py) | A tool returns text with a buried instruction that persists into memory and re-surfaces a turn later (MINJA pattern). | Memory provenance — tier-based sanitization on write + a permanent UNTRUSTED tag | MINJA is a cross-turn attack; a one-shot scanner sees nothing wrong with the tool output in isolation. |

## Run them

```bash
docker compose up -d opa          # demos 1–3 need a policy engine

python examples/adversarial/delegation_scope_escalation.py
python examples/adversarial/plan_step_injection.py
python examples/adversarial/budget_exhaustion_runaway.py
python examples/adversarial/memory_poisoning_minja.py   # no OPA needed
```

## The point

These are complementary to prompt- and output-level tooling, not a
replacement for it. Run a prompt-injection firewall *and* govern the
lifecycle — the attacks above are the ones the firewall structurally
cannot reach.
