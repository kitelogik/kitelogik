# Examples

Runnable scripts demonstrating each integration pattern from the
[main README](../README.md#integrate-in-3-lines). Each script is
self-contained — read it top-to-bottom, copy the pieces you need.

## Prerequisites

All examples talk to an OPA policy engine at `http://localhost:8181`:

```bash
docker compose up -d opa
```

…using the policies shipped in [`kitelogik/policies/`](../kitelogik/policies/).
No Anthropic / OpenAI API key is required unless noted.

Install from the repo root in editable mode:

```bash
pip install -e ".[dev]"
```

## Catalog

| File | What it shows | External deps |
|---|---|:---:|
| [`01_decorator.py`](01_decorator.py) | `@governed` wrapping a single async function — smallest possible integration | — |
| [`02_governed_toolbox.py`](02_governed_toolbox.py) | `GovernedToolbox` for framework-agnostic tool registration + dispatch | — |
| [`03_openai_tools.py`](03_openai_tools.py) | `OpenAIAdapter` executing model-generated tool calls through the gate | `openai` (stubbed in the script) |
| [`04_langchain_agent.py`](04_langchain_agent.py) | `govern_toolkit` wrapping existing LangChain `BaseTool` objects | `langchain-core` |
| [`05_hitl_escalation.py`](05_hitl_escalation.py) | Soft-deny → `HITLQueue` enqueue → human approve → audit trail | — |
| [`06_credential_delegation.py`](06_credential_delegation.py) | `CredentialBroker` subset-only delegation + revocation | — |

Run any example directly:

```bash
python examples/01_decorator.py
```

## Adversarial demos

[`adversarial/`](adversarial/) — four lifecycle attacks (delegation scope
escalation, dangerous plan step, budget exhaustion, memory poisoning) and
how the governance layer stops each. These target what an agent *does*,
not what it says — the gap prompt-injection firewalls and output
validators structurally miss. See [`adversarial/README.md`](adversarial/README.md).

## Where to look next

- [`../quickstart.py`](../quickstart.py) — full four-step walkthrough (Tether, HITL, hard deny, audit)
- [`../kitelogik/adapters/`](../kitelogik/adapters/) — all 11 framework adapters; module docstrings show per-framework usage
- [`../kitelogik/policies/library/`](../kitelogik/policies/library/) — starter policies with tests (cost cap, PII protection, rate limiting, read-only, allowlist)
- [`../kitelogik/policies/examples/`](../kitelogik/policies/examples/) — annotated Rego + YAML templates
