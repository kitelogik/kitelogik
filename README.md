# Kite Logik

[![CI](https://github.com/kitelogik/kitelogik/actions/workflows/ci.yml/badge.svg)](https://github.com/kitelogik/kitelogik/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-645%20passing-brightgreen)](https://github.com/kitelogik/kitelogik/actions)
[![Coverage](https://codecov.io/gh/kitelogik/kitelogik/branch/main/graph/badge.svg)](https://codecov.io/gh/kitelogik/kitelogik)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/kitelogik/kitelogik/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org)
[![PyPI](https://img.shields.io/pypi/v/kitelogik.svg)](https://pypi.org/project/kitelogik/)

**Governance middleware for Python AI agents.** Kite Logik governs what your agents can do, what they can spawn, what they can access, and what resources they can consume — enforced at the infrastructure level, not the prompt level.

Other tools test prompts. Other tools validate LLM outputs. Kite Logik governs the **agent itself.**

```
A prompt-based guardrail is a suggestion.
Kite Logik is a lock.
```

## Why Kite Logik

Prompt-level guardrails rely on the model cooperating. Kite Logik doesn't.

- **Infrastructure enforcement** — Rules are evaluated by OPA and enforced at the policy gate. The model cannot override a deny.
- **Agent-level governance** — Not just tool calls. Agent spawn, delegation, plans, resource budgets, and data access are all policy-controlled.
- **OPA/Rego policies** — The same policy language security teams already use for Kubernetes. Deterministic, testable, version-controlled.
- **Zero-trust sessions** — Every agent gets a scoped, short-lived credential. Least privilege by default.
- **Immutable audit trail** — Every governance decision is logged, timestamped, and integrity-hashed. SQL triggers prevent tampering.

## What Kite Logik Governs

| Governance Event | What's Evaluated | Example |
|---|---|---|
| **Tool calls** | Every tool invocation, before execution | "Block file writes outside /tmp" |
| **Agent spawn** | Agent creation with requested capabilities | "Max delegation depth is 2" |
| **Delegation** | Agent-to-agent task handoff | "Child scopes must be subset of parent" |
| **Plans** | Proposed action sequence, before any step runs | "Deny plans with blocked tools" |
| **Resource budgets** | Token spend, API calls, compute time | "Deny if session budget exhausted" |
| **Data access** | Classification-based flow control | "Confidential data stays in primary session" |

All events flow through the same pipeline:

```
Governance Event → Credential Check → OPA Evaluation → ALLOW / DENY
                                                         ↓ (rare, high-stakes only)
                                                       HITL Escalation
```

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     CONTROL PLANE                        │
│  Agent lifecycle · Delegation chains · Resource budgets  │
│  Plan-before-execute · Data classification               │
└──────────────────────────┬───────────────────────────────┘
                           │
            ┌──────────────▼──────┐
            │  EMBEDDED SDK       │
            │  @governed          │
            │  GovernedToolbox    │
            │  Framework adapters │
            │  (in-process)       │
            └──────────────┬──────┘
                           │
    ┌──────────────────────▼───────────────────────────────┐
    │              TETHER (Policy Engine)                   │
    │  OPA/Rego or Regorus · Deny-by-default · Fail-closed │
    │  YAML or Rego policies · 2-tier hierarchy            │
    └──────────────────────┬───────────────────────────────┘
                           │
            ┌──────────────▼──────────────┐
            │  ANCHOR                     │
            │  Credential broker          │
            │  Audit log                  │
            │  HITL queue                 │
            │  OpenTelemetry              │
            └─────────────────────────────┘
```

### Deployment Modes

| Mode | Who Uses It | How |
|---|---|---|
| **Embedded SDK** | Individual developers & teams | `@governed` decorator wraps tool functions in-process. Zero network hop. Add governance to any agent in 3 lines. |

## Getting Started

> **Prerequisite:** Kite Logik evaluates every governance event through an OPA policy engine over HTTP. You need OPA reachable at `http://localhost:8181` before any of the examples below will succeed — without it, `PolicyGate` fails closed and every call raises `GovernanceError`. The easiest path is Docker; the scaffold below writes a ready-to-use `docker-compose.yml`.

**New project** — scaffold a governed agent in seconds:

```bash
pip install kitelogik
kitelogik init my-agent           # creates agent.py, policies/, docker-compose.yml
cd my-agent
docker compose up -d opa          # start OPA policy engine on :8181
python agent.py                   # see ALLOW / BLOCK decisions immediately
```

This creates a `policies/policy.yaml` with starter rules, compiles it to Rego, and generates an `agent.py` that runs governance demos. Set `ANTHROPIC_API_KEY` to enable an interactive Claude agent loop.

**Existing project** — add governance to any tool function. You'll need OPA running at `http://localhost:8181` — either run it via Docker directly:

```bash
pip install kitelogik
docker run -d --name opa -p 8181:8181 \
    -v "$(pwd)/policies:/policies:ro" \
    openpolicyagent/opa:latest run --server --addr :8181 /policies
```

…or point at an existing OPA server by passing `base_url=` to `OPAClient(...)`.

```python
from kitelogik import governed, PolicyGate, OPAClient, SessionContext

gate = PolicyGate(opa_client=OPAClient())  # defaults to http://localhost:8181
ctx  = SessionContext(session_id="s1", user_role="support",
                      session_scopes=["read_customer", "approve_refund"])

@governed(gate=gate, context=ctx)
async def approve_refund(customer_id: str, amount: float) -> str:
    return payment_api.refund(customer_id, amount)
```

## Integrate in 3 Lines

**Decorator** — wrap any function:

```python
from kitelogik import governed, PolicyGate, OPAClient, SessionContext

gate = PolicyGate(opa_client=OPAClient())
ctx  = SessionContext(session_id="s1", user_role="support",
                      session_scopes=["read_customer", "approve_refund_under_100"])

@governed(gate=gate, context=ctx)
async def approve_refund(customer_id: str, amount: float) -> str:
    return payment_api.refund(customer_id, amount)

# approve_refund("cust_123", 50.0)   → OPA allows, runs normally
# approve_refund("cust_123", 500.0)  → OPA denies, raises GovernanceError
```

**OpenAI** — drop into your existing tool loop:

```python
from kitelogik.adapters.openai import OpenAIAdapter

adapter = OpenAIAdapter(gate=gate, context=ctx)
adapter.register("approve_refund", approve_refund_fn, schema=schema)

tools = adapter.openai_tool_schemas()       # pass to OpenAI API
results = await adapter.execute_all(calls)  # governed execution
```

**LangChain** — wrap tools or an entire toolkit:

```python
from kitelogik.adapters.langchain import govern_toolkit

tools = govern_toolkit(existing_tools, gate=gate, context=ctx)
agent = create_react_agent(llm, tools=tools)
```

**11 framework adapters** — OpenAI, LangChain, CrewAI, OpenAI Agents SDK, LangGraph, Google ADK, PydanticAI, LlamaIndex, Semantic Kernel, Haystack, Dify. All share the same governance pipeline — see the docstrings in `kitelogik/adapters/` for per-framework usage examples.

**Browse runnable examples** — every snippet above has a standalone script in [`examples/`](https://github.com/kitelogik/kitelogik/tree/main/examples) (decorator, GovernedToolbox, OpenAI, LangChain, HITL escalation, credential delegation). Start with [`examples/01_decorator.py`](https://github.com/kitelogik/kitelogik/blob/main/examples/01_decorator.py).

## Writing Policies

### Option A: YAML (no Rego required)

Write policies in YAML and compile to Rego:

```yaml
# policies/custom_rules.yaml
version: 1
package: kitelogik.custom_rules
rules:
  - name: block_high_refunds
    when:
      action: approve_refund
      args.amount: { gt: 1000 }
    then: deny
    reason: "Refunds over $1000 require escalation"

  - name: allow_read_ops
    when:
      action: { in: [read_customer, list_transactions] }
      context.session_scopes: { contains: read_customer }
    then: allow
    risk_tier: INFORMATIONAL
```

```bash
kitelogik compile policies/custom_rules.yaml   # generates .rego file
kitelogik validate                              # check syntax
```

### Option B: Rego (full control)

Policies are OPA/Rego files in `kitelogik/policies/`. Every file starts with `default allow := false` (deny-by-default).

```rego
package kitelogik.financial

import future.keywords.if
import future.keywords.in

default allow := false

# Allow refunds under $100 for support agents with the right scope
allow if {
    input.action == "approve_refund"
    "approve_refund_under_100" in input.context.session_scopes
    input.context.user_role in {"support_agent", "manager"}
    input.args.amount <= 100
}
```

Agent lifecycle policies work the same way:

```rego
package kitelogik.agent_lifecycle

import future.keywords.if
import future.keywords.in
import future.keywords.every

default allow := false
default deny := false

# Allow spawn when within depth limit and capabilities are valid
allow if {
    input.event_type == "agent.spawn"
    input.context.delegation_depth <= 2
    every cap in input.requested_capabilities {
        cap in input.context.session_scopes
    }
}

# Deny spawn when delegation depth exceeds limit
deny if {
    input.event_type == "agent.spawn"
    input.context.delegation_depth > 2
}
```

See `kitelogik/policies/examples/` for annotated templates and `kitelogik/policies/library/` for ready-to-use starter policies.

## Session Credentials

Every agent session gets a scoped, short-lived credential. The policy gate validates it on every governance event. Agents cannot expand their own permissions.

```python
from kitelogik.anchor.credentials import CredentialBroker

broker = CredentialBroker()
token = broker.issue(session_id="s1", scopes=["read_customer"], ttl_seconds=300)

# Delegation narrows scope — child never gets more than parent
child_token = broker.delegate(
    parent_token_id=token.token_id,
    requested_scopes=["read_customer"],  # must be subset of parent
    session_id="s1_worker",
)
```

## Risk Tiers

| Tier | Examples | Default Outcome |
|---|---|---|
| `INFORMATIONAL` | Read-only lookups, memory queries | Auto-allow |
| `OPERATIONAL` | Write/update operations | Allow if scoped |
| `TRANSACTIONAL_HIGH` | High-value financial operations | Policy-defined (HITL optional) |
| `DESTRUCTIVE` | Delete, bulk operations | Policy-defined |
| `SECURITY_CRITICAL` | Shell access, credential ops, path traversal | Hard block |

HITL escalation is triggered **only when OPA policy explicitly sets `requires_hitl := true`** — for high-stakes situations like wire transfers or restricted data access. Most governance decisions resolve instantly with zero human delay.

## Project Structure

```
kitelogik/
  __init__.py       Public API re-exports
  governed.py       @governed decorator, GovernedToolbox
  adapters/         11 framework adapters
  cli.py            CLI entry point
  tether/           Policy engine: OPA client, Regorus client, hierarchy, sanitizer
  anchor/           Credential broker, HITL queue, session tokens
  memory/           Agent memory with trust tiers and provenance
  agents/           Agent session loop
  audit/            Immutable append-only audit log
  observability/    OpenTelemetry tracing
  mcp/              MCP client with supply chain verification
  policies/         OPA/Rego rules, YAML compiler, starter library, examples
tests/              645 tests across unit, integration, adversarial, fuzz, benchmark suites
```

## Features

Everything in this repository is Apache-2.0 and self-hostable. There is no paid tier gating any of it.

**Governance pipeline**
- OPA policy engine (Tether) with an experimental in-process Regorus engine
- YAML policy frontend (`kitelogik compile`) plus a starter policy library
- 2-tier policy hierarchy (global + project)
- Tool-call governance, agent lifecycle governance (spawn, delegate, plan), and resource-budget enforcement
- Data classification labels
- Compliance CLI with OWASP ASI mapping

**Credentials, storage, observability**
- Session-scoped credentials with delegation (issue / validate / delegate / revoke)
- SQLite backends for HITL, credentials, audit, and memory
- OpenTelemetry tracing with session-scoped correlation
- HITL queue for high-stakes escalation

**Framework adapters (11)**
- OpenAI, LangChain, LangGraph, CrewAI, OpenAI Agents SDK
- Google ADK, PydanticAI, LlamaIndex, Semantic Kernel, Haystack, Dify

## Development

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
docker compose up -d opa    # start OPA policy engine

make test           # 645 tests passing (560 unit + 85 adversarial; integration suite runs separately)
make lint           # ruff check + format

# Policy management
kitelogik compile kitelogik/policies/examples/example_rules.yaml   # YAML → Rego
kitelogik validate                                        # check Rego syntax
kitelogik compliance                                      # OWASP ASI audit

# Benchmarks — measured latency on the agent's critical path
docker compose up -d opa
python benchmarks/bench_gate.py             # policy gate: p50 ~3ms, p95 ~8ms
python benchmarks/bench_memory_session.py   # memory + credential broker (no OPA)
```

## Requirements

- Python 3.11+
- Docker (for OPA policy engine) — `docker compose up -d opa`
- No API key needed for `quickstart.py` or policy testing

## Further Reading

- [Examples](https://github.com/kitelogik/kitelogik/tree/main/examples) — runnable scripts for each integration pattern
- [Contributing](https://github.com/kitelogik/kitelogik/blob/main/CONTRIBUTING.md)
- [Security Policy](https://github.com/kitelogik/kitelogik/blob/main/SECURITY.md)
- [Changelog](https://github.com/kitelogik/kitelogik/blob/main/CHANGELOG.md)

---

**Kite Logik** — Governance middleware for Python AI agents.
