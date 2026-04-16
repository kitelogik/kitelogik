# Kite Logik — Open Source Edition

Complete reference for the open source distribution of Kite Logik: governance middleware for enterprise AI agent deployments.

---

## Table of Contents

1. [What It Is](#what-it-is)
2. [Features](#features)
3. [Architecture](#architecture)
4. [Data Storage](#data-storage)
5. [Security Model](#security-model)
6. [Test Coverage](#test-coverage)
7. [Best Practices](#best-practices)
8. [Deployment](#deployment)
9. [Open Source vs Enterprise](#open-source-vs-enterprise)

---

## What It Is

Kite Logik is governance middleware that sits between AI agents and the tools they call. It enforces business rules at the infrastructure level — before the agent acts, every time.

The critical distinction from every competing tool: enforcement happens at the **tool execution layer**, not the LLM I/O layer. NeMo Guardrails, Guardrails AI, and Bedrock Guardrails all intercept at the prompt/response boundary. Kite Logik intercepts the tool call itself — the moment the agent tries to *do* something, not just what it says.

```
    Agent (Anthropic SDK / any LLM)
         |
         | tool_call(name, args)
         v
  ┌─────────────────────────────────────────────────────┐
  │  Tether — Policy Gate (OPA)                         │
  │                                                     │
  │  1. Validate credentials & scopes                   │
  │  2. Validate tool call schema                       │
  │  3. Evaluate Rego rules → ALLOW / HITL / BLOCK      │
  └─────────────────────────────────────────────────────┘
         |              |              |
         v              v              v
     Tool runs     Anchor (HITL)   Hard block
                   Human reviews   Error returned
                   Agent waits     to agent
                   async
         |
         v
  ┌─────────────────────────────────────────────────────┐
  │  Sandbox — Container Isolation (Docker)             │
  │  network_mode=none, resource limits, per-session    │
  └─────────────────────────────────────────────────────┘
```

A system prompt is a suggestion. Kite Logik is a lock.

---

## Features

### Tether — Policy Gate

The core enforcement layer. Every tool call passes through before execution.

**Policy-as-Code with OPA/Rego (or YAML)**
- Business rules written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) or YAML (compiled to Rego via `kitelogik compile`)
- Policies are version-controlled files — reviewed in pull requests, auditable in git history
- Deny-by-default: if no rule explicitly allows an action, it is blocked
- Three evaluation backends: **OPAClient** (HTTP to external OPA), **RegorusClient** (in-process Rego via Rust, zero Docker), **HierarchicalEvaluator** (2-tier global + project with deny-overrides)
- Policies are hot-reloaded by OPA; no restart required for rule changes

**Risk Tier Classification**

Every tool call is assigned a risk tier before evaluation:

| Tier | Default Outcome | Example Actions |
|---|---|---|
| `INFORMATIONAL` | Allow | Read operations, memory queries |
| `OPERATIONAL` | Allow | List transactions, send notifications |
| `TRANSACTIONAL_LOW` | Allow (with scope) | Low-value refunds (≤ $100) |
| `TRANSACTIONAL_HIGH` | HITL escalation | High-value refunds (≤ $1,000) |
| `DESTRUCTIVE` | Block | Delete operations, bulk writes |
| `SECURITY_CRITICAL` | Hard block | File path access, code execution without sandbox |

**Scope-Based Access Control**
- Sessions carry explicit scopes (e.g., `approve_refund_under_100`, `read_customer`, `memory_write`)
- OPA policies check both scope and role; neither alone is sufficient for most high-risk actions
- Scopes are enforced at the credential level — not just checked in policy

**Type-Safe Amount Guards**
- Numeric amount fields are checked via `is_number()` in Rego before comparison
- Prevents type confusion: `null`, `true`, `-1`, and `"50"` all fail the guard
- Negative amounts are rejected regardless of tier

**Fail-Closed Architecture**
- If OPA is unreachable, the gate returns `deny=True, risk_tier=SECURITY_CRITICAL`
- No silent degradation; connectivity loss is surfaced as a hard block
- Configurable OPA base URL; defaults to `http://localhost:8181`

**Full OTel Instrumentation**
- Every gate evaluation produces an OpenTelemetry span
- Span attributes: tool name, risk tier, decision outcome, session ID, latency
- Traces correlate across gate → HITL → tool execution using session ID

---

### Anchor — Human-in-the-Loop Queue

Async escalation for actions that require human review before the agent proceeds.

**Non-blocking escalation**
- HITL actions are enqueued; the agent suspends on `asyncio.Event`, not a polling loop
- Human decision (approve/deny) sets the event immediately — zero polling latency
- Configurable timeout (default: 300s); timed-out actions are marked `TIMED_OUT` in the database

**Action lifecycle**

```
PENDING → APPROVED → (tool executes)
        → DENIED   → (hard block, reason returned to agent)
        → TIMED_OUT → (treated as deny)
```

**Decision metadata**
- Every decision records: `decided_by`, `decided_at`, `denial_reason`
- Full audit trail in the database; visible in the dashboard

**Background expiry task**
- `HITLQueue.start_expiry_task()` runs as an asyncio background task
- Periodically marks overdue `PENDING` actions as `TIMED_OUT` and wakes any waiting agents

**REST API**
- `GET /api/pending` — list actions awaiting review (dashboard uses this)
- `POST /api/decide/{action_id}` — approve or deny with reason
- Exposed via FastAPI; consumed by the dashboard UI

---

### Sandbox — Container Isolation (Enterprise Edition)

Per-session Docker containers that structurally limit what an agent session can reach. The sandbox runtime (Docker with hardened resource limits, gVisor support, Firecracker MicroVM) is available in [Kite Logik Enterprise](https://github.com/kitelogik/kitelogik-enterprise).

**Code execution guard (OSS)**
- `execute_code` tool calls require `sandbox_verified=true` in session context
- OPA `security.rego` hard-blocks code execution if the flag is absent
- The sandbox policy enforcement is in OSS; the sandbox runtime management is in Enterprise

---

### Credentials — Session-Scoped Tokens

Short-lived credentials issued per session, revoked on session end.

**Scope enforcement**
- `CredentialBroker.issue()` creates a token with explicit scopes
- `delegate()` enforces that child scopes are a strict subset of the parent's scopes — a child session cannot escalate its own privileges
- Child tokens cannot outlive their parent token

**Delegation depth control**
- OPA `delegation.rego` enforces maximum delegation depth of 2
- Depth-1 delegates: refund cap reduced to $50
- Depth-2+ delegates: refunds blocked entirely
- `delegation_depth` is carried in `SessionContext` and checked by every policy rule

**Revocation**
- Tokens are revoked in the `AgentSession` `finally` block — even on exception or cancellation
- `validate()` checks active token status before any gate evaluation

**Persistence option**
- Default: in-memory (process restart loses all tokens)
- `PersistentCredentialBroker`: SQLite write-through; survives restarts

---

### Memory — Provenance-Tracked Agent Memory

Agent long-term memory with source tracking to defend against memory poisoning.

**Every write carries provenance**

```python
await memory.write(
    key="customer_context",
    value="...",
    trust_tier=TrustTier.EXTERNAL,   # source trust level
    source="mcp://crm-server",        # where this came from
    session_id="session_abc",         # which session wrote it
)
```

**Trust tiers**

| Tier | Sanitized on Write | Use Case |
|---|---|---|
| `INTERNAL` | No | Verified internal system outputs |
| `VERIFIED` | No | Pre-validated business data |
| `DELEGATED` | Yes | Data from delegated agent sessions |
| `EXTERNAL` | Yes | MCP server responses, database records |
| `UNTRUSTED` | Yes | User-provided input, document content |

**Automatic sanitization**
- Values from `EXTERNAL`, `DELEGATED`, and `UNTRUSTED` sources pass through the injection sanitizer before storage
- The sanitizer strips known prompt injection patterns (instruction overrides, system prompt probes)
- `sanitized=true` flag is stored alongside the value; readers can inspect it

**Memory read access control**
- `query_memory` requires a non-empty `session_id` in context — no anonymous reads
- Controlled via the same OPA policy gate as tool calls

---

### Observability

OpenTelemetry tracing is included in the open source edition.

**OpenTelemetry instrumentation**
- GenAI Semantic Conventions v1.37+ for LLM-specific attributes
- Traces for: gate evaluations, HITL events, memory reads/writes, tool executions, session lifecycle
- All traces correlated by `session_id`

**Trace export**
- Default: file exporter (no external service needed)
- OTLP/HTTP: pass `--otlp http://localhost:4318` to the demo script; works with any OTLP collector

> **Enterprise Edition:** Real-time governance dashboard (live event feed, HITL approve/deny UI, memory browser, fleet view, audit log, trace viewer), Prometheus metrics, SIEM webhook dispatchers, and Grafana + Tempo are available in [Kite Logik Enterprise](https://github.com/kitelogik/kitelogik-enterprise).

---

### Demo Scenarios

13 pre-built demo scenarios in `agents/demo.py`:

| # | Scenario | Expected Outcome |
|---|---|---|
| 1 | Code execution without sandbox | BLOCK |
| 2 | Code execution with sandbox verified | ALLOW |
| 3 | Read customer record (correct scope) | ALLOW |
| 4 | Read customer record (missing scope) | BLOCK |
| 5 | Low-value refund, support agent | ALLOW |
| 6 | High-value refund, manager | HITL |
| 7 | Refund above tier cap | BLOCK |
| 8 | Wrong role for action | BLOCK |
| 9 | Access `/etc/passwd` | BLOCK |
| 10 | Path traversal `../` | BLOCK |
| 11 | Access `.env` file | BLOCK |
| 12 | Worker agent refund under cap | ALLOW |
| 13 | Worker agent refund over cap | BLOCK |

---

## Architecture

```
kitelogik/
├── tether/              # Policy gate: schema validation, OPA client, sanitizer
│   ├── gate.py          # PolicyGate — main enforcement entry point
│   ├── opa_client.py    # OPA HTTP client with fail-closed semantics
│   ├── regorus_client.py # In-process Rego evaluator (experimental)
│   ├── hierarchy.py     # 2-tier global+project policy hierarchy
│   ├── sanitizer.py     # Indirect prompt injection defence
│   └── models.py        # PolicyDecision, SessionContext, RiskTier, GovernanceEvent
│
├── anchor/           # HITL queue, credential broker, REST API
│   ├── queue.py      # HITLQueue (SQLite-backed async)
│   ├── credentials.py # CredentialBroker, PersistentCredentialBroker
│   ├── api.py        # FastAPI HITL endpoints
│   └── models.py     # PendingAction, ActionStatus
│
├── sandbox/          # Container lifecycle management
│   └── manager.py    # DockerSandboxManager: spawn, exec, teardown
│
├── memory/           # Agent memory with provenance
│   ├── store.py      # MemoryStore (SQLite-backed async)
│   └── models.py     # MemoryEntry, TrustTier
│
├── agents/           # Session orchestration
│   ├── session.py    # AgentSession — direct mode
│   └── demo.py       # 13 demo scenarios
│
├── mcp/              # MCP client, supply chain checks
│   ├── client.py
│   └── stdio_transport.py  # Subprocess-based MCP stdio transport
│
├── policies/         # OPA Rego rules
│   ├── main.rego
│   ├── financial.rego
│   ├── security.rego
│   ├── delegation.rego
│   ├── agent_lifecycle.rego
│   ├── agent_plan.rego
│   ├── agent_budget.rego
│   ├── data_classification.rego
│   ├── compiler.py   # YAML→Rego policy compiler
│   └── library/      # Starter policies (5) with OPA tests
│
├── observability/    # OTel config
│   └── tracer.py
│
├── audit/            # Immutable append-only log
│   ├── store.py
│   └── replay.py     # Policy replayer
│
└── kitelogik/        # Public SDK
    ├── governed.py   # @governed decorator, GovernedToolbox
    ├── cli.py        # kitelogik CLI (validate, compile, compliance)
    ├── adapters/     # 11 framework adapters
    └── edition.py    # Enterprise plugin detection
```

---

## Data Storage

### Default (Open Source): SQLite

All persistent state uses SQLite by default. No external database required.

| Component | Database File | Schema |
|---|---|---|
| HITL Queue | `hitl.db` | `pending_actions` table |
| Memory Store | `memory.db` | `memory_entries` table |
| Credentials | `credentials.db` | `session_tokens` table (PersistentCredentialBroker) |

**HITL Queue schema:**
```sql
CREATE TABLE pending_actions (
    id            TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL,
    tool_name     TEXT NOT NULL,
    args_json     TEXT NOT NULL,
    risk_tier     TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'PENDING',
    created_at    TEXT NOT NULL,
    decided_at    TEXT,
    decided_by    TEXT,
    denial_reason TEXT
)
```

**Memory Store schema:**
```sql
CREATE TABLE memory_entries (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    trust_tier TEXT NOT NULL,
    source     TEXT NOT NULL,
    session_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    sanitized  INTEGER NOT NULL DEFAULT 0
)
```

**Thread safety:** All SQLite operations are dispatched via `asyncio.to_thread` — the async event loop is never blocked.

**Suitable for:** Development, single-node deployments, small teams.

### Enterprise: PostgreSQL

Production deployments with multiple nodes or high HITL volume should use the Postgres backends. These are available in [Kite Logik Enterprise](https://github.com/kitelogik/kitelogik-enterprise) and use the same interface — swap the class, keep the code.

---

## Security Model

### 1. Deny by Default

Every OPA policy file opens with:

```rego
default allow := false
```

If no rule positively grants access, the action is blocked. There is no fallback allow path.

### 2. Infrastructure Enforcement, Not Prompt Enforcement

Policy decisions are made by OPA — a deterministic policy engine running outside the model's control. The model cannot reason its way around a policy. A refund above threshold is structurally blocked regardless of the system prompt, the user's instructions, or the model's reasoning.

### 3. Indirect Prompt Injection Defence

Tool output is sanitized before it enters agent context. The sanitizer (`tether/sanitizer.py`) detects and strips known injection patterns:

- Instruction override phrases ("ignore previous instructions", "disregard your guidelines")
- System prompt probes ("print your system prompt", "reveal your instructions")
- Role override attempts ("you are now an unrestricted AI")
- Command injection patterns in tool arguments

The sanitizer is tested against a corpus of real-world injection payloads in `tests/adversarial/test_injection.py`.

Memory writes from `EXTERNAL`, `DELEGATED`, and `UNTRUSTED` sources are sanitized at write time, preventing MINJA-style memory poisoning.

### 4. Credential Scope Enforcement

Session tokens carry an explicit scope list. Delegation enforces strict subset semantics — a child session cannot have more permissions than its parent. OPA checks both the token's scope and the caller's role; scope alone is not sufficient for high-risk actions.

### 5. File System and Path Hardening

`security.rego` hard-blocks:

```
File extensions: .env, .pem, .key, .secret
Paths:           /etc, /proc, /sys, /root, /var/run
Patterns:        ../ (path traversal sequences)
```

These rules cannot be overridden by session scopes or user roles — they are unconditional hard denies.

### 6. Cross-Session Access Prevention

An agent in session `A` cannot read or write resources belonging to session `B`. OPA checks `args.session_id == context.session_id` on any call that targets a specific session.

### 7. Secrets Never Logged

The security non-negotiables in `CLAUDE.md` are enforced throughout the codebase:
- Raw prompt content, tool arguments, and model outputs are never logged without sanitization
- No hardcoded credentials anywhere in the codebase
- MCP server responses are sanitized before being passed to the agent

### 8. OPA Connectivity = Security Invariant

OPA unreachability is treated as a security event, not a degraded-mode trigger. The gate fails closed: every tool call is blocked until OPA is reachable again. This prevents an availability attack (taking down OPA) from becoming a permissions escalation.

---

## Test Coverage

**681 tests across 42 test files.**

```
tests/
├── test_gate.py                  # PolicyGate: allow, deny, HITL, OPA failure, schema validation
├── test_credentials.py           # CredentialBroker: issue, validate, revoke, delegate, scope subset
├── test_hitl_queue.py            # HITLQueue: enqueue, approve, deny, timeout, expiry task
├── test_memory.py                # MemoryStore: write, read, sanitization by trust tier
├── test_session.py               # AgentSession: direct mode, gateway mode, token lifecycle
├── test_delegation.py            # Delegation depth limits, cap enforcement via OPA
├── test_sanitizer.py             # Injection sanitizer: known payloads, benign content preserved
├── test_mcp_client.py            # MCP client: tool discovery, call dispatch, response handling
├── test_mcp_supply_chain.py      # MCP BOM integrity, supply chain verification
├── test_mcp_stdio.py             # MCP stdio transport
├── test_sdk.py                   # Top-level kitelogik package imports and interface
├── test_cli.py                   # CLI: validate, compile, compliance commands
├── test_policy_compiler.py       # YAML→Rego compilation
├── test_policy_tester.py         # Policy tester
├── test_benchmark.py             # Benchmark script output and latency assertions
├── test_anchor_health.py         # Anchor API health endpoint
├── test_governance_events.py     # GovernanceEvent model + evaluate()
├── test_governed.py              # @governed decorator + GovernedToolbox
├── test_hierarchy.py             # HierarchicalEvaluator 2-tier policy
├── test_regorus_client.py        # RegorusClient in-process evaluator
├── test_tools.py                 # Agent tools
├── test_e2e_flows.py             # End-to-end governance flows
├── test_openai_adapter.py        # OpenAI adapter
├── test_langchain_adapter.py     # LangChain adapter
├── test_crewai_adapter.py        # CrewAI adapter
├── test_openai_agents_adapter.py # OpenAI Agents SDK adapter
├── test_langgraph_adapter.py     # LangGraph adapter
├── test_google_adk_adapter.py    # Google ADK adapter
├── test_pydantic_ai_adapter.py   # PydanticAI adapter
├── test_new_adapters.py          # LlamaIndex, Semantic Kernel, Haystack, Dify adapters
├── test_phase2.py                # Phase 2 feature coverage
├── test_phase3.py                # Phase 3 feature coverage
├── adversarial/
│   ├── test_injection.py         # Injection corpus: 12 known payloads, benign content preserved
│   └── test_policy_bypass.py     # Policy bypass attempts: 41 cases
├── fuzz/
│   ├── test_fuzz_gateway_parsing.py  # Hypothesis-based gateway fuzz
│   ├── test_fuzz_policy_input.py     # Policy input fuzz
│   └── test_fuzz_sanitizer.py        # Sanitizer fuzz
└── integration/
    └── test_e2e.py               # End-to-end: full stack with real OPA + Docker (requires services)
```

**Test categories:**

| Category | Files | What is tested |
|---|---|---|
| Unit | 33 files | Individual components in isolation, with mocked dependencies |
| Adapter | 7 files | Framework adapter governance integration |
| Adversarial | 2 files | Injection payloads, policy bypass attempts, edge case inputs |
| Fuzz | 3 files | Hypothesis-based property testing for parsing and sanitization |
| Integration | 2 files | Full stack with live OPA and Docker; E2E governance flows |

**OPA policy tests:**

Rego policies have their own test suite (13 test files), separate from the Python tests:

```
policies/*_test.rego           # 8 core policy test files
kitelogik/policies/library/*_test.rego   # 5 library policy test files
```

Run with:
```bash
opa test kitelogik/policies/ -v
```

**Running the Python test suite:**
```bash
make test
# or
pytest -q -m "not integration"
```

**Running the full integration suite** (requires OPA + Docker running):
```bash
make demo &
pytest -q tests/integration/
```

---

## Best Practices

### What the codebase follows

**Deny by default — consistently applied**
Every policy file starts with `default allow := false`. There is no "default allow with conditions" pattern anywhere in the policy set. OPA evaluates rules as a union of allow conditions; unless one of them matches, the result is deny.

**Least privilege at every boundary**
- Sessions are created with the minimum scope set required for their task
- Delegation enforces scope contraction (child ⊆ parent)
- Network is blocked by default at the container level — not just at the application level

**Async-first, non-blocking design**
- All I/O operations (SQLite, HTTP to OPA, Docker API) use `asyncio.to_thread` or async HTTP clients
- No blocking calls in the async path
- HITL waits on `asyncio.Event`, not a polling loop

**Structured tracing over ad-hoc logging**
- OpenTelemetry spans are used rather than printf-style logs for gate decisions
- Trace correlation via `session_id` attribute on every span
- GenAI Semantic Conventions v1.37+ for LLM-specific span attributes

**Input validation at every system boundary**
- Tool call arguments are schema-validated before OPA evaluation
- Memory writes from external sources are sanitized before storage
- MCP server responses are sanitized before entering agent context
- Type guards (`is_number()`) in Rego prevent type-confusion bypasses

**Explicit error surfaces**
- `OPAConnectionError` is a distinct exception type — callers know exactly what failed
- Policy violations are surfaced to the observability layer, not swallowed
- The gate never returns a partial result — it's always allow, deny, or requires_hitl

### Previously identified gaps (all resolved)

- ✅ `.gitignore` — comprehensive, covers all SQLite, `.env`, `.venv/`, build artefacts
- ✅ `LICENSE` — Apache 2.0
- ✅ `.dockerignore` — excludes `.venv/`, test fixtures, SQLite databases
- ✅ `asyncpg` moved to optional `[postgres]` extra in `pyproject.toml`

---

## Deployment

### Option 1 — Docker Compose (recommended)

The fastest path to a governed agent.

```bash
pip install kitelogik
docker compose up -d opa
python quickstart.py
```

### Option 2 — Full stack (Docker Compose)

Full stack with external OPA server.

```bash
git clone https://github.com/your-org/kitelogik
cd kitelogik
cp .env.example .env          # add ANTHROPIC_API_KEY
python -m venv .venv
.venv/bin/pip install -e .
make demo
```

This starts OPA on `http://localhost:8181` and runs all 13 demo scenarios, printing results to the terminal.

**Stack health:**
```bash
curl http://localhost:8181/health    # OPA
```

### Option 4 — Embedded in your own agent

Use Kite Logik as a library inside your existing agent code:

```python
import asyncio
from kitelogik import (
    OPAClient, PolicyGate, HITLQueue, CredentialBroker,
    AgentSession, SessionContext, TrustTier,
)

async def main():
    opa = OPAClient("http://localhost:8181")
    gate = PolicyGate(opa_client=opa)
    queue = HITLQueue("hitl.db")
    broker = CredentialBroker()

    await queue.setup()

    token = broker.issue(
        role="support_agent",
        scopes=["read_customer", "approve_refund_under_100"],
        ttl_seconds=3600,
    )

    ctx = SessionContext(
        session_id="session_001",
        user_role=token.role,
        session_scopes=token.scopes,
        token_id=token.token_id,
        sandbox_verified=False,
    )

    session = AgentSession(
        context=ctx,
        gate=gate,
        hitl_queue=queue,
        credential_broker=broker,
    )

    result = await session.run(
        task="Look up customer cust_001 and check their last three transactions.",
        tools=["read_customer_record", "list_transactions"],
    )
    print(result.output)

asyncio.run(main())
```

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | Yes | — | Anthropic API key for the agent |
| `OPA_BASE_URL` | No | `http://localhost:8181` | OPA server URL |
| `HITL_DB_PATH` | No | `hitl.db` | SQLite path for HITL queue |
| `MEMORY_DB_PATH` | No | `memory.db` | SQLite path for memory store |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | — | OTLP endpoint for traces (e.g. Tempo) |
| `DASHBOARD_PORT` | No | `8050` | Dashboard server port |

### System Requirements

| Component | Requirement |
|---|---|
| Python | 3.11+ |
| Docker | 20.10+ (for sandbox; **not required** if using Regorus for policy evaluation) |
| OPA | 0.60+ (optional — Regorus provides in-process evaluation without OPA) |
| Memory | 512MB minimum; 2GB recommended for full stack |

---

## Open Source vs Enterprise

The open source edition is a fully functional governance platform. The enterprise edition adds operational features for large-scale, multi-team deployments.

| Capability | Open Source | Enterprise |
|---|---|---|
| Policy engine | OPA (HTTP) + Regorus (in-process) + Hierarchy (2-tier) | Full + fleet-wide policy sync |
| YAML policy compiler | Full | Full |
| Framework adapters | 11 (OpenAI, LangChain, CrewAI, LangGraph, ADK, PydanticAI, LlamaIndex, SK, Haystack, Dify) | Full |
| HITL queue | SQLite | SQLite + PostgreSQL (multi-node, HA) |
| Memory store | SQLite | SQLite + PostgreSQL |
| Credential broker | In-memory / SQLite | SQLite + PostgreSQL + Vault/STS |
| Dashboard | -- | Real-time UI + SSO |
| Governance Gateway | -- | Centralized HTTP enforcement API |
| Multi-agent Orchestrator | -- | Delegation coordination, fan-out |
| Sandbox runtime | -- | Docker (hardened) + Firecracker MicroVM |
| Trace export | File / OTLP | File / OTLP + managed Tempo |
| Prometheus metrics | -- | Full + Grafana dashboards |
| SIEM integration | -- | Splunk HEC, Datadog, Elastic webhooks |
| Compliance CLI | OWASP ASI mapping | Full compliance export packs |
| Policy management UI | No | Yes |
| Multi-tenant session isolation | No | Yes |
| Support | GitHub Issues | SLA-backed |

The open source core handles everything a single team or small organization needs. Enterprise features become relevant when you need centralized enforcement across a fleet, a visual dashboard for ops/compliance teams, or multi-node HA storage.
