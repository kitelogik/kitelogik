# What Is Kite Logik

## What Kite Logik Is

Kite Logik is **the governance control plane for AI agents.** It governs what agents can do, what they can spawn, what they can access, and what resources they can consume — enforced at the infrastructure level, not the prompt level.

Other tools test prompts. Other tools validate LLM outputs. Kite Logik governs the **agent itself.**

```
A prompt-based guardrail is a suggestion.
Kite Logik is a lock.
```

The key distinction: prompt-level guardrails rely on the model cooperating. Kite Logik doesn't. Rules are evaluated by OPA, enforced by the credential broker and policy gate. The model cannot override a deny.

---

## What It Does

Kite Logik governs six categories of agent behavior through a single policy pipeline:

| Governance Event | What's Evaluated | Example |
|---|---|---|
| **Tool calls** | Every tool invocation, before execution | "Block file writes outside /tmp" |
| **Agent spawn** | Agent creation with requested capabilities | "Max delegation depth is 2" |
| **Delegation** | Agent-to-agent task handoff | "Child scopes must be subset of parent" |
| **Plans** | Proposed action sequence, before any step runs | "Deny plans with blocked tools" |
| **Resource budgets** | Token spend, API calls, compute time | "Deny if session budget exhausted" |
| **Data access** | Classification-based flow control | "Confidential data stays in primary session" |

Every event flows through the same pipeline:

```
Governance Event -> Credential Check -> OPA Evaluation -> ALLOW / DENY
                                                            |
                                                          HITL Escalation
                                                    (rare, high-stakes only)
```

HITL is the exception, not the default. It fires **only** when OPA policy explicitly sets `requires_hitl := true` — for wire transfers, restricted data, security-critical actions. The default governance path adds zero human latency.

---

## The Two Layers

1. **Tether (Policy Engine)** — OPA/Rego evaluation of every governance event. Deterministic, testable, version-controlled. The same policy language security teams already use for Kubernetes. Get started with `docker compose up -d opa` — one command, ready in seconds.

2. **Anchor (Oversight)** — Session-scoped credentials with automatic revocation. Async HITL queue for high-stakes situations. Immutable audit trail with integrity hashing. OpenTelemetry tracing.

> **Enterprise Edition** adds a third layer: **Sandbox (Isolation)** — Docker containers and Firecracker MicroVM with network isolation, resource limits, and hardware-enforced kernel isolation. One container per agent session.

---

## How It's Deployed

| Mode | Who Uses It | How |
|---|---|---|
| **Embedded SDK** | Individual developers & teams | `@governed` decorator, `GovernedToolbox`, 11 framework adapters. Runs in-process with the agent. Zero network hop. |
| **Governance Gateway** | Platform teams (Enterprise) | FastAPI HTTP API that agents call tools through. Centralized enforcement, fleet-wide observability. |

Most developers start with the Embedded SDK — it covers the full governance pipeline with no external services beyond an optional OPA server. Enterprise deployments add the Gateway for centralized policy enforcement, fleet management, and compliance reporting.

---

## How Developers Use the OSS

The OSS gives you the **full governance pipeline** for your agents — not a feature-gated trial.

**3-line integration — decorator:**

```python
from kitelogik import governed, PolicyGate, OPAClient, SessionContext

gate = PolicyGate(opa_client=OPAClient())  # start OPA with: docker compose up -d opa
ctx  = SessionContext(session_id="s1", user_role="support",
                      session_scopes=["read_customer", "approve_refund_under_100"])

@governed(gate=gate, context=ctx)
async def approve_refund(customer_id: str, amount: float) -> str:
    return payment_api.refund(customer_id, amount)

# approve_refund("cust_123", 50.0)   -> OPA allows, runs normally
# approve_refund("cust_123", 500.0)  -> OPA denies, raises GovernanceError
```

**Drop into existing agent frameworks:**

11 framework adapters ship out of the box:
- OpenAI, Anthropic, LangChain, LangGraph, CrewAI
- OpenAI Agents SDK, Google ADK, PydanticAI, LlamaIndex, Semantic Kernel, Haystack

All adapters share the same governance pipeline — intercept tool calls, route through policy, return standard results.

**What's included in OSS:**

- OPA/Rego policy engine with deny-by-default enforcement
- Docker Compose setup for OPA — one command to start (`docker compose up -d opa`)
- YAML policy frontend (`kitelogik compile`) — write policies without learning Rego
- Regorus in-process Rego engine (experimental — requires building from source)
- 2-tier policy hierarchy (global + project)
- Tool call, agent lifecycle, plan, budget, and data classification governance
- Session-scoped credentials with delegation and scope narrowing
- HITL queue for high-stakes situations (code-level API)
- Immutable audit trail with SQL trigger enforcement
- OpenTelemetry tracing
- Agent memory with trust tiers and provenance
- Starter policy library with ready-to-use templates
- 11 framework adapters
- CLI for policy compilation, validation, compliance audit
- Compliance CLI with OWASP ASI mapping

**What's not in OSS:** Organizational-scale features — see Enterprise section below.

---

## How Enterprises Use It

Enterprise adds governance at **organizational scale** with Kite Logik Enterprise:

**Infrastructure & Isolation**
- **Firecracker MicroVM** — Hardware-enforced kernel isolation. Sub-125ms boot. Required for fintech/govcon.
- **Docker sandbox** — Network isolation, resource limits, read-only rootfs. One container per agent session.

**Data & Storage**
- **PostgreSQL backends** — HA, connection pooling, read replicas for HITL queue, credentials, memory, and audit.

**Access & Identity**
- **SSO + RBAC** — SAML/OIDC single sign-on. Admin, Policy Author, Operator, Viewer roles scoped to tenant/team.

**Observability & Compliance**
- **Real-time governance dashboard** — Live event feed, HITL approve/deny UI, memory browser, fleet view, audit log, trace viewer.
- **Prometheus metrics** — Decision counters, HITL queue gauges, gate latency histograms with Grafana dashboards.
- **Managed SIEM connectors** — Splunk HEC, Datadog, Elastic with retry and backpressure.
- **Compliance export packs** — One-click SOC 2, HIPAA, FedRAMP audit evidence in PDF/CSV/JSON.
- **Policy intelligence dashboard** — Decision heatmaps, anomaly detection, session risk scoring, HITL SLA tracking.

**Fleet & Operations**
- **Governance Gateway** — Centralized HTTP API for policy enforcement across multiple agents. REST endpoints for HITL approval.
- **Multi-agent Orchestrator** — Spawn and coordinate multiple governed agent sessions with delegation chains.
- **Agent fleet management** — Real-time inventory, remote kill switch, canary policy deployments.
- **Multi-tenant policy isolation** — Namespace-isolated OPA bundles per team. Central registry with inheritance.
- **Cross-agent governance** — Org-wide budgets, concurrent access limits, coordinated deny policies.
- **Policy simulation** — Replay historical sessions against proposed policy changes before deploying.
- **Governance marketplace** — Community and enterprise compliance packs.

The enterprise model: OSS proves the value on a single agent. Enterprise scales it across the organization.

For enterprise licensing: [licensing@kitelogik.com](mailto:licensing@kitelogik.com)

---

## Competitive Positioning

Kite Logik is **not competing** with Promptfoo, Guardrails AI, or NeMo Guardrails. They are complementary:

- **Promptfoo** tests whether your LLM is safe (pre-deployment)
- **Guardrails AI** validates LLM outputs (content quality)
- **NeMo Guardrails** controls conversation flow (dialog safety)
- **Kite Logik** enforces what agents can **do** (runtime governance)

The positioning: *"Use Promptfoo to test your prompts. Use Guardrails AI to validate your outputs. Use Kite Logik to govern what your agents actually execute."*

**What no competitor has:** OPA/Rego policy-as-code, HITL escalation, session-scoped credentials with delegation, agent lifecycle governance, plan-before-execute, delegation chain enforcement, memory provenance tracking, YAML policy frontend, 11 framework adapters out of the box.

---

## The Brand Message

**Kite Logik — The governance control plane for AI agents.**

The core thesis: as agents move from demos to production, the question shifts from "can this agent do the task?" to "should this agent be allowed to do the task?" Kite Logik answers the second question at the infrastructure level, where it can't be prompt-injected away.
