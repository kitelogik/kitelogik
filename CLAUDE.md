# Kite Logik — CLAUDE.md

## What This Project Is

Kite Logik is the **governance control plane for autonomous AI agents.** It governs what agents can do, what they can spawn, what they can access, and what resources they can consume — enforced at the infrastructure level, not the prompt level.

Where other guardrails tools validate LLM outputs or test prompts, Kite Logik governs the **agent itself**: its lifecycle, its tool access, its delegation authority, its data access patterns, and its resource consumption. Rules are enforced by the environment. The model has no override.

### The Two Layers (OSS)

1. **Tether (Policy Engine)** — The policy enforcement layer. An OPA/Rego engine that evaluates every governance event (tool calls, agent spawn, delegation, plan submission, resource checks) against deterministic business rules. Returns allow, deny, or escalate. Enforcement is infrastructure-level — the model cannot override a deny.

2. **Anchor (Oversight)** — An async Human-in-the-Loop escalation queue, credential broker, and OpenTelemetry-based observability stack. HITL is reserved for high-stakes situations (high-value transactions, restricted data access, security-critical actions) — it is not the default governance path. The default path is: OPA evaluates, allow or deny, zero human delay.

> **Sandbox (Isolation)** — Container-based execution environments with hardened resource limits and network isolation. Available in **Kite Logik Enterprise** (Docker, gVisor, Firecracker MicroVM runtimes).

### Deployment Modes

| Mode | Pattern | How It Works |
|---|---|---|
| **Embedded SDK** | Library | `@governed` decorator, `GovernedToolbox`, framework adapters. Runs in-process with the agent. Zero network hop for policy evaluation. |

> **Governance Gateway** (centralized HTTP API enforcement) and **Control Plane** (agent lifecycle orchestration, delegation chains, resource budgets) are available in **Kite Logik Enterprise**.

### What Kite Logik Governs

| Event Type | What's Evaluated | Example Policy |
|---|---|---|
| `tool_call` | Every tool invocation before execution | "Block file writes outside /tmp" |
| `agent.spawn` | Agent creation with specified capabilities | "Max delegation depth is 2" |
| `agent.delegate` | Agent-to-agent task delegation | "Child scopes must be subset of parent" |
| `agent.plan` | Proposed sequence of actions before any execute | "Deny plans with > 20 steps" |
| `agent.resource` | Resource consumption checks | "Deny if session budget exhausted" |

All event types flow through the same pipeline: Credential validation → Schema validation → OPA evaluation → PolicyDecision.

## Domain Vocabulary

Use this terminology consistently throughout the codebase and documentation:

| Term | Meaning |
|---|---|
| **Agent session** | A single scoped execution of an AI agent — spun up in an isolated container, destroyed on completion |
| **Tether** | The policy enforcement layer that evaluates governance events against OPA/Rego rules |
| **Policy gate** | The OPA evaluation step that allows or denies a governance event |
| **Governance event** | Any agent action that requires policy evaluation: tool call, spawn, delegate, plan, resource check |
| **Sandbox** | The container (Docker now; Firecracker MicroVM in production) isolating a single agent session |
| **Anchor** | The HITL escalation mechanism — reserved for high-stakes situations, not the default path |
| **Risk tier** | The classification of an action (Informational / Operational / Transactional / Destructive / Security-Critical) |
| **Trust tier** | The trust level assigned to a data source feeding into agent memory |
| **MCP server** | A Model Context Protocol server exposing tools to the agent |
| **Session token** | A short-lived, scoped credential issued per agent session and revoked on completion |
| **Governance Gateway** | The HTTP API that agents call tools through for centralized enforcement |
| **Plan gate** | Pre-execution evaluation of an agent's proposed sequence of actions |
| **Delegation chain** | The parent → child agent relationship with scope narrowing and depth limits |

## Architecture Principles

These govern every technical decision in this codebase:

1. **Infrastructure enforces, prompts inform.** Never rely on model behavior as a security boundary. All enforcement is deterministic and infrastructure-level.
2. **Govern the agent, not just the tool call.** Lifecycle events (spawn, delegate, plan, terminate) are governance events — they flow through the same policy pipeline as tool calls.
3. **Least privilege by default.** Agent sessions get the minimum tool access, network access, and credential scope required for their task. Expand explicitly, never implicitly. Child agents inherit a strict subset of parent capabilities.
4. **Deny-by-default everything.** OPA policies default-deny. Network egress is blocked. Credential scopes are empty until granted. Plans are evaluated before execution.
5. **Every tool output is untrusted.** MCP server responses must be sanitized before returning to agent context. Indirect prompt injection via tool output is the primary attack vector.
6. **Memory has provenance.** Every write to agent memory carries source, session ID, trust tier, and timestamp metadata. Memory from external tool outputs has lower trust than memory from internal verified systems.
7. **Observability is not optional.** Every governance event, policy decision, memory event, and HITL trigger is traced via OpenTelemetry and correlated by session ID.
8. **HITL is the exception, not the default.** Human review gates are for high-stakes situations — high-value transactions, restricted data, security-critical actions. The default governance path adds zero human latency.

## Technology Stack

- **Policy engine:** Open Policy Agent (OPA) with Rego policies
- **Observability:** OpenTelemetry (GenAI Semantic Conventions v1.37+)
- **Tool protocol:** Model Context Protocol (MCP)
- **Credential management:** In-process broker with SQLite persistence (OSS); HashiCorp Vault or AWS STS (enterprise)
- **Language:** Python 3.11+ (this repo)
- **AI SDK:** Anthropic Python SDK (claude-sonnet-4-6 default, claude-opus-4-6 for complex reasoning)
- **Framework adapters:** 11 shipped adapters (Anthropic, OpenAI, LangChain, LangGraph, CrewAI, OpenAI Agents SDK, Smolagents, Google ADK, AG2, AWS Strands, Pydantic AI)

## Security Non-Negotiables

Do not write code that violates these:

- Never log raw prompt content, tool arguments, or model outputs without sanitization — these may contain sensitive business data
- Never hardcode credentials or API keys — all secrets are injected at session start via the credential broker
- Never trust MCP server responses as safe to pass directly to the agent — always sanitize
- Never write a policy rule that has a default-allow fallback — OPA policies must default-deny
- Never open a network socket from within a sandbox without a corresponding whitelist entry
- All shell commands constructed from agent-provided input must be sanitized before execution (no f-string shell construction)

## Key Threat Model

When writing or reviewing code, keep these attack classes in mind:

- **Indirect prompt injection:** Malicious instructions embedded in tool responses, documents, or database records the agent reads
- **Memory poisoning:** Malicious records injected into agent long-term memory via query interactions (MINJA attack pattern)
- **MCP supply chain:** Compromised or malicious MCP server packages silently exfiltrating data
- **Privilege escalation:** Agent attempting to access resources beyond its session token scope
- **Credential leakage:** Session tokens surviving beyond session expiry
- **Delegation abuse:** Child agents attempting to expand beyond parent-granted scopes or exceed depth limits
- **Runaway agents:** Agents executing unbounded tool call sequences without plan governance

## Project File Conventions

- `kitelogik/` — All source code lives under this namespace
- `kitelogik/tether/` — Policy enforcement layer: governance event model, OPA evaluation, output sanitization
- `kitelogik/anchor/` — HITL queue, credential broker, session token management
- `kitelogik/memory/` — Agent memory store with provenance metadata
- `kitelogik/observability/` — OpenTelemetry instrumentation
- `kitelogik/mcp/` — MCP client, server registry, BOM management, response sanitization
- `kitelogik/agents/` — Agent session, LLM client, tool dispatch
- `kitelogik/audit/` — Immutable, append-only audit log with SQL trigger enforcement
- `kitelogik/policies/` — OPA Rego policy files. One file per domain. Always include `default allow := false`.
- `kitelogik/policies/library/` — Starter policy library. Ready-to-use policies with tests and examples.
- `kitelogik/governed.py` — `@governed` decorator, `GovernedToolbox`
- `kitelogik/adapters/` — Framework adapters (Anthropic, OpenAI, LangChain, CrewAI, etc.)
- `kitelogik/cli.py` — CLI entry point

## Working Style

- Read existing policy files before writing new Rego rules — consistency across the policy set matters
- When adding a new governance event type, the flow is: add to `GovernanceEvent` model → write Rego policy → add OPA tests → wire into the relevant module → add Python tests
- When adding a new tool integration, the flow is: MCP server entry in BOM → schema definition → Rego policy rule → sanitization handler → OPA test
- When in doubt about a security boundary, default to the more restrictive option and document why
- Do not add error handling that silently swallows policy violations — surface them explicitly to the observability layer
- HITL should only be triggered by explicit `requires_hitl := true` in Rego policy — never as a default fallback
