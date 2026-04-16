# Kite Logik OSS — Complete Feature Inventory

> Features marked with **[REVIEWED]** have completed a full code review with all fixes implemented.

## Tether (Policy Engine) **[REVIEWED]**

- **PolicyGate** — Three-stage enforcement pipeline: credential validation → schema validation → OPA evaluation
- **OPAClient** — Async HTTP client with fail-closed behavior (deny-all when OPA unreachable); URL scheme validation at init; narrowed exception handlers
- **Response Sanitizer** — Detects and redacts 10 indirect prompt injection patterns in tool output; NFKC unicode normalization for zero-width character bypass prevention; ReDoS-resistant regex patterns (verified)
- **Governance Event Model** — Unified types with Literal-typed `event_type`: `tool_call`, `agent.spawn`, `agent.delegate`, `agent.plan`, `agent.budget`
- **Risk Tier Classification** — Informational / Operational / Transactional / Destructive / Security-Critical
- **RegorusClient** — In-process Rego evaluator via regorus (Rust); experimental — requires building from source; same `PolicyEvaluator` protocol as OPAClient
- **HierarchicalEvaluator** — 2-tier global + project policy hierarchy with deny-overrides semantics and resolution traces
- **YAML Policy Compiler** — Write policies in YAML, compile to Rego with `kitelogik compile`; JSON Schema validation via `kitelogik validate`

## Sandbox (Isolation) **[REVIEWED]**

- **SandboxManager** — Per-session container lifecycle (spawn, exec, teardown); guaranteed cleanup via finally blocks
- **DockerRuntime** — Hardened containers: 256MB RAM, 50% CPU, 64 procs, read-only FS, cap-drop, no-new-privileges; all hardening flags unconditional
- **Network Isolation** — ISOLATED (no network) or ALLOWLIST (named bridge per session)
- **gVisor Support** — `runsc` runtime via `SANDBOX_RUNTIME` env var
- **Firecracker Extension Point** — Enterprise plugin hook for MicroVM runtime

## Anchor (HITL + Credentials) **[REVIEWED]**

- **CredentialBroker** — Session-scoped token issue, revoke, validate, bulk revoke; CSPRNG token generation; expiry enforced on every validation
- **PersistentCredentialBroker** — SQLite-backed variant with WAL mode and persistence across restarts
- **Token Delegation** — Child tokens with scopes ⊆ parent scopes, depth tracking; one-way revocation
- **HITLQueue** — Async SQLite-backed queue with WAL mode: enqueue, decide (approve/deny), poll status, list pending; decisions immutable once recorded
- **Blocking HITL Waits** — `asyncio.Event`-based blocking for agent sessions awaiting decisions
- **Anchor API** — Input validation on all endpoints, narrowed exception handlers, sanitized error messages

## Memory (Agent Memory with Provenance) **[REVIEWED]**

- **MemoryStore** — SQLite key-value store with WAL mode and trust tier metadata (INTERNAL / DELEGATED / EXTERNAL / UNTRUSTED)
- **Automatic Sanitization** — External/untrusted/delegated sources sanitized on write; no bypass path
- **Provenance Tracking** — Every entry carries source, session ID, trust tier, timestamps

## Observability (OpenTelemetry) **[REVIEWED]**

- **Tracer Setup** — Configurable pipeline: in-memory ring buffer (500 spans) + optional OTLP/file export; no raw prompt/args in spans
- **Span Metrics** — Per-stage latency, session correlation, policy decision attributes (metadata only)
- **SIEMWebhook** — *Enterprise Edition* — Fire-and-forget event emitter with retry/backoff for Splunk HEC, Elastic, generic JSON
- **Prometheus Metrics** — *Enterprise Edition* — Policy decision counters, HITL queue gauges, gate latency histograms

## MCP (Model Context Protocol) **[REVIEWED]**

- **MCPClient** — Async JSON-RPC 2.0 tool executor with governance validation; narrowed exception handlers
- **Supply Chain Verification** — SHA-256 manifest hashing; blocklist on mismatch (`MCPSupplyChainError`)
- **ServerRegistry** — Bill of Materials (registry.json) with tool → server lookup
- **StdioTransport** — Subprocess-based MCP server with stdin/stdout JSON-RPC; no shell injection (`create_subprocess_exec` with list args); modern asyncio API
- **Response Sanitization** — All MCP responses sanitized before returning to agent context

## Gateway (Governance Gateway HTTP API) — *Enterprise Edition*

- **`/v1/tools/call`** — Full enforcement pipeline: auth → schema → OPA → dispatch → sanitize → audit
- **`/v1/tools/list`** — Available tools with risk tiers
- **HITL Endpoints** — `/v1/hitl/{id}/status`, `/approve`, `/deny`; input validation on all path params; sanitized error messages
- **`/v1/health`** — Service health + OPA connectivity + pending HITL count
- **Framework Adapters** — Gateway clients for OpenAI, Anthropic, MCP
- **GatewayClient** — Async HTTP client with retry/backoff; no response body leakage in error messages

## Agents (Session & Orchestration) **[REVIEWED]**

- **AgentSession** — Core execution loop: governance checks → tool dispatch → sanitize → audit, with enforced max_iterations
- **Orchestrator** — *Enterprise Edition* — Multi-agent delegation: `delegate()` (serial) and `delegate_parallel()` (fan-out)
- **Delegation Invariants** — Scope narrowing, depth tracking, parent-child session chaining; all output sanitized before agent context
- **AgentRegistry** — Durable agent identity store with register, lookup, kill switch
- **Dual Mode** — Direct (in-process PolicyGate); Gateway mode available in Enterprise Edition
- **Mock Tools** — read_customer_record, approve_refund, send_notification, read_file, execute_code, query/write_memory

## Audit (Immutable Log) **[REVIEWED]**

- **AuditStore** — SQLite append-only log with WAL mode and SQL trigger enforcement (no UPDATE/DELETE); all queries parameterized
- **Policy Version Tracking** — SHA-256 hash of all .rego files recorded per decision
- **Session Export** — Compliance report with integrity hash
- **PolicyReplayer** — Re-evaluate historical records against current policy to detect regressions; read-only (no mutations during replay)

## Dashboard (Real-time UI) — *Enterprise Edition*

- **WebSocket Event Streaming** — Bidirectional stream with in-memory buffer (500) + SQLite persistence (1000); wss:// auto-detection; 300s idle timeout
- **REST Endpoints** — Health, liveness probe, HITL queue, memory browser, trace viewer, CSV session export
- **Security** — CORS middleware, optional bearer token auth, CSP + security response headers, CSRF protection, input validation on all endpoints
- **Frontend** — Real-time event stream, HITL approve/deny UI, trace waterfalls, memory browser
- **Deployment** — Separate liveness/readiness probes, graceful shutdown, localhost-only Docker port binding, resource limits
- **Dual Mode** — Demo (owns HITL directly) or Gateway (proxies to external Gateway)

## SDK (`kitelogik` package) **[REVIEWED]**

- **`@governed` Decorator** — Wraps sync/async functions with policy gate enforcement; no bypass path to underlying function
- **`GovernedToolbox`** — Framework-agnostic tool registry with governance-before-dispatch; return values sanitized
- **Framework Adapters** — 11 adapters: OpenAI, Anthropic/Claude, LangChain, LangGraph, CrewAI, OpenAI Agents SDK, Google ADK, PydanticAI, LlamaIndex, Semantic Kernel, Haystack, Dify
- **BaseGovernedAdapter** — Extracted base class centralizing the governance pipeline for all adapters
- **CLI** — `kitelogik validate`, `test`, `check`, `version`, `compile`, `compliance`; no command injection (list-form subprocess calls)
- **Policy Tester** — Interactive Rego development tool (`python -m kitelogik.policy_tester`)
- **Edition Detection** — Plugin system for enterprise extensions via standard entry points

## Policies (OPA Rego) **[REVIEWED]**

- **Core Policies (8):** main, security, delegation, financial, agent_lifecycle, agent_plan, agent_budget, data_classification
- **Policy Library (5):** tool_allowlist, pii_protection, read_only, cost_cap, rate_limiting — each with OPA unit tests
- **13 OPA test files** — 8 core + 5 library, all passing
- **Default-deny everywhere**, hard-deny overrides (every `allow` guarded by `not deny`), HITL escalation rules, role-based thresholds
- **194 OPA tests** all passing

## Tests

- **681 tests** across 42 test files
- **Adversarial tests** — prompt injection attempts, unicode evasion payloads, policy bypass attempts, scope violation attempts
- **Fuzz tests** — gateway parsing, policy input, sanitizer (Hypothesis-based)
- **Adapter tests** — CrewAI, Google ADK, LangGraph, OpenAI Agents SDK, PydanticAI, new adapters
- **Integration tests** — multi-tool sessions, full HITL flows, e2e with Anthropic SDK
- **Benchmark** — policy gate latency profiling

## Enterprise Edition Features

The following have been moved to the [Kite Logik Enterprise](https://github.com/kitelogik/kitelogik-enterprise) repository:

- Dashboard (real-time UI with WebSocket event streaming)
- Governance Gateway (centralized HTTP enforcement API)
- Multi-agent Orchestrator
- Sandbox runtime management
- SIEM webhook dispatchers (Splunk HEC, Datadog, Elastic)
- Prometheus metrics
- MCP mock server
- Anchor REST API
- PostgreSQL backends for credentials, HITL, memory, audit
- Entry-point plugin groups: sandbox_runtime, memory_backend, hitl_backend, credential_broker, audit_backend
