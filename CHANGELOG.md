# Changelog

All notable changes to Kite Logik are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Changed
- **Enterprise split** — Moved dashboard, gateway, orchestrator, sandbox, SIEM, Prometheus metrics, MCP mock server, Anchor REST API, and Postgres backends to the `kitelogik-enterprise` package. OSS now focuses on the core governance pipeline: embedded SDK, policy engine, HITL queue, credentials, audit, memory, and 11 framework adapters.
- `AgentSession` simplified — removed `gateway_client`, `sandbox_manager`, and `mcp_client` parameters. Sessions now use in-process `PolicyGate` only.
- `Orchestrator` and `OrchestratorResult` removed from `kitelogik` public API — available via `kitelogik-enterprise`.

### Added

#### Tether — Policy Engine Enhancements
- **RegorusClient** — In-process Rego evaluator using the regorus (Rust) engine; experimental — requires building regoruspy from source (see [microsoft/regorus](https://github.com/microsoft/regorus))
- **HierarchicalEvaluator** — 2-tier policy hierarchy (global + project) with deny-overrides semantics and resolution traces
- **YAML policy compiler** — Write policies in YAML, compile to Rego with `kitelogik compile`; JSON Schema validation via `kitelogik validate`

#### Framework Adapters (9 new)
- **BaseGovernedAdapter** — Extracted base class centralizing the governance pipeline for all adapters
- **CrewAI** adapter (`kitelogik/adapters/crewai.py`)
- **OpenAI Agents SDK** adapter (`kitelogik/adapters/openai_agents.py`)
- **LangGraph** adapter (`kitelogik/adapters/langgraph.py`)
- **Google ADK** adapter (`kitelogik/adapters/google_adk.py`)
- **PydanticAI** adapter (`kitelogik/adapters/pydantic_ai.py`)
- **LlamaIndex** adapter (`kitelogik/adapters/llamaindex.py`)
- **Semantic Kernel** adapter (`kitelogik/adapters/semantic_kernel.py`)
- **Haystack** adapter (`kitelogik/adapters/haystack.py`)
- **Dify** adapter (`kitelogik/adapters/dify.py`)

#### CLI Enhancements
- `kitelogik compile` — YAML → Rego policy compilation
- `kitelogik validate` — JSON Schema validation of YAML policies
- `kitelogik compliance` — Governance compliance audit with OWASP Agentic Security Initiative mapping

#### Observability
- **Prometheus metrics** (`observability/metrics.py`) — Policy decision counters, HITL queue gauges, gate latency histograms

#### Policies
- **Starter policy library** (`policies/library/`) — 5 ready-to-use policies with OPA tests: tool_allowlist, pii_protection, read_only, cost_cap, rate_limiting

#### PostgreSQL Backends
- Postgres backends for HITL queue, credentials, memory, and audit now included in OSS (previously enterprise-only staging)

### Changed
- All public API docstrings converted to numpy-style format for consistency
- `PolicyEvaluator` protocol now implemented by OPAClient, RegorusClient, and HierarchicalEvaluator
- `HierarchicalEvaluator` and `ResolutionStep` exported from top-level `kitelogik` package

### Fixed
- **Memory sanitization tier mismatch** — Postgres memory store now sanitizes `DELEGATED` tier data, aligning with SQLite backend behaviour
- **Fragile asyncpg result parsing** — `postgres_queue.py` `_decide()` now handles unexpected status string formats with try/except instead of bare `int()` conversion

### Tests
- Test count: 352 → 681 (42 test files)
- Added: fuzz tests (gateway parsing, policy input, sanitizer), adapter tests, hierarchy tests, Regorus tests, CLI tests, policy compiler tests, metrics tests, MCP stdio tests
- 13 OPA Rego test files (8 core + 5 library)

---

## [0.1.0] — 2026-03-27

Initial OSS release.

### Added

#### Tether — Policy Gate
- OPA/Rego policy engine integration via HTTP; fail-closed on OPA unreachability (returns `deny=True, risk_tier=SECURITY_CRITICAL`)
- Deny-by-default enforcement — every policy file opens with `default allow := false`
- Five risk tiers: `INFORMATIONAL` → `OPERATIONAL` → `TRANSACTIONAL_HIGH` → `DESTRUCTIVE` → `SECURITY_CRITICAL`
- Scope-based and role-based policy evaluation on every tool call
- Schema validation of tool call inputs before OPA evaluation
- Financial policy domain (`financial.rego`): refund thresholds, read/write/notification rules
- Security policy domain (`security.rego`): blocked file extensions, system path blocking, path traversal prevention, shell execution gating
- Delegation policy domain (`delegation.rego`): delegation depth cap, per-depth refund caps
- Main aggregation policy (`main.rego`): hard-deny overrides are final
- Type guards on all numeric fields — prevents null/bool/string/negative amount bypass
- OpenTelemetry span on every gate evaluation with per-stage child spans (credential validation → schema → OPA)
- `rule_matched` field in every `PolicyDecision` — identifies the specific Rego rule that fired

#### Anchor — Human-in-the-Loop Queue
- Async HITL queue backed by SQLite; agent suspends on `asyncio.Event` (not a polling loop)
- Full action lifecycle: `PENDING` → `APPROVED` / `DENIED` / `TIMED_OUT`
- Configurable per-session HITL timeout (default 300s)
- Background expiry task with consecutive-failure escalation to CRITICAL logging
- Decision metadata: `decided_by`, `decided_at`, `denial_reason`
- REST API: `GET /api/pending`, `POST /api/decide/{id}`
- One-click approve/deny from the live dashboard

#### Sandbox — Container Isolation
- Per-session Docker container; spawned at session start, torn down in `finally` block
- `network_mode=none` — all egress blocked by default
- CPU, memory, and PID limits enforced at container creation
- `sandbox_verified` flag gating code execution (enforced in `security.rego`)

#### Credentials — Session Token Management
- Short-lived session tokens with explicit scopes and TTL
- In-memory `CredentialBroker` and SQLite-backed `PersistentCredentialBroker`
- Token revocation at session end; validated on every gate call
- Delegation: child scopes must be ⊆ parent scopes; child cannot outlive parent
- Delegation depth tracked in session context and enforced by OPA (max depth 2)

#### Memory — Provenance-Tracked Agent Memory
- SQLite-backed memory store with async I/O
- Five trust tiers: `INTERNAL` → `VERIFIED` → `DELEGATED` → `EXTERNAL` → `UNTRUSTED`
- Provenance metadata on every write: `source`, `session_id`, `trust_tier`, `created_at`
- Auto-sanitization on writes from untrusted tiers; `sanitized` flag stored per entry
- Session-scoped reads enforced — non-empty `session_id` required

#### Injection Defence
- Indirect prompt injection detection: instruction override phrases, system prompt probes, role overrides
- Tool output sanitized before entering agent context
- Memory writes sanitized at untrusted trust tiers
- Command injection pattern detection in tool arguments
- 12-payload adversarial corpus; 7 benign counter-examples confirming no false positives

#### Audit — Immutable Logging
- Append-only SQLite audit store; immutability enforced by database trigger (no `UPDATE`/`DELETE`)
- Every tool call recorded with `PolicyDecision`, policy version SHA, session context
- `PolicyReplayer`: re-evaluate historical records against current policy; `outcome_changed` flag per record
- Session export with SHA-256 integrity hash

#### Observability
- OpenTelemetry instrumentation (GenAI Semantic Conventions v1.37+)
- File trace exporter by default; OTLP/HTTP export via `--otlp <url>` flag
- Session ID correlated across all spans
- Policy version SHA on every gate span

#### MCP Integration
- Async JSON-RPC 2.0 MCP client with tool discovery and dispatch
- Supply chain integrity verification: SHA-256 manifest checks on MCP server packages
- Response sanitization before tool output enters agent context
- Mock MCP server for demos and testing

#### Gateway — MCP Standalone Service
- FastAPI gateway with full governance pipeline: token auth → schema → OPA → tool dispatch → sanitize → audit
- Endpoints: `POST /v1/tools/call`, `GET /v1/tools/list`, `GET /v1/hitl/{id}/status`, `POST /v1/hitl/{id}/approve|deny`, `POST /v1/agents/{id}/kill`, `GET /v1/fleet/status`, `GET /v1/audit/export`, `GET /v1/health`
- Kill switch: revokes all sessions for an agent; per-session failure tracking with `CRITICAL` logging
- Bearer token authentication on all endpoints

#### Agent Session and Orchestration
- `AgentSession` — direct mode (in-process `PolicyGate`) and gateway mode (HTTP)
- Session token issued at start, revoked in `finally` block
- Sandbox lifecycle managed alongside session lifecycle
- `Orchestrator` class for multi-agent coordination with scope-narrowed child tokens
- 13 pre-built demo scenarios covering `ALLOW`, `BLOCK`, `HITL`, delegation, injection

#### Adapters
- `@governed` decorator and `GovernedToolbox` for inline policy enforcement
- `OpenAIAdapter`: wraps `tool_calls` array; governance before execution
- `LangChainAdapter`: `as_governed_tool()` and `govern_toolkit()` for `BaseTool` wrapping

#### Dashboard
- Real-time WebSocket live feed of gate decisions
- HITL queue panel with approve/deny controls
- Memory viewer with trust tiers per session
- Fleet view of all active sessions

#### Infrastructure
- `pyproject.toml` with ruff, pytest, coverage configuration; `asyncpg` as optional `[postgres]` extra
- `Makefile` targets: `demo`, `demo-enterprise`, `test`, `landing`
- Docker Compose stack: `opa`, `dashboard`, `mcp-mock`; enterprise profile adds Grafana + Tempo
- GitHub Actions CI: ruff lint, unit tests on Python 3.11 and 3.12, OPA native policy tests

#### Tests
- 352 unit tests across 23 test files
- 36 OPA native policy tests (`opa test kitelogik/policies/ -v`)
- 41 policy bypass adversarial tests (type coercion, path traversal, session boundary, delegation escalation)
- 12-payload injection corpus
- Full-stack integration tests (require Docker + OPA)
- 79% line coverage (threshold enforced at 75%)

### Security

- Fail-closed policy gate: OPA unreachability returns hard block, never an accidental allow
- Database-level immutability on audit log (trigger prevents `UPDATE`/`DELETE`)
- All shell commands constructed from agent input rejected at policy layer — no f-string shell construction
- MCP supply chain verification before any server is registered
- Session tokens scoped to minimum required permissions; revoked on session end

[Unreleased]: https://github.com/kitelogik/kitelogik/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kitelogik/kitelogik/releases/tag/v0.1.0
