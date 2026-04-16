# Kite Logik — Complete Feature List

Status markers: **[Built]** = implemented and tested · **[Planned]** = on the roadmap, not yet built

---

## Open Source Edition

### Tether — Policy Gate

| Feature | Status | Notes |
|---|---|---|
| OPA/Rego policy engine integration | **[Built]** | Via HTTP to local/remote OPA instance |
| Deny-by-default enforcement | **[Built]** | Every policy file opens with `default allow := false` |
| Risk tier classification | **[Built]** | INFORMATIONAL → OPERATIONAL → TRANSACTIONAL_LOW → TRANSACTIONAL_HIGH → DESTRUCTIVE → SECURITY_CRITICAL |
| Scope-based access control | **[Built]** | Session scopes checked in every policy rule |
| Role-based policy rules | **[Built]** | `user_role` field in session context evaluated by OPA |
| Type guards on numeric fields | **[Built]** | `is_number()` guard blocks null/bool/string/negative amounts |
| Fail-closed on OPA unreachability | **[Built]** | Returns `deny=True, risk_tier=SECURITY_CRITICAL` if OPA is down |
| Schema validation before OPA evaluation | **[Built]** | Tool call input validated against schema before policy check |
| OTel span on every gate evaluation | **[Built]** | span attributes: tool name, risk tier, outcome, session ID, latency |
| Per-tool schema definitions | **[Built]** | Each tool has a registered input schema |
| Financial policy domain | **[Built]** | `financial.rego`: refunds, read, notifications, memory |
| Security policy domain | **[Built]** | `security.rego`: file extensions, path blocking, path traversal, shell execution |
| Delegation policy domain | **[Built]** | `delegation.rego`: depth cap, refund cap per depth |
| Main aggregation policy | **[Built]** | `main.rego`: combines all sub-policies, hard-deny overrides |
| Hot policy reload | **[Built]** | OPA `--watch` flag reloads policies on file change |
| `rule_matched` in policy decision | **[Built]** | Identifies which specific Rego rule allowed or denied |
| Policy examples directory | **[Built]** | `kitelogik/kitelogik/policies/examples/` — 3 annotated files with 7/6/9 embedded OPA tests each; all pass `opa test` |
| Policy test CLI (`policy_tester.py`) | **[Built]** | `kitelogik/policy_tester.py` — load policy + input → prints decision + latency |
| OPA bundle distribution support | **[Built]** | `docs/opa-bundle-guide.md` — S3/GCS/nginx, signing, Kubernetes, rollback workflow |

---

### Anchor — Human-in-the-Loop Queue

| Feature | Status | Notes |
|---|---|---|
| Async HITL queue (SQLite) | **[Built]** | `HITLQueue`: append-only enqueue, event-based wakeup |
| Agent suspension on HITL actions | **[Built]** | Agent blocks on `asyncio.Event`, not a polling loop |
| Configurable HITL timeout | **[Built]** | Default 300s; configurable per session |
| Background expiry task | **[Built]** | Marks overdue PENDING actions as TIMED_OUT, wakes agents |
| Action lifecycle: PENDING → APPROVED/DENIED/TIMED_OUT | **[Built]** | Full status machine with timestamps |
| Decision metadata | **[Built]** | `decided_by`, `decided_at`, `denial_reason` recorded |
| HITL REST API | **[Built]** | `GET /api/pending`, `POST /api/decide/{id}` |
| HITL approve/deny from dashboard | **[Built]** | Dashboard UI surfaces pending actions with one-click decision |
| HITL action visible to agent after approval | **[Built]** | Approved result returned as tool output to the waiting agent |
| Timed-out actions treated as deny | **[Built]** | Agent receives hard block on timeout |

---

### Sandbox — Container Isolation

| Feature | Status | Notes |
|---|---|---|
| Per-session Docker container | **[Built]** | One container per `AgentSession`, torn down on completion |
| Network isolation (`network_mode=none`) | **[Built]** | All egress blocked by default |
| Resource limits (CPU, memory, PID) | **[Built]** | Applied at container creation |
| `sandbox_verified` flag in session context | **[Built]** | Set after container health confirmation |
| Code execution blocked without sandbox | **[Built]** | OPA `security.rego` hard-blocks `execute_code` without flag |
| Container teardown in `finally` block | **[Built]** | Guaranteed cleanup even on exception or cancellation |
| Docker runtime | **[Built]** | Current production runtime |
| gVisor (`runsc`) runtime | **[Built]** | `SANDBOX_RUNTIME=gvisor` wires `runtime=runsc`; `SandboxRuntime` enum in `sandbox/models.py` |
| Firecracker MicroVM runtime | **[Planned]** | Raises `NotImplementedError` with clear message; `SandboxRuntime.FIRECRACKER` enum value reserved |

---

### Credentials — Session Token Management

| Feature | Status | Notes |
|---|---|---|
| Short-lived session tokens | **[Built]** | Issued per session with explicit scopes and TTL |
| In-memory credential broker | **[Built]** | Default: `CredentialBroker` (process-local) |
| SQLite persistent credential broker | **[Built]** | `PersistentCredentialBroker`: survives restarts |
| Token validation on every gate call | **[Built]** | `validate()` checks active/expired status before evaluation |
| Token revocation at session end | **[Built]** | Revoked in `AgentSession.finally` block |
| Delegation: scope subset enforcement | **[Built]** | Child scopes must be ⊆ parent scopes; enforced in `delegate()` |
| Delegation: child cannot outlive parent | **[Built]** | Child `expires_at` capped to parent's |
| Delegation depth in session context | **[Built]** | `delegation_depth` carried forward and checked by OPA |
| Maximum delegation depth (2) | **[Built]** | OPA `delegation.rego` hard-blocks depth > 2 |
| Delegation depth-1 refund cap ($50) | **[Built]** | OPA `delegation.rego` enforces reduced financial cap |
| Delegation depth-2 refund block | **[Built]** | Depth-2+ delegates cannot approve any refunds |

---

### Memory — Provenance-Tracked Agent Memory

| Feature | Status | Notes |
|---|---|---|
| SQLite-backed memory store | **[Built]** | Async via `asyncio.to_thread` |
| Trust tier classification | **[Built]** | INTERNAL / VERIFIED / DELEGATED / EXTERNAL / UNTRUSTED |
| Provenance metadata on every write | **[Built]** | `source`, `session_id`, `trust_tier`, `created_at`, `updated_at` |
| Auto-sanitization on untrusted writes | **[Built]** | EXTERNAL/DELEGATED/UNTRUSTED values pass through injection sanitizer |
| `sanitized` flag stored per entry | **[Built]** | Readable by consumers; original value never stored |
| Session-scoped memory reads | **[Built]** | `query_memory` requires non-empty `session_id` |
| OPA access control on memory reads | **[Built]** | `query_memory` is a governed tool call like any other |
| OPA access control on memory writes | **[Built]** | `write_memory` requires `memory_write` scope |

---

### Injection Defence — Sanitization

| Feature | Status | Notes |
|---|---|---|
| Indirect prompt injection detection | **[Built]** | Instruction override phrases, system prompt probes, role overrides |
| Tool output sanitization | **[Built]** | MCP responses sanitized before entering agent context |
| Memory write sanitization | **[Built]** | Applied at write time for untrusted trust tiers |
| Command injection pattern blocking | **[Built]** | Detects shell metacharacters in tool arguments |
| Adversarial injection corpus tests | **[Built]** | 12 real-world payloads verified caught; 7 benign counter-examples |
| Sanitizer false-positive tests | **[Built]** | Verifies legitimate content is not stripped |

---

### Security Policy Hardening

| Feature | Status | Notes |
|---|---|---|
| Blocked file extensions | **[Built]** | `.env`, `.pem`, `.key`, `.secret` — unconditional hard deny |
| Blocked system paths | **[Built]** | `/etc`, `/proc`, `/sys`, `/root`, `/var/run` — unconditional hard deny |
| Path traversal blocking | **[Built]** | `../` sequences in any argument — unconditional hard deny |
| Cross-session access prevention | **[Built]** | `args.session_id` must match `context.session_id` |
| Shell/code execution without sandbox | **[Built]** | Hard block unless `sandbox_verified=true` in context |
| String/null/bool amount bypass prevention | **[Built]** | `is_number()` guard in OPA; type coercion attacks fail |
| Negative amount bypass prevention | **[Built]** | `amount >= 0` guard alongside `is_number()` |

---

### Observability

| Feature | Status | Notes |
|---|---|---|
| OpenTelemetry instrumentation | **[Built]** | GenAI Semantic Conventions v1.37+ |
| File trace exporter | **[Built]** | Default; no external collector required |
| OTLP/HTTP trace exporter | **[Built]** | `--otlp <url>` flag on demo script |
| Session ID correlation across all spans | **[Built]** | `session.id` attribute on every span |
| Gate evaluation spans | **[Built]** | Credential validation → schema → OPA evaluation stages |
| HITL event spans | **[Built]** | Enqueue, decision, timeout events traced |
| Memory event spans | **[Built]** | Read and write operations traced |
| Tool execution spans | **[Built]** | Execution latency and outcome traced |
| Policy version in trace attributes | **[Built]** | `policy.version` SHA on every gate span |
| Pre-built Grafana dashboard JSON | **[Built]** | `observability/grafana/provisioning/dashboards/kitelogik.json` — 4 panels; auto-provisioned by `make demo-enterprise` |

---

### Dashboard

| Feature | Status | Notes |
|---|---|---|
| Real-time live feed | **[Built]** | WebSocket; gate decisions as they happen |
| HITL queue panel | **[Built]** | Pending actions with approve/deny controls |
| Memory viewer | **[Built]** | Keys, values, trust tiers per session |
| Fleet view | **[Built]** | All active sessions |
| Dashboard health endpoint | **[Built]** | `GET /api/health` — probes OPA, HITL queue, and memory; returns 503 on degraded |
| Session filter on live feed | **[Built]** | Dropdown populates from active sessions; filters WebSocket events client-side |
| Audit log tab | **[Built]** | Table: timestamp/session/tool/outcome/risk tier/latency; outcome + session filters |
| Audit log CSV export | **[Built]** | `GET /api/audit/export` — streams CSV; respects active filters; Download CSV button in UI |
| Comprehensive health endpoint | **[Built]** | See above — OPA + queue + memory probed; `{"status":"ok"|"degraded"}` |

---

### Agent Session and Orchestration

| Feature | Status | Notes |
|---|---|---|
| `AgentSession` — direct mode | **[Built]** | In-process `PolicyGate`; no external gateway needed |
| `AgentSession` — gateway mode | **[Built]** | HTTP calls to MCP Gateway; polls for HITL decisions |
| Session token lifecycle management | **[Built]** | Issue at start, revoke in `finally` |
| Sandbox lifecycle management | **[Built]** | Spawn at start, teardown in `finally` |
| Multi-agent orchestration | **[Built]** | `Orchestrator` class for coordinating multiple sessions |
| 13 pre-built demo scenarios | **[Built]** | Full range: ALLOW, BLOCK, HITL across policy domains |
| Demo CLI flags (`--speed`, `--no-dashboard`, `--otlp`) | **[Built]** | `--speed fast|demo`, `--no-dashboard` for terminal-only mode, `--otlp <url>` |
| Demo summary table | **[Built]** | Printed at end of run: per-scenario outcome + latency, colour-coded totals |

---

### MCP Integration

| Feature | Status | Notes |
|---|---|---|
| MCP client | **[Built]** | Tool discovery, call dispatch, response handling |
| MCP mock server | **[Built]** | Simulates tool integrations for demo |
| MCP response sanitization | **[Built]** | Sanitizes responses before they enter agent context |
| MCP supply chain verification | **[Built]** | BOM integrity checks on MCP server packages |
| MCP server registry | **[Built]** | Central registry of available MCP servers |

---

### Test Coverage

| Feature | Status | Notes |
|---|---|---|
| 352 Python tests across 23 test files | **[Built]** | Unit, adversarial, integration |
| 36 OPA native policy tests | **[Built]** | `financial_test.rego`; run with `opa test kitelogik/policies/ -v` |
| 41 policy bypass adversarial tests | **[Built]** | Type coercion, path traversal, session boundary, delegation escalation |
| Injection corpus tests | **[Built]** | 12 real-world payloads; 7 benign counter-examples |
| Integration tests (full stack) | **[Built]** | Real OPA + Docker; requires `make demo` |
| Benchmark script | **[Built]** | `benchmark.py` — p50/p95/p99 across ALLOW/DENY/HITL; `--iterations`, `--scenarios`, `--concurrency` flags |

---

### Developer and Repository Infrastructure

| Feature | Status | Notes |
|---|---|---|
| `pyproject.toml` build config | **[Built]** | setuptools, ruff, pytest configured |
| `Makefile` targets | **[Built]** | `demo`, `demo-enterprise`, `start`, `test`, `landing` |
| `kitelogik/__init__.py` SDK entrypoint | **[Built]** | Exports all public types and classes |
| `livereload` dev server for landing page | **[Built]** | `make landing` → browser reloads on save |
| Docker Compose stack | **[Built]** | `opa`, `dashboard`, `mcp-mock` services |
| `.gitignore` | **[Built]** | Python, Docker, macOS, runtime artifacts |
| `LICENSE` (Apache-2.0) | **[Built]** | Apache License 2.0 1.1; converts to Apache 2.0 on 2030-03-26 |
| `.dockerignore` | **[Built]** | Excludes `.venv`, test fixtures, local DBs from image |
| `asyncpg` as optional dependency | **[Built]** | Available as `[postgres]` extra in `pyproject.toml` |
| `.env.example` | **[Built]** | Template for all env vars; enterprise vars commented out |
| `README.md` | **[Built]** | GitHub landing page: quickstart, architecture diagram, feature table |
| GitHub Actions CI | **[Built]** | Lint, test matrix (3.11/3.12), OPA native tests, coverage, pip-audit |
| `CONTRIBUTING.md` | **[Built]** | Dev setup, code style, Rego → OPA test → Python flow |
| `SECURITY.md` | **[Built]** | Responsible disclosure policy, response timeline |
| `CHANGELOG.md` | **[Built]** | Keep a Changelog format; `Security` category |
| GitHub issue and PR templates | **[Built]** | Bug report, feature request, PR checklist |
| `quickstart.py` | **[Built]** | Guided 4-step walkthrough: ALLOW → HITL → BLOCK |
| Multi-stage Dockerfile | **[Built]** | Builder + runtime stages; non-root user (uid 1001) |
| `docs/architecture.md` | **[Built]** | Full system diagram, data flow, threat model |

---
---

## Enterprise Edition

All open source features are included. The enterprise edition adds:

### PostgreSQL Backends

| Feature | Status | Notes |
|---|---|---|
| `PostgresHITLQueue` | **[Built]** | Multi-node concurrent writes; same interface as SQLite queue |
| `PostgresMemoryStore` | **[Built]** | Same interface as SQLite store |
| `PostgresCredentialBroker` | **[Built]** | In-memory cache warmed from DB at startup |
| `PostgresAuditStore` | **[Built]** | Append-only via Postgres rules (no UPDATE/DELETE at DB level) |
| Bulk session revocation (`revoke_session()`) | **[Built]** | Single `UPDATE` revokes all tokens for a session |
| Policy version in every audit record | **[Built]** | SHA-256 of policy files at evaluation time |
| Session export with integrity hash | **[Built]** | SHA-256 of full audit record set for tamper detection |
| Database migrations (Alembic) | **[Planned]** | `upgrade()` and `downgrade()` for all schemas; `make migrate` |
| Connection pool configuration | **[Planned]** | `POSTGRES_POOL_MIN/MAX/TIMEOUT` env vars |
| Connection pool observability | **[Planned]** | Pool size/idle/waiting surfaced in health endpoint and Prometheus |

---

### MCP Gateway

| Feature | Status | Notes |
|---|---|---|
| `POST /v1/tools/call` | **[Built]** | Full gate evaluation; 200/202/403/401/502 responses |
| `GET /v1/tools/list` | **[Built]** | Scope-filtered tool discovery per session token |
| `GET /v1/hitl/{id}/status` | **[Built]** | Poll HITL action status: PENDING/APPROVED/DENIED/TIMED_OUT |
| `POST /v1/hitl/{id}/approve` | **[Built]** | Approve with `decided_by`; 409 if already decided |
| `POST /v1/hitl/{id}/deny` | **[Built]** | Deny with reason; 409 if already decided |
| `POST /v1/agents/{id}/kill` | **[Built]** | Kill switch: revokes all sessions, marks agent as killed |
| `GET /v1/fleet/status` | **[Built]** | Aggregate fleet view: agent count, active/killed breakdown |
| `GET /v1/fleet/hitl` | **[Built]** | All pending HITL actions across the entire fleet |
| `GET /v1/audit/export` | **[Built]** | Session compliance report with SHA-256 integrity hash |
| `GET /v1/audit/query` | **[Built]** | Filtered audit query: session/tool/outcome |
| `GET /v1/health` | **[Built]** | Active OPA probe; returns `"opa": "unreachable"` + 503 if down |
| Bearer token authentication | **[Built]** | All endpoints require `Authorization: Bearer <token_id>` |
| Automatic audit on every tool call | **[Built]** | Gateway writes to `PostgresAuditStore` on every evaluation |
| Response sanitization | **[Built]** | Tool output sanitized before returning to caller |
| Gateway added to Docker Compose | **[Planned]** | Enterprise profile includes gateway service with health check |
| Gateway rate limiting | **[Planned]** | Per-token sliding window; `429` with `Retry-After` |
| Graceful shutdown | **[Planned]** | SIGTERM drains in-flight HITL waits before exit |
| Gateway RBAC (`viewer/reviewer/admin`) | **[Planned]** | Role enforced per endpoint via FastAPI dependency |
| `GET /v1/tokens` (admin) | **[Planned]** | List all active tokens and their roles for audit |
| `POST /v1/audit/replay` | **[Planned]** | Async policy replay job over historical records |
| `GET /v1/audit/replay/{job_id}` | **[Planned]** | Poll replay job status and results |

---

### Multi-LLM Adapter Layer

| Feature | Status | Notes |
|---|---|---|
| Anthropic adapter | **[Built]** | Translates `tool_use` content blocks; `id` → `request_id` |
| OpenAI adapter | **[Built]** | Handles `tool_calls` array and legacy `function_call` |
| MCP JSON-RPC adapter | **[Built]** | Handles `tools/call` JSON-RPC 2.0 format |
| LangChain integration guide | **[Planned]** | `BaseTool` subclass calling the Gateway |
| LangGraph integration guide | **[Planned]** | HITL pause/resume pattern in LangGraph nodes |
| AutoGen integration guide | **[Planned]** | `code_execution_config` → Gateway; kill switch integration |

---

### Agent Registry and Fleet Management

| Feature | Status | Notes |
|---|---|---|
| `AgentRegistry` — tracks agent identities | **[Built]** | Agent name, role, active session list |
| `AgentRegistry` — kill switch | **[Built]** | Marks agent as `killed`; blocks new sessions |
| `AgentRegistry` — fleet status aggregation | **[Built]** | Active/killed counts; used by `GET /v1/fleet/status` |
| Persistent Agent Registry (SQLite) | **[Planned]** | `PersistentAgentRegistry`: kills survive restart |
| Persistent Agent Registry (Postgres) | **[Planned]** | `PostgresAgentRegistry`: multi-node kill durability |

---

### Policy Replay

| Feature | Status | Notes |
|---|---|---|
| `PolicyReplayer` class | **[Built]** | Re-evaluates historical audit records vs current policy |
| Single-record replay | **[Built]** | `replay_record(record)` → `ReplayResult` with `outcome_changed` |
| Session replay | **[Built]** | `replay_session(audit_store, session_id)` → all records chronologically |
| Bulk replay from arbitrary record list | **[Built]** | `replay_records(records)` for cross-session analysis |
| `outcome_changed` flag on every result | **[Built]** | Boolean; shows where current policy differs from original |
| Policy replay REST API | **[Planned]** | `POST /v1/audit/replay` → async job; poll for results |
| Policy replay dashboard UI | **[Planned]** | Session selector → table of changes → "N of M records changed" |
| Policy replay CSV export | **[Planned]** | Download changed decisions for external review |

---

### SIEM Integration

| Feature | Status | Notes |
|---|---|---|
| `SIEMWebhook` connector | **[Built]** | HTTP POST webhook; configurable URL and auth header |
| Structured event envelope | **[Built]** | `time`, `source`, `event_type`, `severity`, `data` |
| Policy decision events | **[Built]** | Every gate evaluation; severity: LOW/MEDIUM/HIGH by outcome |
| Audit record events | **[Built]** | Structured; maps to `audit_log` schema |
| HITL escalation events | **[Built]** | Severity: MEDIUM |
| Kill switch events | **[Built]** | Severity: HIGH; always |
| Fire-and-forget emit | **[Built]** | `siem.emit()` — returns immediately; errors logged not raised |
| Awaitable emit | **[Built]** | `siem.emit_async()` — returns True on 2xx, False on error |
| SIEM never blocks gate evaluation | **[Built]** | SIEM unavailability does not affect policy enforcement |
| Splunk HEC support | **[Built]** | `api_key="Splunk tok_abc"` → `Authorization` header |
| Datadog / Elastic / custom webhook | **[Built]** | Any endpoint accepting JSON POST |

---

### Observability — Enterprise

| Feature | Status | Notes |
|---|---|---|
| Grafana + Tempo in Docker Compose | **[Built]** | Enterprise profile: `make demo-enterprise` |
| Tempo OTLP/HTTP ingestion | **[Built]** | Port 4318; traces from demo script shipped automatically |
| Grafana datasource auto-provisioned | **[Built]** | Tempo datasource configured at startup |
| Pre-built Grafana dashboard | **[Planned]** | Decisions panel, latency panel, queue depth, trace list |
| Grafana alerting rules (7 alerts) | **[Planned]** | HITL backlog, OPA unreachable, kill switch, denial spike, latency |
| Prometheus metrics exporter | **[Planned]** | 12 metrics: decisions, latency, OPA errors, pool depth, kill events |
| HITL SLA monitoring dashboard | **[Planned]** | Queue depth gauge, oldest pending, resolution time histogram |
| Reviewer activity panel | **[Planned]** | Decisions per reviewer per hour; from `decided_by` field |
| Actions approaching timeout panel | **[Planned]** | List of PENDING actions with <60s remaining |

---

### Access Control and Authentication

| Feature | Status | Notes |
|---|---|---|
| Bearer token auth on all Gateway endpoints | **[Built]** | Validated against `CredentialBroker` on every request |
| Dashboard API key authentication | **[Planned]** | `X-API-Key` header; `DASHBOARD_API_KEY` env var |
| Dashboard OIDC/SSO | **[Planned]** | Okta, Azure AD, Google Workspace, Keycloak |
| OIDC group → dashboard role mapping | **[Planned]** | IdP groups map to viewer/reviewer roles |
| Grafana admin credentials | **[Planned]** | Replace anonymous auth with `GRAFANA_ADMIN_USER/PASSWORD` |
| HashiCorp Vault secrets backend | **[Planned]** | Resolve env vars from Vault KV v2 at startup |
| AWS SSM Parameter Store backend | **[Planned]** | Resolve env vars from SSM at startup |
| Secret rotation without restart | **[Planned]** | Pool drained and recreated on lease renewal |

---

### Compliance and Data Governance

| Feature | Status | Notes |
|---|---|---|
| Append-only audit log (Postgres rules) | **[Built]** | `audit_log_no_update` and `audit_log_no_delete` rules at DB level |
| SHA-256 integrity hash on session export | **[Built]** | Hash of sorted record set; recipients can verify completeness |
| Policy version on every audit record | **[Built]** | Links each decision to the exact Rego ruleset in effect |
| Audit retention policy | **[Planned]** | `AUDIT_LOG_RETENTION_DAYS` (default: 2555 — 7 years) |
| Cold storage archival (S3/GCS/local) | **[Planned]** | Nightly archival job; JSON with SHA-256; records deleted after archival |
| GDPR Art. 17 data subject deletion | **[Planned]** | Redacts PII in-place; preserves audit record; logs deletion event |
| Compliance report export (CSV) | **[Planned]** | From audit log tab; filtered by session/outcome/date range |
| Audit log date-range query | **[Planned]** | `GET /v1/audit/query?from=&to=&outcome=` |

---

### Multi-Tenancy

| Feature | Status | Notes |
|---|---|---|
| Single-tenant deployment | **[Built]** | Current model; all data in one namespace |
| `tenant_id` column on all Postgres tables | **[Planned]** | HITL queue, memory, credentials, audit log |
| Tenant-scoped queries (implicit filter) | **[Planned]** | All backend methods filter by `tenant_id` from token |
| Cross-tenant access prevention | **[Planned]** | `tenant_id` in token; never a caller-supplied param |
| Tenant isolation test suite | **[Planned]** | Adversarial cross-tenant access attempts in CI |
| `POST /v1/admin/tenants` | **[Planned]** | Provision new tenant: policy namespace, DB setup, initial admin token |
| `DELETE /v1/admin/tenants/{id}` | **[Planned]** | Two-phase: deactivate → data deleted after retention period |

---

### Policy Management Platform

| Feature | Status | Notes |
|---|---|---|
| OPA `--watch` for development | **[Built]** | Policies reloaded on file change |
| OPA bundle distribution | **[Planned]** | Config guide for production clustered OPA |
| Policy deployment pipeline | **[Planned]** | PR → CI tests → impact analysis → staging → manual gate → production |
| Impact analysis before deploy | **[Planned]** | `PolicyReplayer` runs against 7 days of staging records in CI |
| Canary policy rollout | **[Planned]** | Gradual percentage-based rollout with automatic rollback |
| `policy_versions` table | **[Planned]** | Hash → commit message → deployed at → deployed by |
| Policy version history dashboard | **[Planned]** | Last 20 versions; diff viewer; rollback button |
| Policy diff viewer | **[Planned]** | Two-version comparison using `opa fmt` output |

---

### Kubernetes Production Delivery

| Feature | Status | Notes |
|---|---|---|
| Docker Compose (enterprise profile) | **[Built]** | OPA, dashboard, mcp-mock, gateway, tempo, grafana |
| Helm chart | **[Planned]** | All enterprise services; `values.yaml` with documented defaults |
| `PodDisruptionBudget` | **[Planned]** | `minAvailable: 1` for gateway and OPA |
| `HorizontalPodAutoscaler` | **[Planned]** | Scale on CPU + HITL queue depth (Prometheus adapter) |
| `NetworkPolicy` | **[Planned]** | Explicit egress rules: gateway → OPA, gateway → DB, gateway → SIEM |
| `readinessProbe` / `livenessProbe` | **[Planned]** | Readiness on `/v1/health`; liveness on `/v1/ping` |
| `preStop` lifecycle hook | **[Planned]** | `sleep 5` before SIGTERM for connection drain |
| Non-root container user | **[Planned]** | `USER 1000:1000` in Dockerfile and Helm securityContext |
| Resource requests and limits defined | **[Planned]** | CPU/memory per service in `values.yaml` |
| Terraform module — AWS | **[Planned]** | EKS, RDS, ECR, IAM IRSA roles, ALB, Secrets Manager |
| Terraform module — GCP | **[Planned]** | GKE, Cloud SQL, Artifact Registry, Workload Identity |
| Terraform module — Azure | **[Planned]** | AKS, Azure PostgreSQL, ACR, managed identities |

---

### Customer Infrastructure

| Feature | Status | Notes |
|---|---|---|
| Enterprise onboarding documentation | **[Planned]** | Sequential checklist: deploy → auth → policies → agents → SIEM → alerts |
| "Verify it worked" check per step | **[Planned]** | Every onboarding step has a health check command |
| LangChain integration guide | **[Planned]** | `BaseTool` subclass → Gateway; HITL polling pattern |
| LangGraph integration guide | **[Planned]** | Pause/resume graph node on HITL 202 response |
| AutoGen integration guide | **[Planned]** | `code_execution_config` → Gateway; kill switch termination |
| Enterprise `.env.enterprise.example` | **[Planned]** | All enterprise env vars with comments |

---

## Feature Count Summary

| Edition | Built | Planned | Total |
|---|---|---|---|
| Open Source | 107 | 1 | 108 |
| Enterprise (additions) | 37 | 59 | 96 |
| **Combined** | **144** | **60** | **204** |

OSS built coverage: **99%** of the OSS feature set is implemented (Firecracker MicroVM runtime is the one deferred item).
Enterprise built coverage: **39%** of enterprise-specific features are implemented today.
