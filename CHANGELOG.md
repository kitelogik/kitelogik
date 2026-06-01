# Changelog

All notable changes to Kite Logik are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `ADAPTER_MATURITY` registry in `kitelogik.adapters` — the source of
  truth for each of the 11 framework adapters' maturity tier (`stable` /
  `beta` / `experimental`). A guard test fails if an adapter module ships
  without a tier. The 7 core adapters (OpenAI, OpenAI Agents, LangChain,
  LangGraph, CrewAI, Google ADK, PydanticAI) are `stable`; the newer
  LlamaIndex / Semantic Kernel / Haystack / Dify are `beta`.

### Changed
- `OPAConnectionError` messages now include a recovery hint (the
  `docker compose up -d opa` command and the OPAClient base_url override)
  at each httpx failure mode — connect refused, request timeout, and
  non-2xx HTTP responses. The HTTP-status branch additionally points at
  the policy-bundle and `kitelogik/main` package as the likely cause.
- `GovernanceError.__str__` now appends `(rule: <rule_matched>)` when the
  underlying `PolicyDecision` names a specific Rego rule, so a developer
  sees which rule fired without unpacking `exc.decision`. The message is
  unchanged when `rule_matched` is `None`.
- `kitelogik init` now scaffolds the full core governance bundle (main,
  userpolicy, financial, security, delegation, and the agent_* modules)
  into the project's `policies/`, so a new project evaluates against the
  real pipeline — security hard-denies, delegation limits, HITL routing,
  event dispatch — not just the user's compiled rules. Previously the
  compiled policy stood in for `main` and the project had none of the
  built-in protections.

### Removed
- The YAML policy `package:` field. Compiled policies now always target
  the `kitelogik.userpolicy` package (see Fixed). Existing YAML files
  that still set `package:` keep compiling — the field is ignored, not
  an error.
- `edition`, `Edition`, and `load_plugin` are no longer re-exported from
  the top-level `kitelogik` package. They were an enterprise-detection /
  plugin-discovery surface (`edition()` returns `"ENTERPRISE"` when a
  plugin is registered) that did not belong on the OSS public API. The
  `kitelogik.edition` module is unchanged and still importable directly
  for any extension package that needs it.

### Fixed
- Compiled YAML policies are now actually enforced. A compiled policy
  previously landed in whatever package the YAML named — either one the
  gate never queries (`kitelogik.custom_rules`, so the rules governed
  nothing) or one that collides with a core module (`kitelogik.main` /
  `kitelogik.financial`, an OPA bundle compile error). Compiled output
  now targets `kitelogik.userpolicy`, which `main.rego` aggregates
  alongside the other sub-policies, with merge-safe Rego (no `default`
  declarations; `deny`/`hitl` always set-valued).
- A YAML `then: deny` now hard-blocks instead of being routed to human
  review. `main.rego`'s soft-deny → HITL fallback no longer catches an
  explicit user-policy deny, and a high-value transaction that is denied
  no longer also sets `requires_hitl` — a denied action stays a pure
  deny rather than surfacing as both blocked and awaiting approval.

### Documentation
- README lists the framework adapters as a table with per-adapter
  maturity tiers, sourced from `ADAPTER_MATURITY`.
- `SECURITY.md` adds a Deployment Hardening section flagging that the
  bundled `docker-compose.yml` binds OPA to `0.0.0.0:8181` for local
  convenience and the OPA REST API ships without authentication, with
  guidance to bind `127.0.0.1` / front with a reverse proxy / review
  OPA's `server` configuration in production.
- `README.md` replaces the "OSS vs Enterprise" comparison table with a
  single "Features" section that enumerates what ships in this Apache-2.0
  package. The Enterprise Governance Gateway callout under Deployment
  Modes and the `licensing@kitelogik.com` contact line are removed.
- `NOTICE` drops the `COMMERCIAL LICENSING` block.
- `pyproject.toml` drops the Enterprise extension-points comment block;
  the actual plugin contract still lives in `kitelogik.edition`.
- `.github/ISSUE_TEMPLATE/config.yml` drops the Enterprise enquiries
  contact link.
- `kitelogik/observability/tracer.py` drops a stale `# Enterprise:`
  comment from a code path that ships in OSS (OTLP forwarding).


## [0.3.0] — 2026-04-30

### Added
- Governed handoffs and agent-as-tool for OpenAI Agents SDK (#18) (*adapters*) (4c1c661)
- OTel parent span on tool calls + duplicate-name guard (#19) (*adapters*) (fe9b61b)


### Changed
- Centralise governance pipeline into _run_governed_call (#17) (*adapters*) (9420164)


### Documentation
- Align test count + fix relative links for PyPI (#20) (*readme*) (77a58d9)


### Fixed
- Preserve args_schema in govern_toolkit; drop deprecated event-loop API (#14) (*adapters*) (88972e5)
- Make 5 broken adapters functional + correct OpenAI Agents signature (#15) (*adapters*) (6e2eba9)
- Redesign Dify adapter with plugin-base class (#16) (*adapters*) (8c2bff2)


## [0.2.1] — 2026-04-27

### Documentation
- Bump test count 484 → 605 in README (48c1970)


### Fixed
- SLSA generator needs hashes from build job, not as-file flag (*ci*) (dcec8b9)


## [0.2.0] — 2026-04-27

### Changed (breaking)
- Move demo tools out of AgentSession default, extract timeout/token constants, close Phase 1a policy audit (null delegation_depth bypass, default-declaration hygiene, dead rate_limit         constant, opa fmt --fail), and refresh CLAUDE.md for OSS/Enterprise/Landing split **BREAKING** (14d13b4)
- Multi-provider AgentSession + numpy-docstringed API (*agents*) **BREAKING** (c3e1bba)
- Add `then: hitl` to YAML compiler + propagate to main (*policies*) **BREAKING** (98cdce1)


### Documentation
- Remove dead links to private architecture doc (411daad)
- Add runnable examples directory (*examples*) (1281aec)


### Fixed
- CI failures (5d3b522)
- Resolve mypy errors, scorecard on private repo, coverage threshold (b0c27c4)
- Ruff lint errors (cbc4634)
- Ruff format (f8814d1)
- Import sorting (I001) (2d1dcbe)
- Resolve all mypy type errors (5791566)
- Quiet hard-deny logging + broaden injection patterns (*tether*) (48b10fc)
- Ruff lint + format drift on new coverage tests (*tests*) (33973cb)
- Use public ainvoke API for langchain-core ≥0.3 (*adapters/langchain*) (2a43bcc)


---

## [Unreleased]

_No unreleased changes._

---

## [0.1.0] — 2026-04-19

Initial OSS release on PyPI. This release is the governance core: Tether (policy
engine), Anchor (HITL + credential broker + observability), memory store with
provenance, MCP client with supply-chain verification, immutable audit log, 11
framework adapters, CLI, and a starter policy library. Gateway, Dashboard,
Orchestrator, and Sandbox runtimes live in the `kitelogik-enterprise` package
and are not part of OSS.

### Added — Tether (Policy Engine)
- OPA/Rego policy engine integration via HTTP; fail-closed on OPA unreachability (returns `deny=True, risk_tier=SECURITY_CRITICAL`).
- Deny-by-default enforcement — every policy file opens with `default allow := false`.
- Five risk tiers: `INFORMATIONAL` → `OPERATIONAL` → `TRANSACTIONAL_HIGH` → `DESTRUCTIVE` → `SECURITY_CRITICAL`.
- `PolicyGate` — scope-based + role-based evaluation on every tool call, schema validation before OPA, per-stage OpenTelemetry spans, `rule_matched` on every decision.
- `HierarchicalEvaluator` — 2-tier policy hierarchy (global + project) with deny-overrides semantics and resolution traces.
- `RegorusClient` — in-process Rego evaluator via Microsoft's regorus (Rust) engine. Experimental. Regorus Python bindings are not yet on PyPI; see [microsoft/regorus](https://github.com/microsoft/regorus/tree/main/bindings/python) for build-from-source instructions.
- YAML policy compiler: write policies in YAML, compile to Rego via `kitelogik compile`; JSON Schema validation via `kitelogik validate`.
- Starter Rego policies: `financial`, `security`, `delegation`, `agent_lifecycle`, `agent_plan`, `agent_budget`, `data_classification`, `main`.
- Policy library (`policies/library/`): `tool_allowlist`, `pii_protection`, `read_only`, `cost_cap`, `rate_limiting` — all with OPA tests.
- Type guards on all numeric fields — prevents null/bool/string/negative amount bypass.

### Added — Anchor (Oversight)
- Async HITL queue backed by SQLite; agent suspends on `asyncio.Event` (no polling).
- Full action lifecycle: `PENDING` → `APPROVED` / `DENIED` / `TIMED_OUT`, with per-session timeout and decision metadata (`decided_by`, `decided_at`, `denial_reason`).
- Background expiry task with consecutive-failure escalation to CRITICAL logging.
- `CredentialBroker` — in-memory and SQLite-backed brokers, short-lived scoped tokens, parent/child delegation with scope-subset enforcement, revocation at session end.

### Added — Audit (Immutable Logging)
- Append-only SQLite audit store; immutability enforced by database triggers (`UPDATE`/`DELETE` aborted at the SQL level).
- Every tool call recorded with the full `PolicyDecision`, policy version SHA, and session context.
- `PolicyReplayer`: re-evaluate historical records against current policy with `outcome_changed` flag per record.
- Session export includes a SHA-256 integrity hash for tamper detection.

### Added — Memory (Provenance-Tracked)
- SQLite-backed async memory store.
- Five trust tiers (most → least trusted): `TRUSTED` → `INTERNAL` → `DELEGATED` → `EXTERNAL` → `UNTRUSTED`.
- Provenance metadata on every write: `source`, `session_id`, `trust_tier`, `created_at`.
- Auto-sanitization on writes from untrusted tiers with `sanitized` flag persisted per entry.
- Session-scoped reads — non-empty `session_id` required.

### Added — Injection Defence
- Indirect prompt injection detection: instruction-override phrases, system-prompt probes, role overrides.
- Tool output sanitized before entering agent context (`sanitize_tool_output`).
- Tool schema sanitizer (`sanitize_tool_schema`) for externally-sourced MCP `tools/list` responses.
- Unicode tag-char smuggling defence: NFKC normalization + demirroring of the U+E0020–U+E007E ASCII-mirror block before scanning.
- Role-confusion patterns (`assume the role`, `act as`, `in the role of`, `if you were`).
- Memory writes sanitized at untrusted trust tiers.
- Command-injection pattern detection in tool arguments.

### Added — Observability
- OpenTelemetry instrumentation aligned with GenAI Semantic Conventions v1.37+.
- File trace exporter by default; OTLP/HTTP export via `--otlp <url>`.
- Session ID correlated across all spans; policy version SHA stamped on every gate span.

### Added — MCP Integration
- Async JSON-RPC 2.0 MCP client with tool discovery and dispatch.
- Supply-chain integrity verification: SHA-256 manifest checks on MCP server packages.
- Response sanitization before tool output enters agent context.

### Added — Agent Session
- `AgentSession` — in-process direct mode over `PolicyGate`.
- Session token issued at start, revoked unconditionally in the `finally` block, including any delegated child tokens attached to the session.
- Anthropic Python SDK as the default LLM client (`claude-sonnet-4-6`).

### Added — Framework Adapters (11)
- `@governed` decorator and `GovernedToolbox` for inline enforcement.
- `OpenAIAdapter`, `LangChainAdapter` (`as_governed_tool` / `govern_toolkit`), `LangGraphAdapter`, `CrewAIAdapter`, `OpenAIAgentsAdapter`, `GoogleADKAdapter`, `PydanticAIAdapter`, `LlamaIndexAdapter`, `SemanticKernelAdapter`, `HaystackAdapter`, `DifyAdapter`.
- `BaseGovernedAdapter` centralizes the governance pipeline.

### Added — CLI
- `kitelogik init <project>` — scaffold a governed-agent project.
- `kitelogik compile` — YAML → Rego compilation.
- `kitelogik validate` — JSON Schema validation of YAML policies.
- `kitelogik test` — OPA Rego test runner with a bundled Docker fallback.
- `kitelogik check` — evaluate a governance event via OPA from stdin JSON.
- `kitelogik compliance` — governance audit with OWASP Agentic Security Initiative mapping.
- Automatic OPA-in-Docker fallback for `validate` / `test` / `check` when no `opa` binary is on PATH — contributors without a local OPA install still get a working CLI.

### Added — Public API
- Root `kitelogik` package exports: `AgentSession`, `SessionResult`, `PolicyGate`, `HierarchicalEvaluator`, `SessionContext`, `PolicyDecision`, `ResolutionStep`, `RiskTier`, `SanitizedResponse`, `ToolCallInput`, `OPAClient`, `OPAConnectionError`, `RegorusClient`, `HITLQueue`, `CredentialBroker`, `AuditStore`, `MemoryStore`, `TrustTier`, `compile_yaml`, `compile_yaml_string`, `Edition`, `edition`, `load_plugin`, `governed`, `GovernedToolbox`, `GovernanceError`, `__version__`.
- `kitelogik.tether` additionally exposes: `GovernanceEvent`, `PolicyInput`, `PolicyEvaluator`, `result_to_decision`, `sanitize_tool_output`, `sanitize_tool_schema`.
- `py.typed` marker shipped — PEP 561 type-checker friendly.

### Fixed
- Delegated child tokens now revoked when the parent session ends or raises — previously only tokens the session issued itself were cleaned up in the `finally` block.
- `CredentialBroker.delegate()` rejects empty-scope delegation (previously silently issued a no-op token, bypassing the narrowing intent).
- `agent_lifecycle.rego` — null `delegation_depth` no longer bypasses depth caps.
- `rate_limiting.rego` — removed dead `_max_calls` constant.
- `default` declarations in all Rego files now pass `opa fmt --fail`.
- `kitelogik check` — use OPA's `--stdin-input` flag (was incorrectly `-i -`, which OPA interprets as a filename).

### Security
- Fail-closed policy gate: OPA unreachability returns a hard block, never an accidental allow.
- Database-level immutability on the audit log (triggers reject `UPDATE` and `DELETE`); regression tests added for trigger enforcement, reconnect-survival, and integrity-hash tamper detection.
- All shell commands constructed from agent input rejected at policy layer — no f-string shell construction.
- MCP supply-chain verification before any server is registered.
- Session tokens scoped to minimum required permissions; revoked on session end (including delegated children).

### Tests
- 469 unit tests + 36 OPA native policy tests.
- Added adversarial coverage: tag-char smuggling, role-confusion payloads, schema-sanitization, audit trigger enforcement, credential lifecycle edge cases.
- Extended CrewAI and OpenAI Agents SDK adapter tests to drive the full governance flow (allow / deny / async bridging) via `sys.modules` stubs, without taking a hard dependency on either framework.

[Unreleased]: https://github.com/kitelogik/kitelogik/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kitelogik/kitelogik/releases/tag/v0.1.0
