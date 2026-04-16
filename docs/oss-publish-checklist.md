# OSS Publish Checklist — Kite Logik (Apache-2.0)

_Work through this top-to-bottom before pushing to a public GitHub repository.
Each item is either already done ✅, a gap to close ⬜, or a decision to make 🔲._

_Last audited: 2026-04-11_

---

## 0. Launch readiness — feature vs claim alignment

**This is the most important section.** The README and docs must not claim features that don't exist. Shipping claims ahead of code destroys credibility with the exact audience (security-conscious developers) that Kite Logik is targeting.

### Features that exist and work

| Feature | Status | Evidence |
|---|---|---|
| Tool call governance via OPA/Rego | ✅ | tether/gate.py, 8 core Rego policies + tests |
| GovernanceEvent model with event_type | ✅ | tether/models.py — Literal-typed event_type field |
| PolicyGate.evaluate() general method | ✅ | tether/gate.py — evaluates any GovernanceEvent |
| agent.spawn governance | ✅ | agents/session.py, policies/agent_lifecycle.rego |
| agent.delegate governance | ✅ | agents/orchestrator.py, policies/agent_lifecycle.rego |
| Plan-before-execute gate | ✅ | tether/gate.py evaluate_plan(), policies/agent_plan.rego |
| Resource budget enforcement | ✅ | policies/agent_budget.rego with OPA tests |
| Data classification labels | ✅ | policies/data_classification.rego with OPA tests |
| Docker sandbox (network isolation, resource limits, read-only FS) | ✅ | sandbox/runtime.py, full test suite |
| Session-scoped credentials with delegation + scope narrowing | ✅ | anchor/credentials.py, PersistentCredentialBroker |
| HITL queue (async, expiry, blocking wait) | ✅ | anchor/queue.py |
| Immutable audit trail (SQL trigger enforcement) | ✅ | audit/store.py |
| `@governed` decorator + `GovernedToolbox` | ✅ | kitelogik/governed.py |
| 11 framework adapters | ✅ | kitelogik/adapters/ (OpenAI, LangChain, CrewAI, OpenAI Agents SDK, LangGraph, Google ADK, PydanticAI, LlamaIndex, Semantic Kernel, Haystack, Dify) |
| Governance Gateway (FastAPI) | ✅ | gateway/server.py |
| Agent memory with trust tiers + provenance | ✅ | memory/store.py |
| MCP client with supply chain verification (HTTP + stdio transport) | ✅ | mcp/client.py, mcp/stdio_transport.py |
| OpenTelemetry tracing | ✅ | observability/tracer.py |
| Prometheus metrics | ✅ | observability/metrics.py |
| SIEM webhook dispatcher | ✅ | observability/siem.py (full implementation) |
| Real-time WebSocket dashboard | ✅ | dashboard/server.py |
| Agent orchestrator with delegation chains | ✅ | agents/orchestrator.py |
| CLI tool (`kitelogik` command) | ✅ | kitelogik/cli.py — validate, test, check, version, compile, compliance |
| YAML→Rego policy compiler | ✅ | policies/compiler.py |
| RegorusClient (in-process Rego, experimental) | ✅ | tether/regorus_client.py |
| HierarchicalEvaluator (2-tier policy hierarchy) | ✅ | tether/hierarchy.py |
| Starter policy library | ✅ | kitelogik/policies/library/ — 5 policies with OPA tests |
| 681 tests passing, 75% coverage enforced | ✅ | pyproject.toml, CI |

### Features claimed in README but NOT built

All previously claimed features have been implemented. No feature/claim gaps remain.

---

## 1. Repository hygiene — secrets & runtime artefacts

| File | Risk | .gitignore covers it? |
|------|------|-----------------------|
| `.env` | `ANTHROPIC_API_KEY` and other secrets | ✅ |
| `events.db`, `hitl.db`, `memory.db` | Session state, HITL records | ✅ (`*.db`) |
| `traces.jsonl` | Raw OTel traces — may contain tool args | ✅ (`*.jsonl`) |
| `kitelogik.egg-info/` | Build artefact | ✅ |
| `__pycache__/` | Bytecode | ✅ |
| Internal planning docs | competitive-analysis.md, oss-improvement-plan.md | ✅ (gitignored) |

**Action:** before first push, run:
```bash
# Verify nothing sensitive is about to be tracked
git status
# Or use a pre-commit secret scanner:
pip install detect-secrets
detect-secrets scan > .secrets.baseline
```

---

## 2. Git initialisation & first commit

```bash
git init
git add .
git commit -m "Initial OSS release — v0.1.0"
```

- ✅ Default branch name: `main`
- ✅ `.gitattributes` exists for consistent line endings

---

## 3. Apache-2.0 licence — verify terms are correct

| Field | Current value | Status |
|-------|---------------|--------|
| Licensor | `Kite Logik Contributors` | 🔲 Should this be a legal entity? |
| `LICENSE` file | Pure Apache-2.0 | ✅ |

---

## 4. `pyproject.toml` — metadata for PyPI

| Field | Status |
|-------|--------|
| `name`, `version`, `license` | ✅ |
| `description` | ✅ |
| `authors` | ✅ |
| `readme` | ✅ |
| `keywords` | ✅ |
| `classifiers` | ✅ |
| `[project.urls]` (Homepage, Repository, Docs, Bug Tracker, Changelog) | ✅ |
| `[tool.pytest.ini_options]` | ✅ |
| `[tool.coverage.run]` + `[tool.coverage.report]` | ✅ |
| `[tool.ruff]` | ✅ |
| `[project.scripts]` for CLI | ✅ |

---

## 5. `CHANGELOG.md`

- ✅ Exists with v0.1.0 content and [Unreleased] section populated

---

## 6. CI/CD workflows

| Workflow | Status |
|----------|--------|
| `.github/workflows/ci.yml` (lint, test 3.11/3.12, OPA tests, coverage, pip-audit) | ✅ |
| `.github/workflows/release.yml` (PyPI trusted publishing, GitHub release) | ✅ |
| Coverage enforcement (`--cov-fail-under=75`) | ✅ |
| Dependency security scan (`pip-audit`) | ✅ |

---

## 7. GitHub repository settings (do after `gh repo create`)

```bash
gh repo create kitelogik/kitelogik --public --source=. --push
```

- ⬜ Branch protection on `main` (require CI pass, require 1 review)
- ⬜ Enable: Dependabot alerts, Dependabot security updates, Secret scanning, Push protection
- ⬜ Set topics: `ai-agents`, `governance`, `opa`, `policy-as-code`, `llm`, `security`, `enterprise`
- ⬜ Set description and homepage URL

---

## 8. Files to remove or scrub before going public

| File/path | Status |
|-----------|--------|
| Internal enterprise docs | ✅ Deleted |
| Internal strategy docs | ✅ Deleted |
| `docs/competitive-analysis.md` | ✅ Gitignored |
| `docs/oss-improvement-plan.md` | ✅ Gitignored |
| `benchmark.py` | 🔲 Decide: publish or omit |
| `enterprise_staging/` | ✅ Gitignored |

---

## 9. README — items to verify before going public

- ✅ Test count badge (681)
- ⬜ CI badge URL — will only work once repo exists and first CI run completes
- ⬜ Confirm `licensing@kitelogik.com` — must be live and monitored before going public
- ⬜ Confirm `security@kitelogik.com` — must be live before going public
- ✅ `kitelogik/kitelogik/policies/library/` reference — directory exists with 5 policies
- ✅ Adapter count — 11 adapters, matches README
- ✅ CLI in project structure — `kitelogik/cli.py` exists
- ✅ Agent lifecycle governance table — all event types implemented with Rego policies
- ⬜ `pip install kitelogik` — confirm PyPI name is reserved or note it's install-from-source only

---

## 10. Documentation quality

| Doc | Status |
|-----|--------|
| `CONTRIBUTING.md` | ✅ Updated 2026-04-11 |
| `SECURITY.md` | ✅ Exists with content |
| `CHANGELOG.md` | ✅ Updated with [Unreleased] section |
| `DEV.md` | ✅ Updated 2026-04-11 |
| `README.md` | ✅ Updated 2026-04-11 |
| `docs/architecture.md` | ✅ Detailed |
| `docs/what-is-kitelogik.md` | ✅ Brand/positioning doc |
| `docs/onboarding.md` | ✅ Exists |
| `docs/opa-bundle-guide.md` | ✅ Exists |
| `docs/sandbox-runtimes.md` | ✅ Exists |
| `CLAUDE.md` | ✅ Updated with governance control plane framing |

---

## 11. Best practices checklist

| Practice | Status | Notes |
|----------|--------|-------|
| **No hardcoded secrets** | ✅ | All via env vars / .env |
| **Default-deny OPA policies** | ✅ | Every .rego starts with `default allow := false` |
| **Fail-closed on OPA unreachable** | ✅ | gate.py returns deny on OPAConnectionError |
| **No `datetime.utcnow()`** | ✅ | All converted to `datetime.now(UTC)` |
| **Deprecation warnings clean** | ✅ | pytest filterwarnings enforces |
| **Ruff lint + format passing** | ✅ | Zero errors |
| **SPDX headers on all source files** | ✅ | Apache-2.0 identifier |
| **No print() in library code** | ✅ | All logging via stdlib logging |
| **Type hints on public API** | ✅ | Pydantic models + typed signatures |
| **Async-first with sync wrappers** | ✅ | `call_sync()`, sync `@governed` wrapper |
| **Tests don't require external services** | ✅ | Docker/OPA tests marked `@pytest.mark.integration` |
| **No sensitive data in test fixtures** | ✅ | All test data is synthetic |
| **Immutable audit (SQL triggers)** | ✅ | UPDATE/DELETE blocked at DB level |
| **Output sanitization before agent context** | ✅ | sanitize_tool_output() on every path |
| **Credential lifecycle (issue → use → revoke)** | ✅ | Full lifecycle in session.py |
| **.env.example provided** | ✅ | Template without real keys |
| **docker-compose.yml for dev setup** | ✅ | OPA + optional services |
| **Numpy-style docstrings** | ✅ | All public API docstrings use numpy format |
| **Memory sanitization aligned** | ✅ | SQLite and Postgres backends sanitize same tiers |

---

## 12. First PyPI publish

- ⬜ Register at pypi.org under `kitelogik`
- ⬜ Set up trusted publishing (no long-lived tokens)
- ⬜ Test publish to TestPyPI first
- ⬜ Verify `pip install kitelogik` pulls correct package and runs quickstart

---

## 13. Tag and release

```bash
# Final check
pytest -q -m "not integration"
ruff check . && ruff format --check .

# Tag
git tag -a v0.2.0 -m "v0.2.0 — Agent lifecycle governance, 11 adapters, Regorus, YAML policies"
git push origin main --tags

# GitHub release
gh release create v0.2.0 --title "v0.2.0" --generate-notes
```

---

## Summary — priority order

### Must fix before going public (launch blockers)

1. ⬜ **Confirm licensing@ and security@ emails** are live and monitored
2. ⬜ **Reserve PyPI package name**

### Should do before announce (credibility)

3. ⬜ Branch protection on `main`
4. ⬜ Enable GitHub secret scanning + push protection
5. ⬜ CI badge URL (requires first CI run)

### All feature work complete

All previously blocked features have been implemented:
- ✅ GovernanceEvent model + PolicyGate.evaluate()
- ✅ 8 core Rego policies (including agent lifecycle, plan, budget, data classification)
- ✅ agent.spawn + agent.delegate events wired into session/orchestrator
- ✅ Budget tracking fields in SessionContext
- ✅ CLI tool with compile, validate, compliance commands
- ✅ Starter policy library (5 policies)
- ✅ 11 framework adapters
- ✅ MCP stdio transport
- ✅ RegorusClient (no-Docker policy evaluation)
- ✅ HierarchicalEvaluator (2-tier policy hierarchy)
- ✅ YAML→Rego policy compiler
- ✅ Prometheus metrics
- ✅ 681 tests passing
