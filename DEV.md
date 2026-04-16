# Developer Command Reference

Personal reference for building, running, and testing Kite Logik locally.
Not part of the public-facing docs.

---

## Environment setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
docker compose up -d opa           # start OPA policy engine
cp .env.example .env               # then add ANTHROPIC_API_KEY
```

---

## Daily workflow

```bash
make demo                     # run governance quickstart (requires OPA: docker compose up -d opa)
make stop                     # stop Docker containers
make clean                    # stop everything AND wipe all local .db files (fresh state)
```

---

## Docker (optional — OPA server mode)

```bash
docker compose up -d opa                        # OPA server for team-wide policy management
docker compose ps                               # container status
docker compose logs -f opa                      # tail OPA logs
docker compose restart opa                      # reload OPA (e.g. after policy change)
docker compose stop                             # stop all containers
docker compose down                             # stop + remove containers
```

---

## CLI tools

```bash
# YAML → Rego compilation
kitelogik compile kitelogik/policies/examples/example_rules.yaml
kitelogik compile kitelogik/policies/examples/example_rules.yaml --check   # validate only

# Validate Rego syntax (requires OPA binary)
kitelogik validate
kitelogik validate --path kitelogik/policies/library/

# Governance compliance audit (OWASP ASI mapping)
kitelogik compliance
kitelogik compliance --path kitelogik/policies/

# Dry-run a governance event
kitelogik check '{"action":"approve_refund","tool_name":"approve_refund","args":{"amount":50},"context":{"session_id":"s1","user_role":"support_agent","session_scopes":["approve_refund"],"sandbox_verified":false}}'

# Print version
kitelogik version
```

---

## Python scripts

```bash
# No API key required — auto-detects Regorus or OPA
python quickstart.py

# No API key required — 8 scenarios covering delegation, injection, role thresholds
python dev/explore.py

# Getting-started example (governance demo + optional Claude agent loop)
python examples/getting-started/agent.py
```

---

## Policy tester

Test any Rego policy file against a JSON input without a full agent session.
OPA must be running first.

```bash
# Inline JSON input
python -m kitelogik.policy_tester \
    --policy kitelogik/policies/financial.rego \
    --input '{"action":"approve_refund","args":{"amount":50},"context":{"user_role":"support_agent","session_scopes":["approve_refund_under_100"]}}'

# Input from file
python -m kitelogik.policy_tester \
    --policy kitelogik/policies/security.rego \
    --input test_input.json

# Point at a non-default OPA instance
python -m kitelogik.policy_tester \
    --policy kitelogik/policies/financial.rego \
    --input '{"action":"approve_refund","args":{"amount":50},"context":{"user_role":"support_agent","session_scopes":["approve_refund_under_100"]}}' \
    --opa http://opa.staging:8181

# Exit codes: 0 = allow, 1 = deny, 2 = error — usable in CI pipelines
```

---

## Policy engines

Kite Logik supports two policy backends — use either or both:

| Engine | Install | Best for |
|---|---|---|
| **Regorus** (in-process) | Build from source ([microsoft/regorus](https://github.com/microsoft/regorus)) | Experimental — single-process deploys |
| **OPA** (server) | `brew install opa` or Docker | Team-wide policy management, fleet deployment |
| **HierarchicalEvaluator** | Built-in | 2-tier global + project policy hierarchy |

```python
# Regorus (in-process, no server)
from kitelogik.tether.regorus_client import RegorusClient
engine = RegorusClient(policy_dir="kitelogik/policies/")  # experimental — requires regoruspy built from source

# OPA (HTTP server)
from kitelogik.tether.opa_client import OPAClient
engine = OPAClient(base_url="http://localhost:8181")

# 2-tier hierarchy (global + project)
from kitelogik.tether.hierarchy import HierarchicalEvaluator
engine = HierarchicalEvaluator(global_evaluator=global_opa, project_evaluator=project_opa)

# All three implement the same PolicyEvaluator protocol
gate = PolicyGate(opa_client=engine)
```

---

## OPA / Rego

```bash
# Run embedded OPA tests
opa test kitelogik/policies/ -v

# Run tests for a specific file
opa test kitelogik/policies/examples/example_financial_thresholds.rego -v

# Interactive REPL with all policies loaded
opa run --repl kitelogik/policies/

# In REPL — evaluate a decision manually
> data.kitelogik.allow with input as {"action":"approve_refund","args":{"amount":50},"context":{"user_role":"support_agent","session_scopes":["approve_refund_under_100"]}}

# Format all Rego files in-place
opa fmt --write kitelogik/policies/

# Build a production bundle (for bundle server deployment)
opa build kitelogik/policies/ -o bundle.tar.gz

# Check OPA health
curl -s http://localhost:8181/health | python -m json.tool
```

---

## Tests

```bash
# Full suite — 681+ tests (excludes integration and postgres tests)
pytest -q

# With coverage report
pytest --cov --cov-report=term-missing -q

# Coverage with failure threshold
pytest --cov --cov-fail-under=75 -q

# Run a specific test file
pytest tests/test_gate.py -v
pytest tests/test_governed.py -v
pytest tests/test_hierarchy.py -v

# Run only fast unit tests (skip integration + slow)
pytest -q -m "not integration and not slow"

# Run fuzz tests (property-based testing via Hypothesis)
pytest tests/fuzz/ -v

# Run adversarial/security tests
pytest tests/adversarial/ -v

# Run framework adapter tests
pytest tests/test_new_adapters.py -v

# Run E2E flow tests
pytest tests/test_e2e_flows.py -v

# Run integration tests (requires Docker + OPA running)
pytest -m integration -v

# Run tests and show deprecation warnings as errors
pytest -W error::DeprecationWarning -q

# Run a single test by name
pytest -k "test_gate_hard_blocks" -v
```

---

## Benchmark

OPA must be running. Tests policy gate latency under concurrent load.

```bash
python dev/benchmark.py                              # 1000 runs, concurrency 5
python dev/benchmark.py --runs 5000                  # more runs for stable p99
python dev/benchmark.py --concurrency 20             # higher concurrency
python dev/benchmark.py --opa http://opa.staging:8181
```

---

## Linting

```bash
ruff check .                   # lint check
ruff check --fix .             # auto-fix safe issues
ruff format .                  # format in-place
ruff format --check .          # format check only (CI mode)
```

---

## Dependency audit

```bash
pip install pip-audit
pip-audit                      # scan for CVEs in installed packages
pip-audit --strict             # non-zero exit on any finding
```

---

## Inspecting local state

```bash
# List tables and row counts in a SQLite database
sqlite3 hitl.db "SELECT name FROM sqlite_master WHERE type='table';"
sqlite3 hitl.db "SELECT COUNT(*) FROM pending_actions;"
sqlite3 memory.db "SELECT key, trust_tier, session_id FROM memory_entries ORDER BY updated_at DESC LIMIT 20;"
sqlite3 events.db "SELECT tool, outcome, session_id FROM events ORDER BY received_at DESC LIMIT 20;"

# Tail the live OTel trace log
tail -f traces.jsonl | python -m json.tool

# Check OPA's loaded policies
curl -s http://localhost:8181/v1/policies | python -m json.tool

# Manually evaluate a policy via OPA REST API
curl -s -X POST http://localhost:8181/v1/data/kitelogik \
    -H "Content-Type: application/json" \
    -d '{"input":{"action":"approve_refund","args":{"amount":50},"context":{"user_role":"support_agent","session_scopes":["approve_refund_under_100"]}}}' \
    | python -m json.tool
```

---

## Landing page dev server

```bash
make landing                   # live-reload server at http://localhost:8099/landing.html
# edit docs/landing.html — browser reloads on every save
```

---

## OSS vs Enterprise — how the split works

**Model:** open-core. One public OSS repo (`kitelogik/kitelogik`), one private
enterprise repo (`kitelogik/kitelogik-enterprise`). Enterprise never forks OSS;
it installs alongside it and registers implementations via Python entry points.

**OSS code never imports enterprise code.** It calls `load_plugin(group)` and
gets back either the enterprise implementation (if installed) or `None`.

**Entry-point groups** (defined in `kitelogik/edition.py`):

| Group | OSS default | Enterprise override |
|---|---|---|
| `kitelogik.sandbox_runtime` | *(none — enterprise only)* | `DockerRuntime` / `FirecrackerRuntime` |
| `kitelogik.memory_backend` | `MemoryStore` (SQLite) | `PostgresMemoryBackend` |
| `kitelogik.hitl_backend` | `HITLQueue` (SQLite) | `PostgresHITLQueue` |
| `kitelogik.credential_broker` | `CredentialBroker` (in-memory) | `VaultCredentialBroker` |
| `kitelogik.audit_backend` | `AuditStore` (SQLite) | `PostgresAuditStore` |

**Detecting edition at runtime:**

```python
from kitelogik import edition, Edition, load_plugin

print(edition())             # Edition.OSS or Edition.ENTERPRISE
cls = load_plugin("kitelogik.memory_backend")  # None on OSS
```

**How enterprise-repo structure looks:**

```
kitelogik-enterprise/
├── pyproject.toml               # [project.entry-points."kitelogik.*"] registrations
├── kitelogik_enterprise/
│   ├── dashboard/               # Real-time governance dashboard (WebSocket)
│   ├── gateway/                 # HTTP API for centralized policy enforcement
│   ├── agents/orchestrator.py   # Multi-agent delegation coordination
│   ├── agents/registry.py       # Fleet agent tracking
│   ├── sandbox/                 # Docker/Firecracker container isolation
│   ├── observability/           # SIEM webhook, Prometheus metrics, Grafana
│   ├── anchor/api.py            # HITL REST endpoints
│   ├── anchor/postgres_*.py     # Postgres credential/HITL backends
│   ├── memory/postgres_store.py # Postgres memory backend
│   ├── audit/postgres_store.py  # Postgres audit backend
│   └── mcp/mock_server.py       # Mock MCP server for demos
```

**Marking extension points in OSS code:**

When adding a new extension point, add this comment above the OSS fallback:

```python
# ── Enterprise extension point: kitelogik.<group> ────────────────────────────
```

**Testing enterprise locally:**

```bash
# In kitelogik-enterprise repo
pip install -e ../kitelogik        # install OSS in editable mode
pip install -e .                   # install enterprise on top

python -c "from kitelogik import edition; print(edition())"
# Edition.ENTERPRISE
```

---

## Publishing checklist

See `docs/oss-publish-checklist.md` for the full pre-publish checklist.

```bash
# Quick pre-publish sanity checks
ruff check . && ruff format --check .
pytest -q -m "not integration" --ignore=tests/adversarial   # 681+ tests
kitelogik compliance                                         # OWASP ASI audit
opa test kitelogik/policies/ -v
python -m build --sdist --wheel
twine check dist/*
```
