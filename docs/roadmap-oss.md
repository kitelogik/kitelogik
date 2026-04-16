# Kite Logik — Open Source Roadmap

This document defines the task list for taking Kite Logik from its current state (a working but unpublished codebase) to a production-grade, professionally published open source project. For each task: what to build, why it matters, which best practices govern it, how it serves the OSS mission, and where it feeds into the enterprise product.

Tasks are ordered within each phase by dependency and impact. Earlier phases must be completed before later phases are released publicly.

---

## Current State Assessment

The codebase has strong technical bones: a real OPA policy engine, a working HITL queue, 350 tests, a functioning dashboard, and the enterprise components (Gateway, PostgreSQL backends, SIEM, audit store) already built. What is missing is everything around the code that makes a project a project:

- No `.gitignore` — secrets and database files will be committed on first push
- No `LICENSE` — legally "all rights reserved" without one; blocks enterprise adoption
- No `README.md` — GitHub shows nothing; first impression fails
- No `.dockerignore` — the Docker image copies `.venv/` and test fixtures
- `asyncpg` is a hard dependency — forces a native build on every OSS install, even ones that never touch Postgres
- No CI/CD — there is no automatic verification that contributions don't break things
- No `CONTRIBUTING.md` — no guidance for the community
- No quickstart example — nothing to run after `pip install`
- No annotated policy examples — the core value proposition (Policy-as-Code) has no entry point for new users

The enterprise components are complete and tested. The gap is everything between "it works on my machine" and "an engineer at a company I've never met can pick this up and trust it."

---

## Phase 1 — Release Gate

**Goal:** The minimum required before the first public commit to GitHub. Nothing else should ship before these are in place. These are not improvements — they are preconditions.

---

### Task 1.1 — `.gitignore`

**What:** Create a root `.gitignore` covering Python, Docker, macOS, JetBrains IDEs, and all Kite Logik runtime artifacts.

**Minimum contents:**
```
# Python
__pycache__/
*.py[cod]
*.egg-info/
dist/
build/
.venv/

# Runtime artifacts
*.db
*.sqlite
*.log

# Secrets
.env
.env.*
!.env.example

# Docker
.dockerignore

# macOS
.DS_Store

# JetBrains
.idea/

# Test output
.pytest_cache/
.coverage
htmlcov/
```

**Why:** Without this, the first `git init && git add .` commits `.venv/` (60,000+ files), `hitl.db`, `memory.db`, and any `.env` file containing `ANTHROPIC_API_KEY`. This would be a security incident on the first day.

**Best practices:** The `.env` pattern requires a specific exception: ignore `.env` and `.env.*` but explicitly track `.env.example` (the template). This is the standard pattern used by Django, FastAPI, and most Python projects.

**OSS mission:** A clean repository is a signal of maturity. Contributors will run into bizarre errors if `.venv/` or a local database is accidentally committed.

**Enterprise alignment:** The enterprise deployment pipeline (GitHub Actions → Docker image → ECR → ECS) will fail silently if node_modules-equivalent files are tracked. A good `.gitignore` now prevents expensive CI debugging later.

---

### Task 1.2 — `LICENSE` (Apache 2.0)

**What:** Add `LICENSE` at the project root with the Apache License 2.0 text, copyright line: `Copyright 2026 Kite Logik Contributors`.

**Why Apache 2.0 and not MIT:**
- Apache 2.0 includes an explicit **patent grant** — contributors grant users a license to any patents their contributions might touch. For a security/compliance product this matters: enterprise legal teams will flag "no patent grant" as a blocker on MIT-licensed tools.
- Apache 2.0 allows commercial use (critical for the open-core model) but requires preservation of the copyright notice.
- Apache 2.0 is the standard for infrastructure OSS: Kubernetes, Terraform, OPA itself, OpenTelemetry.
- It is compatible with the enterprise commercial license layered on top.

**Why:** Without a license file, every file in the repository is legally "all rights reserved." Any company that tries to use or contribute to Kite Logik is technically infringing copyright. Enterprise legal reviews will reject it outright.

**Best practices:** `SPDX-License-Identifier: Apache-2.0` comment at the top of every source file is the machine-readable standard used by FOSS compliance tools (FOSSA, Snyk). Add to all `.py` files as part of this task.

**OSS mission:** Apache 2.0 maximises adoption. It explicitly welcomes commercial use, which is what the target audience (platform engineers at enterprises) needs to hear from legal before they can engage.

**Enterprise alignment:** The commercial enterprise license is layered on top of Apache 2.0 for enterprise-only features (PostgreSQL backends, Gateway, SIEM). The open source core being Apache 2.0 makes this legally clean.

---

### Task 1.3 — `.dockerignore`

**What:** Create `.dockerignore` at project root.

**Minimum contents:**
```
.venv/
.git/
.github/
__pycache__/
*.py[cod]
*.db
*.sqlite
*.log
.env
.env.*
tests/
docs/
*.md
.DS_Store
.idea/
dist/
build/
htmlcov/
.coverage
```

**Why:** Currently, `docker build` copies the entire project into the image including `.venv/` (hundreds of MB), test fixtures, local databases, and potentially `.env` files. The resulting image is bloated, insecure (local secrets in a container layer), and non-reproducible.

**Best practices:** The canonical Docker pattern is: `COPY pyproject.toml .` → `RUN pip install` → `COPY src/ src/`. The `.dockerignore` enforces that only the source is copied, not the local environment.

**OSS mission:** A compact, reproducible Docker image means `docker pull kitelogik/kitelogik` works identically everywhere. Contributors can trust the image they build locally matches what production runs.

**Enterprise alignment:** Enterprise deployments push images to ECR/GCR. An image with `.venv/` included will fail size limits, cost more in registry storage, and increase attack surface during security scans (Trivy, Snyk Container).

---

### Task 1.4 — Move `asyncpg` to Optional Dependency

**What:** In `pyproject.toml`, move `asyncpg>=0.29.0` from `[project.dependencies]` to a new optional extras group:

```toml
[project.optional-dependencies]
postgres = [
    "asyncpg>=0.29.0",
]
dev = [
    "pytest>=8.0.0",
    "pytest-asyncio>=0.23.0",
    "pytest-mock>=3.14.0",
    "respx>=0.21.0",
    "ruff>=0.6.0",
    "livereload>=2.7.0",
]
enterprise = [
    "asyncpg>=0.29.0",
]
```

**Why:** `asyncpg` is a native extension that requires a C compiler and `libpq` headers at build time. On a fresh macOS or Linux machine without `libpq-dev` installed, `pip install kitelogik` fails with a confusing C compilation error before the user has run a single line of Kite Logik code. OSS users who only use SQLite will never touch Postgres; they should not pay this cost.

**Best practices:** The standard open-core pattern: `pip install kitelogik` (SQLite only) vs `pip install kitelogik[postgres]` (adds Postgres support). All guard the import with a try/except in the module that uses it, raising a clear error: `"PostgreSQL backends require: pip install kitelogik[postgres]"`.

**OSS mission:** The OSS install must be frictionless. A failed install in the first 30 seconds is the top contributor to abandonment. Every native dependency that can be optional, should be.

**Enterprise alignment:** Enterprise users explicitly install `kitelogik[postgres]` or `kitelogik[enterprise]`. This makes the enterprise/OSS boundary explicit at the package level, which is the right mental model for both users.

---

### Task 1.5 — `.env.example`

**What:** Create `.env.example` at the project root:

```bash
# Required
ANTHROPIC_API_KEY=your_api_key_here

# Optional — defaults shown
OPA_BASE_URL=http://localhost:8181
HITL_DB_PATH=hitl.db
MEMORY_DB_PATH=memory.db
DASHBOARD_PORT=8050

# Optional — enterprise
# DATABASE_URL=postgresql://user:pass@localhost/kitelogik
# SIEM_WEBHOOK_URL=https://splunk.internal:8088/services/collector
# SIEM_API_KEY=Splunk your_hec_token_here
# OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

**Why:** Without `.env.example`, new contributors guess which environment variables exist. They either set the wrong thing or miss required variables and get unhelpful errors.

**Best practices:** Every variable should have a comment explaining what it does and where to get the value. Enterprise variables are commented out — they document what exists without implying they are required for the OSS path.

**OSS mission:** Reduces the "getting started" friction. A developer who can clone → copy `.env.example` → fill in one value → `make demo` is a developer who evaluates the product rather than bouncing.

**Enterprise alignment:** The enterprise variables in `.env.example` act as discovery documentation — a developer who sees `DATABASE_URL` and `SIEM_WEBHOOK_URL` commented out understands what the enterprise edition adds without reading a sales page.

---

## Phase 2 — Foundation

**Goal:** The infrastructure that makes Kite Logik a maintainable, contribution-ready OSS project. Once Phase 1 is complete, these tasks can be done in parallel.

---

### Task 2.1 — `README.md`

**What:** The primary GitHub landing page. Target: 600–800 words, readable in under 3 minutes.

**Required sections:**
1. **Headline** — what it is in one sentence
2. **The problem** — 3 bullet points: why prompts are not a security boundary
3. **How it works** — the 3-layer diagram (Tether → Anchor → Sandbox) with ASCII art
4. **Quickstart** — `pip install` → `make demo` → see output. Must work copy-paste
5. **Core concept** — one short Rego snippet from `financial.rego` with inline comments
6. **What's included** — 3-column table: feature / OSS / Enterprise
7. **Test coverage badge** — `make test` → N tests passing
8. **Links** — Docs, Contributing, License, Enterprise

**Why:** GitHub `README.md` is the product's first impression for every engineer who hears about Kite Logik. No README means the GitHub page shows only file listings. For a security/compliance product, an absent README signals abandonment or prototype status.

**Best practices:**
- Never put the full documentation in the README — link to `docs/`. README is the hook; docs are the reference.
- The Quickstart must be tested on a clean machine before publishing. Copy-paste failure in the README is the single most cited reason for abandoning OSS tools in developer surveys.
- Badges (CI status, test count, license) signal active maintenance before the reader reads a word.

**OSS mission:** The README is the primary acquisition surface. The tagline "AI agents with boundaries your compliance team can read" belongs above the fold, with the Rego snippet immediately below. The target reader is a platform engineer who has 90 seconds to decide if this is worth a deeper look.

**Enterprise alignment:** The OSS/Enterprise feature table in the README is intentional positioning: enterprises see what they get for free, what they need to pay for, and that the architecture is credible before they book a call.

---

### Task 2.2 — GitHub Actions CI

**What:** Create `.github/workflows/ci.yml` with three jobs that run on every push and pull request.

**Job 1 — `lint`:**
```yaml
- run: .venv/bin/ruff check .
- run: .venv/bin/ruff format --check .
```

**Job 2 — `test`:**
```yaml
strategy:
  matrix:
    python-version: ["3.11", "3.12"]
- run: pip install -e ".[dev]"
- run: pytest -q -m "not integration"
```

**Job 3 — `opa-test`** (runs OPA native policy tests):
```yaml
- uses: open-policy-agent/setup-opa@v2
  with:
    version: latest
- run: opa test kitelogik/policies/ -v
```

**Why:** Without CI, there is no guarantee that a contributor's PR doesn't break existing tests. For a security product, a broken policy test that slips through is not an embarrassment — it is a potential security regression.

**Best practices:**
- Matrix testing on 3.11 and 3.12 catches version-specific behaviour early.
- OPA tests run in CI independently from Python tests — policy regressions are caught by the correct tool (OPA), not by Python mocks.
- `not integration` marker excludes tests that require live Docker/OPA in the CI environment, keeping the feedback loop fast.
- Status badge in README shows green/red to visitors before they read a word.

**OSS mission:** CI signals that the project is professionally maintained and that contributions are held to a standard. Contributors who see a green badge trust that their PR will get a fair review, not be lost in a broken-by-default state.

**Enterprise alignment:** The same CI workflow becomes the foundation for the enterprise CD pipeline: add a `deploy` job that pushes to ECR on merge to `main`. The test matrix is already in place.

---

### Task 2.3 — `CONTRIBUTING.md`

**What:** Contribution guide covering: development environment setup, how to run tests, code style, PR process, and the security disclosure path.

**Required sections:**
1. **Development setup** — exact commands from clone to `make test` passing
2. **Running tests** — unit tests, OPA tests, adversarial tests (with Docker caveat)
3. **Code style** — ruff, line length 100, `ruff check . && ruff format .` before PR
4. **PR process** — one feature/fix per PR, link to issue, tests required for new functionality
5. **Adding a policy rule** — the flow: Rego rule → OPA test → Python integration test
6. **Security disclosure** — link to `SECURITY.md`, do not open public issues for vulnerabilities

**Why:** Without `CONTRIBUTING.md`, every first-time contributor asks the same questions via issues: "how do I run tests?", "what's the code style?", "how do I add a policy?" This is wasted maintainer time at scale.

**Best practices:** The "adding a policy rule" section is critical for Kite Logik specifically. Most Python contributors will not know the Rego → OPA test → Python integration test flow. Documenting this exact sequence reduces the friction of the most important type of contribution (new domain policies).

**OSS mission:** Community growth depends on contributors feeling welcomed and capable. A CONTRIBUTING guide with clear, working instructions is the difference between a contributor who opens a PR and one who closes the tab.

**Enterprise alignment:** Enterprise customers often contribute domain-specific policy rules back to the OSS core (healthcare, financial, GDPR). A clear contribution process makes this path obvious.

---

### Task 2.4 — `SECURITY.md`

**What:** Responsible disclosure policy.

**Contents:**
- Supported versions table
- How to report a vulnerability (private GitHub Security Advisory or email)
- Response timeline commitment (acknowledge within 72 hours, patch within 30 days for critical)
- What information to include in a report
- What is in scope vs out of scope (the policy engine itself, not the demo scripts)
- Credit policy (CVE attribution, acknowledgement in changelog)

**Why:** For a security product, `SECURITY.md` is not optional. If a researcher discovers a policy bypass — say, a Rego rule that can be circumvented with a crafted input — they need a path to report it that doesn't require opening a public GitHub issue. A public issue for a security vulnerability in a policy engine is a 0-day disclosure.

**Best practices:** GitHub's "Report a vulnerability" feature (private security advisories) is the correct mechanism. `SECURITY.md` should link directly to it. Response timeline commitments should be realistic — 30 days for a patch on a critical finding is the industry standard for small teams.

**OSS mission:** Security tooling that doesn't take its own security seriously is a red flag. `SECURITY.md` signals that the project treats security with the same rigour it asks its users to apply.

**Enterprise alignment:** Enterprise customers run security reviews before adopting infrastructure tooling. The absence of `SECURITY.md` is frequently a finding in vendor security assessments.

---

## Phase 3 — Developer Experience

**Goal:** The first experience for a new user or evaluator. These tasks define what happens in the first 15 minutes after someone finds Kite Logik.

---

### Task 3.1 — `quickstart.py`

**What:** A 50-line, single-file example at the project root that demonstrates the core value proposition end-to-end. Requires only OPA running (`docker run -p 8181:8181 openpolicyagent/opa run --server --addr :8181`).

**What it shows:**
1. Import from `kitelogik`
2. Create `OPAClient`, `PolicyGate`, `HITLQueue`, `CredentialBroker`
3. Issue a session token with explicit scopes
4. Create an `AgentSession`
5. Run one allowed tool call → print result
6. Run one blocked tool call → print block reason
7. Revoke the session token

**Why:** `agents/demo.py` (13 scenarios, full dashboard integration) is too complex as a first example. An evaluator needs to understand the core loop in under 5 minutes. `quickstart.py` is that entry point.

**Best practices:**
- Every import is from `kitelogik` — no internal module paths. This validates that the SDK entrypoint (`kitelogik/__init__.py`) exports everything needed.
- The file is self-contained: no separate config files, no database files, no environment setup beyond `ANTHROPIC_API_KEY` and OPA.
- Comments explain every decision: why scopes are explicit, why the token is revoked, what the gate does.

**OSS mission:** The quickstart is the answer to "how do I use this in my own agent?" It bridges the gap between reading the README and adopting the library. For a developer audience, code is more persuasive than prose.

**Enterprise alignment:** The enterprise quickstart (showing `PostgresHITLQueue`, `PostgresAuditStore`, and the Gateway) is a direct extension of this file — same shape, more powerful components. Starting with a clean OSS quickstart makes the enterprise upgrade path obvious.

---

### Task 3.2 — `kitelogik/kitelogik/policies/examples/`

**What:** Three Rego policy files with extensive inline comments. Each is a standalone, runnable policy that demonstrates a different governance pattern.

**File 1: `example_read_only_agent.rego`**
- Allow only read operations; block everything that writes or deletes
- Comments explain: how the action allowlist works, how to add new read actions
- OPA test included in the same file

**File 2: `example_tiered_approval.rego`**
- Low-value actions: auto-approve
- Medium-value: require specific scope
- High-value: require HITL regardless of scope
- Comments explain: what risk tiers mean, how to set thresholds, the `is_number()` guard

**File 3: `example_tool_isolation.rego`**
- Agent A can only call tools in set A; Agent B can only call tools in set B
- Cross-agent tool access blocked
- Comments explain: how role + scope combination works, how to extend the role map

**Why:** "Policy-as-Code" is Kite Logik's core differentiator. If a platform engineer can't write their first policy rule within 30 minutes of evaluating the product, that differentiator is inaccessible. The examples are the documentation that makes the concept tangible.

**Best practices:**
- Every file starts with a comment block: "What this policy does", "What to change for your use case", "What the expected OPA input looks like."
- Every file has embedded OPA tests (`test_` prefixed rules) that run with `opa test`.
- Policies are genuinely useful — not "hello world" placeholders — so engineers can copy-modify-use rather than starting from scratch.

**OSS mission:** The examples directory is the on-ramp to the most differentiated part of Kite Logik. Making Policy-as-Code accessible to engineers who have never written Rego is the single highest-leverage contribution to adoption.

**Enterprise alignment:** Enterprise customers will contribute domain-specific policies (healthcare, financial, GDPR) back to `kitelogik/kitelogik/policies/examples/`. A well-structured examples directory with a consistent format makes this contribution path clear.

---

### Task 3.3 — `kitelogik/policy_tester.py`

**What:** A CLI tool that loads a Rego policy file and a JSON input, sends the input to OPA, and prints the decision in human-readable format.

```bash
python -m kitelogik.policy_tester \
  --policy policies/financial.rego \
  --input '{"action": "approve_refund", "args": {"amount": 50}, "context": {...}}'
```

**Output:**
```
Policy:  policies/financial.rego
Input:   approve_refund (amount=50)

Decision
  allow:          true
  deny:           false
  risk_tier:      TRANSACTIONAL_LOW
  requires_hitl:  false
  rule_matched:   allow_refund_low_value

OPA response time: 4ms
```

**Why:** Engineers writing new Rego rules need a fast feedback loop. The current workflow requires starting the full stack (OPA container + Python) just to test whether a rule matches. The policy tester reduces this to a single command.

**Best practices:**
- Uses the existing `OPAClient` — no new OPA integration. The tool is a thin CLI wrapper over existing infrastructure.
- `--dry-run` flag loads the policy into a temporary OPA instance via `opa eval` subprocess, not the production OPA server. This means it works without `make demo` running.
- Exits with code `0` for allow, `1` for deny, `2` for error — scriptable in CI.

**OSS mission:** Developer tooling that reduces friction for the primary contribution type (new policies) directly accelerates community growth. The policy tester is the IDE for Kite Logik's most distinctive feature.

**Enterprise alignment:** The enterprise policy management UI uses the same evaluation path under the hood. Building the CLI first establishes the interface contract.

---

## Phase 4 — Production Hardening

**Goal:** Make Kite Logik suitable for production deployments, not just demos. These tasks close the gap between "it works" and "an ops team can run it at 3am when something goes wrong."

---

### Task 4.1 — Multi-Stage Dockerfile

**What:** Replace the current single-stage Dockerfile with a proper multi-stage build.

```dockerfile
# Stage 1: build deps
FROM python:3.11-slim AS builder
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir --user -e .

# Stage 2: runtime
FROM python:3.11-slim AS runtime
WORKDIR /app
COPY --from=builder /root/.local /root/.local
COPY . .
ENV PATH=/root/.local/bin:$PATH
USER 1000:1000      # non-root
EXPOSE 8050
```

**Why:** The current Dockerfile:
- Is a single stage — dev tools, test fixtures, and C headers end up in the production image
- Runs as root — any container escape leads to root on the host
- Has no EXPOSE declaration — container orchestrators can't introspect the ports
- Copies `.venv/` unless `.dockerignore` is present (Task 1.3)

**Best practices:**
- Builder stage installs all dependencies; runtime stage has only what's needed to run
- Non-root user (`USER 1000:1000`) is a security baseline required by most enterprise container policies and Kubernetes pod security standards
- Pinned base image (`python:3.11.9-slim`) for reproducibility; Dependabot handles the pin updates
- `HEALTHCHECK` instruction: `HEALTHCHECK CMD curl -f http://localhost:8050/api/health || exit 1`

**OSS mission:** A production-quality Dockerfile signals that Kite Logik is ready to deploy, not just demo. Contributors who are platform engineers will immediately spot a single-stage root-running Dockerfile as a red flag.

**Enterprise alignment:** Enterprise deployments run Trivy/Snyk Container scans on every image. Root-running containers fail most enterprise security policies. Multi-stage builds reduce the CVE surface by keeping compiler toolchains out of the runtime layer.

---

### Task 4.2 — Comprehensive Health Endpoint

**What:** Update `GET /api/health` in `dashboard/server.py` to actively probe all dependent services and return structured status.

**Target response:**
```json
{
  "status": "ok",
  "checks": {
    "opa": {"status": "ok", "latency_ms": 3},
    "hitl_queue": {"status": "ok", "pending_count": 2},
    "memory_store": {"status": "ok"},
    "database": {"status": "ok"}
  },
  "version": "0.1.0",
  "policy_version": "a3f4b2c1"
}
```

If any check fails, `"status"` at the top level becomes `"degraded"` or `"error"`, and the endpoint returns HTTP 503.

**Why:** The current `/api/health` returns a static response. A load balancer health check or Kubernetes readiness probe that hits this endpoint gets a false positive if OPA is down — the gateway is up, but all policy enforcement is broken (and failing closed means all tool calls are blocked).

**Best practices:**
- Health checks must be honest. A `200 OK` from a `/health` endpoint means "this service can serve traffic." If OPA is unreachable, the answer is no.
- Probe with a timeout (500ms max per dependency). Never let a slow OPA response make the health check time out and mark the container unhealthy.
- Include `version` and `policy_version` — ops teams need to verify which version is running without SSHing into the container.
- `GET /api/health/live` (always 200 if process is running) vs `GET /api/health/ready` (200 only if all deps healthy) — the Kubernetes liveness/readiness probe pattern.

**OSS mission:** Reliable health endpoints are table stakes for any service that claims to be production-ready. Platform engineers will evaluate this immediately.

**Enterprise alignment:** Enterprise Kubernetes deployments use readiness probes to prevent traffic from routing to instances where OPA is still warming up. The liveness/readiness distinction enables zero-downtime rolling deploys.

---

### Task 4.3 — `benchmark.py`

**What:** A script at the project root that measures gate evaluation latency against a running OPA instance.

**What it tests:**
- 1,000 calls: simple allow (read operation)
- 1,000 calls: HITL trigger (high-value refund)
- 1,000 calls: hard deny (security block)

**Output:**
```
Kite Logik Gate Latency Benchmark
OPA: http://localhost:8181
Iterations: 1,000 per scenario

Scenario                     p50      p95      p99      max
───────────────────────────────────────────────────────────
Simple allow                 4ms      7ms      11ms     18ms
HITL trigger                 5ms      8ms      13ms     22ms
Hard deny (security block)   4ms      7ms      10ms     16ms
```

**Why:** The landing page claims `<8ms gate latency`. Without a reproducible benchmark, this claim is unverifiable. Engineers evaluating Kite Logik for a latency-sensitive path will measure this themselves. Providing the benchmark script controls the measurement methodology and makes the claim trustworthy.

**Best practices:**
- Warm up OPA before measurement (100 calls discarded) — cold JIT compilation inflates early numbers
- Uses `statistics.quantiles()` from the standard library — no benchmark framework dependency
- Reports wall clock time end-to-end (including HTTP round-trip to OPA), not just Python-side CPU time — this is the number that matters for real deployments
- Parameterised: `--iterations 1000 --opa-url http://localhost:8181`

**OSS mission:** Verifiable performance claims are a sign of technical confidence. Publishing the benchmark script invites the community to reproduce, challenge, and improve the numbers — which is exactly the kind of engagement that builds trust.

**Enterprise alignment:** Enterprise performance SLAs (e.g. "gate evaluation must add <10ms P99 to API latency") need a reproducible measurement methodology. The benchmark script is the starting point for those conversations.

---

### Task 4.4 — Demo Script Polish (`agents/demo.py`)

**What:** Add `argparse` CLI flags to `agents/demo.py` and a summary table after all scenarios run.

**Flags:**
```
--speed [fast|demo]   fast: 5s HITL timeout (for quick runs); demo: 30s (default)
--no-dashboard        skip push_event() calls; run terminal-only
--otlp URL            send traces to this OTLP endpoint instead of file
```

**Summary table (printed after all 13 scenarios):**
```
Demo Summary
──────────────────────────────────────────────────────────
  #   Scenario                           Outcome   Latency
  ─────────────────────────────────────────────────────────
  1   Code exec — no sandbox             BLOCK      6ms
  2   Code exec — sandbox verified       ALLOW      8ms
  3   Read customer — correct scope      ALLOW      5ms
  ...
  13  Worker agent — refund over cap     BLOCK      7ms
──────────────────────────────────────────────────────────
  ALLOW: 6   BLOCK: 6   HITL: 1
  Total time: 14.3s
```

**Why:** The current demo script runs sequentially with no outcome summary. A developer running `make demo` sees 13 blocks of output but no consolidation. The summary table makes the enforcement story legible: here are the decisions, here is the latency, here is what the policy engine did.

**Best practices:**
- `--speed fast` is critical for iterating during development (HITL timeout of 5s vs 30s).
- `--no-dashboard` enables terminal-only CI-like runs where the dashboard is not needed.
- `--otlp` enables the enterprise trace story without requiring it.
- Every scenario tracks `(name, outcome, latency_ms)` in a list; the table renders at the end regardless of whether individual scenarios succeed or fail.

**OSS mission:** The demo is the product's primary demonstration vehicle at conferences and in screencasts. A polished demo with a clean summary table is the difference between "interesting prototype" and "this is real."

**Enterprise alignment:** `--otlp http://localhost:4318` is the flag used in `make demo-enterprise`. The same demo script, the same scenarios, more observability. This consistency is intentional.

---

## Phase 5 — Dashboard Completeness

**Goal:** The dashboard needs two more features to be a complete operational UI: the ability to filter by session and an audit log tab.

---

### Task 5.1 — Session Filter on Live Feed

**What:** Add a session dropdown to the live feed tab in `dashboard/index.html`. When a session is selected, the feed filters to show only events from that session.

**Implementation:**
- Maintain a `sessionsSeen` Set populated from every `gate_decision` WebSocket event
- Render a `<select>` populated from this set above the filter bar
- Filter feed cards by matching `session_pill` text against the selected session
- "All sessions" is the default option

**Why:** In production, multiple agent sessions run simultaneously. Without session filtering, the live feed is noise — a mix of events from unrelated sessions that makes it impossible to follow what a specific agent is doing. Session filtering is the basic operational capability for multi-agent deployments.

**Best practices:**
- Session filter reuses the existing filter logic — no new JS complexity
- The `<select>` is populated lazily from WebSocket events — no API call required
- Filter state is preserved if new events arrive while a session is selected

**Enterprise alignment:** Session filtering is the first step toward the enterprise multi-tenant session isolation view. The dropdown becomes a full session management panel in the enterprise edition.

---

### Task 5.2 — Audit Log Tab

**What:** Add a fourth tab "Audit Log" to the dashboard sidebar.

**Contents:**
- Filter row: outcome (all/allowed/blocked/hitl), session dropdown
- Table: timestamp | session | tool | outcome | risk tier | latency | rule matched
- Data source: `GET /api/audit?outcome=&session_id=&limit=50`
- Populated on tab open, polling every 15s
- Export button: download filtered results as CSV

**What to add to `dashboard/server.py`:**
```python
@app.get("/api/audit")
async def get_audit(session_id: str | None = None, outcome: str | None = None, limit: int = 100):
    # reads from AuditStore; if not configured, returns 503 with clear message
```

**Why:** The audit log is the compliance artefact. An operator who needs to answer "what did the agent do between 2pm and 3pm on Tuesday?" needs this view. Without it, they have to read raw OTel trace files.

**Best practices:**
- `AuditStore` is injected as an optional dependency in `init_app()`. If not provided, the endpoint returns `503 Service Unavailable` with a JSON body explaining the SQLite audit store is not configured — not a silent empty table.
- The table renders as plain HTML `<table>` using existing CSS variables — no new JS framework.
- CSV export is a `<a href="/api/audit?format=csv">` link — the server returns `Content-Type: text/csv` with the appropriate filename. No client-side CSV generation.

**OSS mission:** The audit log tab makes the "complete governance picture" claim visible and interactive. A compliance officer watching a demo who can click through to the audit log and export it is a much stronger conversion moment than "the data is in the database."

**Enterprise alignment:** The enterprise audit log (PostgreSQL-backed, `policy_version` included, append-only) uses the same dashboard tab. The OSS version shows what the audit log looks like; the enterprise version makes it production-grade.

---

## Phase 6 — Enterprise Foundations

These tasks are built in the OSS codebase but are directly targeted at making the enterprise edition usable in production. They do not require enterprise infrastructure to develop.

---

### Task 6.1 — `CHANGELOG.md`

**What:** A changelog following the [Keep a Changelog](https://keepachangelog.com/) format.

**Initial entry:**
```markdown
# Changelog

## [Unreleased]
### Added
- Initial open source release
- Tether policy gate (OPA/Rego)
- Anchor HITL queue (SQLite)
- Sandbox container isolation (Docker)
- Real-time dashboard
- 13 demo scenarios
- 350 test cases

## [0.1.0] — 2026-03-24
...
```

**Why:** Contributors and users need to know what changed between versions. For a compliance product, changelog entries are also compliance artefacts — a customer's change management process requires documentation of what changed in the security tooling they run.

**Best practices:** Keep a Changelog format (`Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`) is the standard and is parseable by automated tooling. The `Security` category is especially important for a policy engine.

**Enterprise alignment:** Enterprise customers on SLAs need to evaluate every upgrade for compliance impact. A structured changelog with a `Security` section makes this evaluation tractable.

---

### Task 6.2 — GitHub Issue and PR Templates

**What:** Create `.github/ISSUE_TEMPLATE/` with two templates and `.github/pull_request_template.md`.

**Bug report template:** Kite Logik version, OPA version, Python version, reproduction steps, expected vs actual behaviour, relevant policy files.

**Feature request template:** Problem statement, proposed solution, which layer it affects (Tether/Anchor/Sandbox), OSS or enterprise only?

**PR template:** Description, type (bug fix / feature / policy / docs), tests added, OPA tests updated if policies changed, breaking changes.

**Why:** Consistent issue and PR templates reduce the maintainer time spent asking follow-up questions. "What version are you on?" and "did you add tests?" should not need to be asked for every issue and PR.

**OSS mission:** Good templates signal a professionally maintained project that respects contributor and maintainer time equally.

**Enterprise alignment:** Issue templates that ask "OSS or enterprise only?" make it easy to triage which issues go into the OSS roadmap vs. the enterprise backlog.

---

### Task 6.3 — `docs/architecture.md`

**What:** A technical architecture document covering the full system: component responsibilities, data flow for a tool call through all three layers, the OPA evaluation model, the HITL lifecycle, and the delegation depth enforcement mechanism.

**Key diagrams to include:**
1. Full stack diagram (agent → Tether → Anchor/Sandbox → tool infrastructure)
2. A single tool call sequence: credential validation → schema validation → OPA evaluation → ALLOW/HITL/DENY → execution → sanitization → audit
3. The HITL state machine: PENDING → APPROVED/DENIED/TIMED_OUT
4. Delegation depth: parent token → child token scope subset constraint

**Why:** Enterprise buyers evaluating Kite Logik need to understand the architecture before they can assess whether it fits their threat model. A well-written architecture document reduces the number of calls required to reach a decision.

**Best practices:** Use ASCII diagrams or Mermaid (renders in GitHub) rather than image files. Images in documentation repositories are unmaintainable — every architecture change requires exporting a new image. Text-based diagrams are diffable.

**OSS mission:** Architecture documentation is the primary resource for engineers who want to contribute but need to understand the system first. It is also the reference that enterprise security reviews cite.

**Enterprise alignment:** The architecture document is the technical reference for the enterprise security review. A clear threat model section ("what Kite Logik protects against, what it does not protect against") is required for enterprise due diligence.

---

## Phase 7 — Observability Completion

**Goal:** Close the gap between "traces go somewhere" and "traces are useful."

---

### Task 7.1 — Grafana Dashboard JSON

**What:** Create `observability/grafana/provisioning/dashboards/kitelogik.json` — a pre-built Grafana dashboard that auto-provisions at startup.

**Panels:**
1. **Gate Decisions (last 1h)** — bar chart: ALLOW / HITL / BLOCK counts
2. **Trace List** — filterable by session_id, tool_name, risk_tier
3. **Gate Latency** — p50/p95/p99 of `kitelogik.duration_ms` span attribute
4. **HITL Queue Depth** — metric from `/api/health` endpoint
5. **Active Sessions** — count of distinct session_ids in traces last 15min

**What to add to `docker-compose.yml`:**
```yaml
grafana:
  volumes:
    - ./observability/grafana/provisioning:/etc/grafana/provisioning
```

**Why:** The enterprise stack already includes Grafana and Tempo. Without a pre-built dashboard, users who start the enterprise stack see an empty Grafana and have to build panels themselves. That is not "enterprise-ready."

**Best practices:** Dashboard JSON is generated by creating the dashboard in Grafana UI and exporting. Variables (`$session_id`, `$service_name`) make it reusable across deployments without editing JSON. The dashboard is versioned in git alongside the policies.

**OSS mission:** A pre-built dashboard makes the observability story concrete. "Every decision is traced" is more convincing when you can see the trace list in Grafana immediately after running `make demo-enterprise`.

**Enterprise alignment:** This is the first of several Grafana dashboards for the enterprise edition. The pre-built OSS dashboard establishes the provisioning pattern that the enterprise edition extends (compliance dashboard, HITL SLA dashboard, session anomaly dashboard).

---

## Summary: Task Backlog

| # | Task | Phase | Impact | Effort |
|---|---|---|---|---|
| 1.1 | `.gitignore` | Release Gate | Blocker | XS |
| 1.2 | `LICENSE` (Apache 2.0) | Release Gate | Blocker | XS |
| 1.3 | `.dockerignore` | Release Gate | Blocker | XS |
| 1.4 | `asyncpg` → optional dep | Release Gate | Blocker | S |
| 1.5 | `.env.example` | Release Gate | High | XS |
| 2.1 | `README.md` | Foundation | Very High | M |
| 2.2 | GitHub Actions CI | Foundation | Very High | M |
| 2.3 | `CONTRIBUTING.md` | Foundation | High | S |
| 2.4 | `SECURITY.md` | Foundation | High | XS |
| 3.1 | `quickstart.py` | Dev Experience | Very High | S |
| 3.2 | `kitelogik/kitelogik/policies/examples/` | Dev Experience | Very High | M |
| 3.3 | `kitelogik/policy_tester.py` | Dev Experience | High | M |
| 4.1 | Multi-stage Dockerfile | Production | High | S |
| 4.2 | Comprehensive health endpoint | Production | High | M |
| 4.3 | `benchmark.py` | Production | Medium | S |
| 4.4 | Demo script: argparse + summary | Production | High | M |
| 5.1 | Dashboard: session filter | Dashboard | High | S |
| 5.2 | Dashboard: audit log tab | Dashboard | High | L |
| 6.1 | `CHANGELOG.md` | Enterprise Foundation | Medium | S |
| 6.2 | GitHub issue/PR templates | Enterprise Foundation | Medium | XS |
| 6.3 | `docs/architecture.md` | Enterprise Foundation | High | L |
| 7.1 | Grafana dashboard JSON | Observability | High | L |

**Effort guide:** XS = <1h, S = 1–3h, M = 3–6h, L = 6–12h

**Critical path for first public release:** 1.1 → 1.2 → 1.3 → 1.4 → 1.5 → 2.1 → 2.2 → 3.1

Everything on that path can be completed in under a day. After that, the project is publishable and the remaining phases can be delivered iteratively as GitHub releases.
