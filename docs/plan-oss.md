# Kite Logik — Open Source Implementation Plan

This plan defines how to build the open source edition to production-grade quality. It covers implementation sequencing, concrete engineering patterns, testing requirements, security review gates, and the definition of done for each sprint. The goal is a codebase that is reliable, stable, verifiably correct, and architected so that the enterprise edition layers on top without requiring structural changes.

---

## Guiding Principles

These govern every implementation decision in this plan. When in doubt, refer back here.

**1. Security is structural, not configurational.**
Enforcement happens in the infrastructure — OPA, the container runtime, the credential broker — not in prompts, comments, or configuration flags. A policy rule that relies on a developer remembering to set a flag is not a security control.

**2. Fail closed, surface loudly.**
Any error in the enforcement path (OPA unreachable, credential validation failure, schema mismatch) results in a hard deny. Errors are never silently swallowed. They are traced, logged, and surfaced to the observability layer. Silent failures in a governance tool are worse than crashes.

**3. Every trust boundary is tested adversarially.**
The sanitizer, the policy gate, and the credential broker each have adversarial test suites that try to break them. New enforcement features require new adversarial tests, not just happy-path unit tests. The adversarial suite runs in CI on every PR.

**4. The OSS architecture is the enterprise foundation.**
Every interface in the OSS edition — `HITLQueue`, `MemoryStore`, `CredentialBroker`, `PolicyGate` — is designed as a protocol, not a concrete class. The Postgres backends drop in without changing call sites. This is not accidental; it must be maintained deliberately as new features are added.

**5. AI-specific threats are first-class.**
Indirect prompt injection, memory poisoning, and privilege escalation through delegated agents are treated with the same rigour as SQL injection or XSS. Every point where external data enters agent context is a trust boundary that requires explicit sanitization and provenance tracking.

**6. The minimal footprint principle.**
Add no dependency unless it is strictly necessary. Every dependency is an attack surface, a compatibility constraint, and a maintenance burden. Prefer the standard library. When a dependency is needed, pin it and document why.

---

## Sprint 0 — Repository Hygiene

**Objective:** Make the repository safe to publish publicly. Nothing else ships before this sprint is complete. Zero exceptions.

**Dependency chain:** This sprint blocks everything else. It cannot be parallelised with other sprints.

---

### S0.1 — `.gitignore`

**Implementation:**
Use the authoritative gitignore.io template for `Python,macOS,JetBrains` as the base, then add Kite Logik-specific runtime artifacts:

```
# Runtime artifacts (Kite Logik)
hitl.db
memory.db
audit.db
credentials.db
*.db
*.sqlite

# Trace output
traces/
*.otlp

# Screenshot artifacts
*.png
*.jpg
screenshot_*.png
```

The critical entries are `*.db` and `.env`. Verify they work: run `git status` on a branch where `hitl.db` exists and confirm it does not appear as untracked.

**Security check:** Run `git ls-files --others --exclude-standard` on a working copy after adding `.gitignore`. The output must contain zero `.db`, `.env`, or `.venv` files. This check is added to `CONTRIBUTING.md`.

**Definition of done:** `git add .` from a clean working copy with a populated `hitl.db` and `.env` file adds zero database files and zero secret files to the staging area.

---

### S0.2 — `LICENSE` (Apache 2.0)

**Implementation:**
1. Download the canonical Apache 2.0 text from apache.org. Do not modify it.
2. Copyright line: `Copyright 2026 Kite Logik Contributors`
3. Add `SPDX-License-Identifier: Apache-2.0` as the first comment in every `.py` file in the project. This is machine-readable and processed by FOSS compliance tools (FOSSA, Snyk).

```python
# SPDX-License-Identifier: Apache-2.0
```

A `ruff` rule can enforce this: add to `pyproject.toml`:
```toml
[tool.ruff.lint]
select = ["E", "F", "I", "UP", "CPY001"]

[tool.ruff.lint.flake8-copyright]
notice-rgx = "SPDX-License-Identifier: Apache-2.0"
```

**Security check:** No source file in the repository should be distributable without a clear license declaration. The SPDX header on every file makes the license unambiguous even if a file is extracted from the repository.

**Definition of done:** `ruff check .` passes. `find . -name "*.py" | xargs grep -L "SPDX-License-Identifier"` returns no results (excluding `.venv`).

---

### S0.3 — `.dockerignore`

**Implementation:**
The `.dockerignore` must prevent three categories from entering the build context:
1. **Local environment** — `.venv/`, `.idea/`, `.DS_Store`
2. **Runtime state** — `*.db`, `*.log`, `.env`, `traces/`
3. **Development artifacts** — `tests/`, `docs/`, `*.md`, `.github/`, `htmlcov/`

Critical verification: after adding `.dockerignore`, run `docker build --no-cache -t kitelogik-test .` and inspect the image size. Before `.dockerignore`, the image size includes `.venv/` (200–400 MB). After, it should be under 200 MB total.

**Security check:** Run `docker run --rm kitelogik-test find / -name ".env" 2>/dev/null`. The output must be empty — no `.env` file in any layer.

**Definition of done:** `docker build` produces an image under 200 MB. `docker inspect kitelogik-test` shows no `.venv/` or `.env` in any layer. `docker run kitelogik-test ls /app` shows only source packages.

---

### S0.4 — `asyncpg` as Optional Dependency

**Implementation:**
In `pyproject.toml`, move `asyncpg` from `[project.dependencies]` to `[project.optional-dependencies]`:

```toml
[project.optional-dependencies]
postgres = ["asyncpg>=0.29.0"]
enterprise = ["asyncpg>=0.29.0"]
dev = [
    "pytest>=8.0.0",
    "pytest-asyncio>=0.23.0",
    "pytest-mock>=3.14.0",
    "respx>=0.21.0",
    "ruff>=0.6.0",
    "livereload>=2.7.0",
]
```

Guard every `asyncpg` import with a clear error message:

```python
# anchor/postgres_queue.py
try:
    import asyncpg
except ImportError as e:
    raise ImportError(
        "PostgreSQL backends require asyncpg. "
        "Install with: pip install 'kitelogik[postgres]'"
    ) from e
```

This pattern must be applied to every file in `anchor/postgres_*.py`, `memory/postgres_store.py`, and `audit/postgres_store.py`.

**Verification:** Create a fresh virtualenv, run `pip install -e .` (no extras), then `python -c "from kitelogik.anchor.queue import HITLQueue"`. This must succeed. Then run `python -c "from kitelogik.anchor.postgres_queue import PostgresHITLQueue"`. This must raise `ImportError` with the helpful message. Then run `pip install -e ".[postgres]"` and re-run the import — it must succeed.

**Definition of done:** `pip install -e .` on a machine without `libpq` installed succeeds. The import guard test passes. `tests/test_hitl_queue.py` (SQLite) passes without `asyncpg` installed. `tests/test_postgres_backends.py` is skipped (not failed) without `asyncpg`.

---

### S0.5 — `.env.example`

**Implementation:**
Write `.env.example` as the canonical reference for all configuration. Every variable must have a comment. Group by: required, optional OSS, optional enterprise.

Structure:
```bash
# ── Required ──────────────────────────────────────────────────────────────────
# Your Anthropic API key. Get one at https://console.anthropic.com
ANTHROPIC_API_KEY=your_api_key_here

# ── Optional — defaults shown ─────────────────────────────────────────────────
OPA_BASE_URL=http://localhost:8181
HITL_DB_PATH=hitl.db
MEMORY_DB_PATH=memory.db
AUDIT_DB_PATH=audit.db
DASHBOARD_PORT=8050
HITL_TIMEOUT_SECONDS=300

# ── Optional — observability ─────────────────────────────────────────────────
# Send traces to an OTLP collector (e.g. Grafana Tempo, Jaeger, Honeycomb).
# Leave unset to write traces to a local file instead.
# OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318

# ── Optional — enterprise only ────────────────────────────────────────────────
# DATABASE_URL=postgresql://user:pass@localhost/kitelogik
# SIEM_WEBHOOK_URL=https://splunk.internal:8088/services/collector
# SIEM_API_KEY=Splunk your_hec_token_here
# GRAFANA_ADMIN_USER=admin
# GRAFANA_ADMIN_PASSWORD=change_me_in_production
```

**Security check:** Add `.env.example` to the explicit allow list in `.gitignore` (`!.env.example`). Verify: rename `.env.example` to `.env`, run `git status` — it must show as untracked. Rename back — it must show as tracked.

**Definition of done:** New contributor can run `cp .env.example .env`, fill in `ANTHROPIC_API_KEY`, and `make demo` runs successfully with zero other configuration.

---

## Sprint 1 — CI and Container Foundation

**Objective:** Establish the automated quality gate that governs all future contributions. After this sprint, no code merges without passing lint, tests, and OPA policy tests.

---

### S1.1 — GitHub Actions CI

**Implementation:**
Three independent jobs, each failing fast, running in parallel:

**Job: `lint`**
```yaml
runs-on: ubuntu-latest
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5
    with: {python-version: "3.11"}
  - run: pip install -e ".[dev]"
  - run: ruff check .
  - run: ruff format --check .
```

**Job: `test`**
```yaml
strategy:
  matrix:
    python-version: ["3.11", "3.12"]
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5
    with: {python-version: "${{ matrix.python-version }}"}
  - run: pip install -e ".[dev]"
  - run: pytest -q -m "not integration" --tb=short
  - uses: actions/upload-artifact@v4
    if: failure()
    with:
      name: test-results-${{ matrix.python-version }}
      path: .pytest_cache/
```

**Job: `opa-policy-tests`**
```yaml
steps:
  - uses: actions/checkout@v4
  - uses: open-policy-agent/setup-opa@v2
    with: {version: latest}
  - run: opa test kitelogik/policies/ -v
  - run: opa fmt --diff kitelogik/policies/      # fails if policies are not formatted
```

The OPA format check (`opa fmt --diff`) prevents policy files from diverging in style, which makes diffs harder to review.

**Security note for CI:** The CI workflow must never expose secrets to forks. Use `pull_request` trigger (not `pull_request_target`) for untrusted code. `ANTHROPIC_API_KEY` is never needed in CI — tests mock the Anthropic client.

**Definition of done:** Status badge appears in `README.md`. PRs from forks cannot merge without CI passing. OPA format violations fail the pipeline.

---

### S1.2 — Multi-Stage Dockerfile

**Implementation:**
```dockerfile
# SPDX-License-Identifier: Apache-2.0

# Stage 1: install dependencies
FROM python:3.11.9-slim AS builder
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir --user -e . --no-warn-script-location

# Stage 2: runtime image
FROM python:3.11.9-slim AS runtime
WORKDIR /app

# Copy installed packages from builder (not the C toolchain)
COPY --from=builder /root/.local /root/.local

# Copy only application source — .dockerignore excludes everything else
COPY . .

# Run as non-root
RUN adduser --disabled-password --gecos '' kitelogik
USER kitelogik

ENV PATH=/root/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8050
EXPOSE 8200

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8050/api/health')" || exit 1
```

**Security practices applied:**
- Pinned base image (`3.11.9-slim`) — not `latest`. Dependabot keeps this updated without manual tracking.
- Non-root user — any container escape lands as an unprivileged user on the host
- `PYTHONDONTWRITEBYTECODE=1` — prevents `.pyc` files accumulating in the container filesystem
- `PYTHONUNBUFFERED=1` — ensures logs are written immediately; no buffered output during failures
- Builder stage has `pip` and C toolchain; runtime stage has neither

**Definition of done:** `docker build -t kitelogik .` produces an image under 200 MB. `docker run kitelogik whoami` returns `kitelogik` (not `root`). `docker scout cves kitelogik` shows no critical CVEs in the runtime layer.

---

### S1.3 — `README.md`

**Implementation pattern:** The README serves one purpose — convert a visitor into either a contributor or a user within 3 minutes. Structure:

1. **Tagline** — one sentence, above the fold
2. **The problem** — 3 bullet points: why prompts fail as security boundaries. No paragraphs.
3. **Architecture diagram** — ASCII, 20 lines maximum
4. **Quickstart** — `pip install` + `docker run opa` + `python quickstart.py`. Must work copy-paste on macOS and Ubuntu. Tested on a clean machine before every release.
5. **Core concept** — one Rego snippet with inline comments. Shows the value immediately.
6. **What's included** — 3-column table: feature / OSS / Enterprise
7. **Badges** — CI status, test count, license, Python version

**AI-specific framing:** The README must communicate the fundamental insight — prompt-based governance is not governance. The architecture diagram must show the interception point (tool execution layer, not LLM I/O layer) explicitly. This is the differentiation that makes the product credible to platform engineers who have evaluated prompt-based alternatives.

**Definition of done:** A person who has never seen the project can clone it, run `make demo`, and see governed agent decisions within 10 minutes, following only the README. This is tested manually before the first public release.

---

## Sprint 2 — Developer Experience

**Objective:** Make the core value proposition — Policy-as-Code governance — accessible within 30 minutes to an engineer who has never used OPA.

---

### S2.1 — `quickstart.py`

**Implementation principles:**
- Single file, zero imports outside `kitelogik` package
- Runs with OPA started via one Docker command (documented in a comment at the top)
- Shows two outcomes: one ALLOW, one hard BLOCK — the contrast is the point
- Every decision prints: tool name, outcome, risk tier, reason, latency
- Session token is explicitly revoked at the end — demonstrates the lifecycle

**Pattern for the quickstart:**
```python
# SPDX-License-Identifier: Apache-2.0
"""
Kite Logik Quickstart — see governance in action in under 5 minutes.

Requires OPA running locally:
    docker run -p 8181:8181 -v $(pwd)/policies:/policies \
        openpolicyagent/opa:latest run --server --addr :8181 --watch /policies
"""
import asyncio
import os
from kitelogik import (
    OPAClient, PolicyGate, HITLQueue, CredentialBroker,
    AgentSession, SessionContext,
)
# ... 40 lines total
```

**AI best practice applied:** The quickstart must include a commented explanation of WHY scopes are explicit, WHY the token is revoked, and WHY the gate exists as infrastructure rather than as a prompt instruction. These comments turn a code example into conceptual documentation.

**Definition of done:** `python quickstart.py` runs from a clean virtualenv with only `pip install -e .` and OPA on `localhost:8181`. Output shows two decisions with outcomes, risk tiers, and latency. Total runtime under 10 seconds.

---

### S2.2 — `kitelogik/kitelogik/policies/examples/`

**Implementation:**
Three files, each independently runnable and self-documenting.

**File 1: `example_read_only_agent.rego`**

Core pattern: explicit action allowlist, deny everything else.

```rego
# SPDX-License-Identifier: Apache-2.0
#
# example_read_only_agent.rego
# ─────────────────────────────
# PURPOSE:  Restrict an agent to read-only operations.
# USE CASE: Data analysis agents, audit query agents, reporting bots.
# ADAPT:    Add to read_actions to expand what this agent can read.
#           Combine with financial.rego to add scoped write permissions.
#
# Expected OPA input shape:
#   {"action": "...", "args": {}, "context": {"user_role": "...", ...}}
```

Every example must include:
1. Header block: purpose, use case, how to adapt, expected input shape
2. Inline comments on every non-obvious rule
3. Embedded test cases (`test_*` rules) that run with `opa test`
4. A "common mistakes" section at the bottom

**AI best practice applied:** Policy files that agents operate under must be readable by non-Rego engineers. Comments should explain the business logic, not the Rego syntax. "This blocks refunds over $100 for support agents" is more useful than "this evaluates `input.args.amount <= 100`."

**OPA formatting:** All policy examples must pass `opa fmt --diff` with zero changes. Formatted policies are easier to diff during code review.

**Definition of done:** `opa test kitelogik/kitelogik/policies/examples/ -v` passes all embedded tests. `opa fmt --diff kitelogik/kitelogik/policies/examples/` exits 0. A developer with no Rego background can read any example and describe what it does in plain English within 2 minutes.

---

### S2.3 — `kitelogik/policy_tester.py`

**Implementation:**

```
python -m kitelogik.policy_tester \
  --policy policies/financial.rego \
  --input '{"action": "approve_refund", "args": {"amount": 50}, ...}'
```

Uses the existing `OPAClient` — no new OPA integration. The flow:
1. Load the policy file from the path argument
2. POST the input to `OPAClient.evaluate()`
3. Pretty-print the `PolicyDecision` with colour coding (green=allow, red=deny, amber=hitl)
4. Print OPA response time in ms

Exit codes:
- `0` — allow
- `1` — deny or requires_hitl
- `2` — input validation error or OPA unreachable

**Why exit codes matter:** The CLI is scriptable in CI. A policy change CI check can run `policy_tester --policy policies/financial.rego --input fixtures/test_input.json` and fail the build if the decision changes unexpectedly.

**Security note:** The CLI must not log the full `args` content in verbose mode — tool arguments may contain PII (customer IDs, amounts). Verbose mode logs field names only, not values.

**Definition of done:** `python -m kitelogik.policy_tester --help` prints usage. Exit code test: `policy_tester` with an allow input exits 0; with a deny input exits 1. Output is human-readable with colour. No PII in verbose output.

---

## Sprint 3 — Production Hardening

**Objective:** Make every component independently verifiable and reliably deployable. After this sprint, an ops engineer can determine system health, validate latency claims, and demonstrate governance in a polished way.

---

### S3.1 — Comprehensive Health Endpoint

**Implementation:**

The health endpoint at `GET /api/health` must actively probe all dependent services and return structured JSON. It must never return `200 OK` when enforcement is broken.

```python
@app.get("/api/health")
async def health():
    checks = {}

    # OPA probe — 500ms timeout
    try:
        async with asyncio.timeout(0.5):
            opa_ok = await opa_client.health()
        checks["opa"] = {"status": "ok" if opa_ok else "unreachable"}
    except asyncio.TimeoutError:
        checks["opa"] = {"status": "timeout"}

    # HITL queue probe
    try:
        pending = await hitl_queue.get_pending()
        checks["hitl_queue"] = {"status": "ok", "pending_count": len(pending)}
    except Exception as e:
        checks["hitl_queue"] = {"status": "error", "detail": type(e).__name__}

    # Memory store probe
    try:
        await memory_store.list_keys()
        checks["memory_store"] = {"status": "ok"}
    except Exception as e:
        checks["memory_store"] = {"status": "error", "detail": type(e).__name__}

    overall = "ok" if all(
        c["status"] == "ok" for c in checks.values()
    ) else "degraded"

    status_code = 200 if overall == "ok" else 503
    return JSONResponse(status_code=status_code, content={
        "status": overall,
        "version": __version__,
        "policy_version": _compute_policy_version(),
        "checks": checks,
    })
```

**Kubernetes probes:**
- `GET /api/health/live` — always `200` if the process is running (liveness)
- `GET /api/health/ready` — `200` only when all checks pass (readiness)

The distinction matters: a liveness failure causes a pod restart; a readiness failure removes the pod from the load balancer. OPA being slow should trigger readiness failure, not a restart.

**Security note:** The health endpoint must never expose internal error messages verbatim. `"detail": "Connection refused"` reveals network topology. Use exception type names only (`"detail": "ConnectionRefusedError"`).

**Definition of done:** `curl -sf localhost:8050/api/health | jq .status` returns `"ok"` with all services running, `"degraded"` with OPA stopped. The endpoint returns HTTP 503 when degraded. Response time under 100ms in the normal case.

---

### S3.2 — `benchmark.py`

**Implementation:**

The benchmark is a standalone script that requires only OPA running. It uses the existing `PolicyGate` and `OPAClient` directly.

**Measurement methodology:**
1. 100 warm-up calls (discarded) — allows OPA's JIT compilation to settle
2. 1,000 measured calls per scenario
3. Wall clock time per call: `time.perf_counter()` around the full `evaluate_tool_call()` call
4. `statistics.quantiles(data, n=100)` for percentiles — no third-party benchmark library

**Three scenarios:**
1. **Simple allow** — `read_customer_record`, `read_customer` scope, `support_agent` role
2. **HITL trigger** — `approve_refund`, amount=500, `approve_refund_under_1000` scope, `manager` role
3. **Hard deny** — `read_file`, path=`/etc/passwd`

**Output format:**
```
Kite Logik Gate Latency — 2026-03-25T14:00:00
OPA: http://localhost:8181  Python: 3.11.9  Iterations: 1,000

Scenario                  p50    p95    p99    max
─────────────────────────────────────────────────
Simple allow              4ms    7ms   11ms   23ms
HITL trigger              5ms    9ms   14ms   28ms
Hard deny (security)      4ms    7ms   10ms   19ms
```

**Parameterisation:**
```
python benchmark.py --iterations 1000 --opa-url http://localhost:8181 --output json
```

`--output json` produces machine-readable output for CI performance regression checks.

**Definition of done:** `python benchmark.py` runs to completion against a local OPA instance. Results are reproducible within 20% across runs. The p99 of the "simple allow" scenario is under 20ms on a MacBook M-series (the development environment). The script can be run as part of a release checklist.

---

### S3.3 — Demo Script Polish

**Implementation:**

```python
# agents/demo.py — top of file
import argparse

def parse_args():
    p = argparse.ArgumentParser(description="Kite Logik demo — 13 governance scenarios")
    p.add_argument("--speed", choices=["fast", "demo"], default="demo",
                   help="fast=5s HITL timeout; demo=30s (default)")
    p.add_argument("--no-dashboard", action="store_true",
                   help="Run terminal-only; skip dashboard push_event() calls")
    p.add_argument("--otlp", metavar="URL",
                   help="OTLP endpoint for traces (e.g. http://localhost:4318)")
    return p.parse_args()
```

**Summary table implementation:**
```python
@dataclass
class ScenarioResult:
    name: str
    outcome: str   # ALLOW / BLOCK / HITL
    latency_ms: float

results: list[ScenarioResult] = []
```

After each scenario, append to `results`. After all 13 run:

```python
def print_summary(results):
    print("\n" + "=" * 60)
    print("  Demo Summary")
    print("  " + "-" * 56)
    print(f"  {'#':<4} {'Scenario':<36} {'Outcome':<10} {'Latency':>7}")
    print("  " + "-" * 56)
    for i, r in enumerate(results, 1):
        colour = GREEN if r.outcome == "ALLOW" else RED if r.outcome == "BLOCK" else AMBER
        print(f"  {i:<4} {r.name:<36} {colour}{r.outcome:<10}{RESET} {r.latency_ms:>6.0f}ms")
    print("  " + "=" * 56)
    counts = Counter(r.outcome for r in results)
    print(f"  ALLOW: {counts['ALLOW']}  BLOCK: {counts['BLOCK']}  HITL: {counts['HITL']}")
    print(f"  Total: {sum(r.latency_ms for r in results):.0f}ms")
    print("=" * 60)
```

Colour codes are only applied when `sys.stdout.isatty()` — CI output is uncoloured.

**AI best practice:** The summary table makes the enforcement story legible in a single view. Presenters should be able to screenshot the summary and use it in a slide deck. Keep the format fixed-width so it renders correctly in terminals and Markdown code blocks.

**Definition of done:** `python agents/demo.py --speed fast --no-dashboard` runs all 13 scenarios and prints a summary table in under 60 seconds (fast mode uses 5s HITL timeout). `--otlp` flag routes traces to the specified endpoint. Exit code `0` on success, `1` if any scenario fails unexpectedly.

---

## Sprint 4 — Dashboard Completion

**Objective:** Make the dashboard a complete operational UI. After this sprint, an ops engineer can monitor active sessions, review and decide HITL actions, and inspect the audit trail without leaving the browser.

---

### S4.1 — Session Filter on Live Feed

**Implementation:**

All state in the existing JS. No new API endpoints required.

```javascript
// Maintain the set of sessions seen in the live feed
const sessionsSeen = new Set();
const sessionSelect = document.getElementById('session-filter');

// On each incoming gate_decision event:
function handleGateDecision(event) {
    const sessionId = event.session_id;
    if (!sessionsSeen.has(sessionId)) {
        sessionsSeen.add(sessionId);
        const option = document.createElement('option');
        option.value = sessionId;
        option.textContent = sessionId;
        sessionSelect.appendChild(option);
    }
    renderFeedCard(event); // existing function
}

// Filter on select change:
sessionSelect.addEventListener('change', () => {
    const selected = sessionSelect.value;
    document.querySelectorAll('.feed-card').forEach(card => {
        card.style.display = (selected === 'all' ||
            card.dataset.sessionId === selected) ? '' : 'none';
    });
});
```

The `data-session-id` attribute must be added to every feed card at render time. This is a two-line change to the existing `renderFeedCard()` function.

**No DOM `innerHTML`** — per the project's existing pattern, all DOM manipulation uses `createElement` and `appendChild`. `data-session-id` is set via `element.dataset.sessionId = value`.

**Definition of done:** With two concurrent demo sessions running, the dropdown shows both session IDs. Selecting one hides all events from the other. Selecting "All sessions" shows everything. New sessions appearing after the dropdown was rendered appear in the dropdown without a page reload.

---

### S4.2 — `GET /api/audit` Endpoint

**Implementation:**

Add to `dashboard/server.py`:

```python
@app.get("/api/audit")
async def get_audit(
    session_id: str | None = Query(default=None),
    outcome: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    if audit_store is None:
        return JSONResponse(
            status_code=503,
            content={"error": "Audit store not configured. "
                              "Pass an AuditStore to init_app() to enable this endpoint."}
        )
    records = await audit_store.query(
        session_id=session_id, outcome=outcome, limit=limit
    )
    return {
        "record_count": len(records),
        "offset": offset,
        "records": [
            {
                "id": r.id,
                "timestamp": r.timestamp,
                "session_id": r.session_id,
                "tool_name": r.tool_name,
                "outcome": r.outcome,
                "risk_tier": r.policy_decision.get("risk_tier"),
                "rule_matched": r.policy_decision.get("rule_matched"),
                "policy_version": r.policy_version,
                "hitl_action_id": r.hitl_action_id,
            }
            for r in records
        ],
    }
```

`AuditStore` is injected as an optional argument in `init_app()`. If not provided, the endpoint returns a clear 503 — not an empty table that looks like there are no audit records.

**Security note:** The audit endpoint must never expose `args_json` (tool arguments) or `context_json` in the paginated list view — these may contain PII. The detail view (`GET /api/audit/{id}`) can expose them to authenticated users (enterprise) but the list view must be safe for any authenticated operator.

**Definition of done:** `GET /api/audit` returns a valid JSON response with `record_count`. `GET /api/audit?outcome=denied` filters correctly. Without `AuditStore` configured, returns `503` with a helpful message. `test_dashboard.py` covers all three cases.

---

### S4.3 — Audit Log Tab in Dashboard

**Implementation:**

Four-tab layout already exists (live feed, HITL, memory, fleet). A fifth tab "Audit" is added with the same structure:

```html
<div class="tab-content" id="tab-audit">
  <div class="filter-row">
    <select id="audit-outcome-filter">
      <option value="">All outcomes</option>
      <option value="allowed">Allowed</option>
      <option value="denied">Denied</option>
      <option value="pending_review">HITL</option>
    </select>
    <select id="audit-session-filter">
      <option value="">All sessions</option>
    </select>
    <a id="audit-export-btn" href="/api/audit?format=csv" download>Export CSV</a>
  </div>
  <table id="audit-table">
    <thead>
      <tr>
        <th>Time</th><th>Session</th><th>Tool</th>
        <th>Outcome</th><th>Risk Tier</th><th>Rule</th>
      </tr>
    </thead>
    <tbody id="audit-tbody"></tbody>
  </table>
</div>
```

Polling: tab opens → immediate fetch → poll every 15 seconds while tab is visible (`document.visibilityState`). Stop polling when tab is not visible.

CSV export: `GET /api/audit?format=csv&outcome=&session_id=` returns `Content-Type: text/csv` with `Content-Disposition: attachment; filename="kitelogik-audit-{date}.csv"`. Server-side generation — no client-side CSV construction.

**Definition of done:** Audit tab shows records that match filter selections. Polling every 15s adds new records without full page reload. CSV download contains the same records as the current view. Tab is accessible via keyboard navigation (existing pattern).

---

## Sprint 5 — Documentation and Community

**Objective:** Establish the contribution infrastructure that transforms a published repository into a community project. After this sprint, a first-time contributor has everything they need to set up, contribute, and get their PR reviewed.

---

### S5.1 — `CONTRIBUTING.md`

**Critical section: Adding a Policy Rule**

This is the highest-value contribution type. Document the exact flow:

```
1. Edit or create a .rego file in policies/
2. Write OPA tests in policies/*_test.rego:
       test_your_rule_name if {
           your_policy.allow with input as { ... }
       }
3. Run: opa test kitelogik/policies/ -v
4. Add a Python integration test in tests/test_gate.py or tests/test_delegation.py
5. Run: pytest tests/test_gate.py -v
6. If the policy adds a new risk tier classification, update tests/test_phase3.py
7. Submit PR — CI runs all three test suites
```

Include a worked example: adding a `healthcare.rego` policy with a `test_allow_view_patient_record` test. Show the full diff across all four files that need to change.

**Code style section:** Document the ruff rules in use and give one concrete example of each linting category. Engineers shouldn't have to discover the rules by getting CI failures.

**Definition of done:** A developer with no prior Kite Logik experience can follow `CONTRIBUTING.md` to add a policy test, get CI green, and understand the PR review process. This is tested by having someone outside the core team do exactly that before publishing.

---

### S5.2 — `SECURITY.md`

**Implementation:**

```markdown
# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x     | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use GitHub's private security advisory feature:
https://github.com/your-org/kitelogik/security/advisories/new

Include:
- Description of the vulnerability
- Steps to reproduce
- Which component is affected (Tether/Anchor/Sandbox/Memory)
- Potential impact
- Any suggested fix

## Response Timeline

- Acknowledgement: within 72 hours
- Status update: within 7 days
- Critical fix: within 30 days
- CVE assignment: for confirmed vulnerabilities with CVSS >= 7.0

## Scope

In scope: the policy gate, HITL queue, sanitizer, credential broker, memory store.
Out of scope: the demo scripts, documentation, example policies.

## Credit

Reporters of valid vulnerabilities are credited in the CHANGELOG under the
Security category and in the CVE acknowledgements field.
```

**Definition of done:** `SECURITY.md` is linked from `README.md`. GitHub's "Security" tab shows the private advisory link. The response timeline commitment is reviewed by the team before publishing.

---

### S5.3 — `docs/architecture.md`

**Key sections:**

**Threat model section** (the most important for enterprise adoption):

```
Attack class: Indirect Prompt Injection
Vector: Malicious content in tool response → agent context → instruction override
Defence: sanitize_tool_output() called on every MCP response before it enters context

Attack class: Memory Poisoning (MINJA)
Vector: Attacker-controlled data written to memory store → poisons future reads
Defence: External-source writes pass through sanitizer + trust_tier=EXTERNAL flag

Attack class: Credential Escalation
Vector: Agent requests child token with scopes exceeding parent
Defence: delegate() enforces strict subset; OPA checks delegation_depth

Attack class: Policy Engine Unavailability
Vector: OPA taken offline → agent bypasses governance
Defence: Fail-closed: OPAConnectionError → deny, risk_tier=SECURITY_CRITICAL
```

**Sequence diagram** for a single governed tool call — this is the most common question from engineers evaluating the platform. Every step must be labelled with which component handles it.

**Definition of done:** `docs/architecture.md` is complete. The threat model section covers all four primary attack classes with their defences. The sequence diagram shows the full call flow. A security engineer can read this document and produce a threat model assessment without additional Q&A.

---

## Testing Strategy

### Pyramid

```
          ┌──────────────────┐
          │  Integration     │  11 tests — full stack, real OPA + Docker
          │  (slow, real)    │  Run manually: make demo && pytest -m integration
          ├──────────────────┤
          │  Adversarial     │  53 tests — real OPA, injection corpus
          │  (medium speed)  │  Run: docker compose up opa && pytest adversarial/
          ├──────────────────┤
          │  Unit            │  286 tests — mocked deps, fast
          │  (fast, mocked)  │  Run: pytest -m "not integration"
          └──────────────────┘
```

### Rules for New Tests

1. Every new enforcement rule in OPA has both an OPA native test and a Python integration test
2. Every new sanitization pattern has both a positive test (pattern is caught) and a negative test (benign content is not affected)
3. Every new API endpoint has tests for: success case, auth failure, input validation failure, downstream dependency failure
4. No test mocks the OPA client in adversarial tests — adversarial tests run against real OPA
5. Tests that require Docker are marked `@pytest.mark.integration` and skipped in the fast CI job

### Coverage Gate

Add to `pyproject.toml`:
```toml
[tool.pytest.ini_options]
addopts = "--cov=. --cov-fail-under=80 --cov-report=term-missing"
```

80% line coverage minimum. The coverage gate does not count test files or the demo script. It does count the policy gate, sanitizer, credential broker, memory store, and HITL queue — the enforcement components must have near-100% coverage.

---

## Security Review Gates

These checkpoints happen before each sprint's work merges. They are not optional.

| Gate | Sprint | Check |
|---|---|---|
| Secret scan | S0 | `git log --all --full-history -- "*.env"` returns no results |
| Dependency audit | S1 | `pip-audit` shows no known vulnerabilities in required deps |
| Container scan | S1 | `docker scout cves` shows no critical CVEs in runtime layer |
| Input validation | S2 | `policy_tester` accepts no unsanitized shell input in any code path |
| Auth bypass | S4 | Health endpoint is the only unauthenticated endpoint |
| Injection corpus | S2 | All 12 injection payloads caught; all 7 benign cases pass through |
| OPA policy review | Each sprint | Every new Rego rule reviewed against the denial-by-default pattern |

---

## Definition of Done — Sprint Level

A sprint is done when all of the following are true:

- All items in the sprint have their item-level definition of done satisfied
- CI is green on `main` after merging
- `make test` passes locally on macOS and Linux
- `make demo` runs all 13 scenarios successfully with a summary table
- No new `ruff` violations introduced
- `opa test kitelogik/policies/ -v` passes all tests including new ones
- `CHANGELOG.md` updated with the sprint's changes under `[Unreleased]`
- Any new public API is documented in the relevant `docs/` file

---

## Architecture Decisions Preserved for Enterprise Compatibility

These decisions in the OSS codebase directly enable the enterprise edition to layer on top without structural refactoring:

| Decision | OSS Implementation | Enterprise Extension |
|---|---|---|
| All persistence behind interfaces | `HITLQueue`, `MemoryStore`, `CredentialBroker` are abstract protocols | Postgres implementations drop in without call-site changes |
| `init_app()` accepts injected dependencies | `AuditStore` is optional in dashboard's `init_app()` | Enterprise passes `PostgresAuditStore`; OSS passes `None` |
| OPA client is injectable | `PolicyGate(opa_client=...)` | Enterprise can point at a clustered OPA without changing gate code |
| `asyncio.to_thread` for all I/O | SQLite operations never block the event loop | Postgres operations are already async-native; no refactor needed |
| Session context is a Pydantic model | `SessionContext` is fully serialisable | Gateway mode serialises context over HTTP; same model both sides |
| `sanitize_tool_output()` is a pure function | No side effects; composable | Enterprise wraps it with additional sanitization layers |
