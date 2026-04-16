# Kite Logik — Onboarding Roadmap

A structured path from first contact to production deployment.
Each stage builds on the last. Skip nothing in Stage 1–3 — they establish the mental model that makes everything else obvious.

---

## Overview

```
Stage 1  First contact          10 min    No API key required
Stage 2  Full demo              30 min    Requires ANTHROPIC_API_KEY
Stage 3  Understand policies    1–2 hr    OPA + Rego fundamentals
Stage 4  Integrate your agent   2–4 hr    Add governance to existing code
Stage 5  Write custom policies  2–4 hr    Domain-specific Rego rules
Stage 6  Production deployment  1 day     Docker Compose, OPA bundle, HITL ops
Stage 7  Observability          half day  OTel traces, OTLP export
Stage 8  Scale up               varies    Enterprise features
```

---

## Stage 1 — First Contact

**Goal:** See enforcement in action without setting anything up.
**Time:** ~10 minutes.
**Requires:** Python 3.11+. No Docker or OPA server needed.

### Option A — New project (recommended for first-time users)

```bash
pip install kitelogik
kitelogik init my-first-agent
cd my-first-agent
docker compose up -d              # start OPA policy engine
python agent.py
```

`kitelogik init` scaffolds a complete project:
- `policies/policy.yaml` — YAML governance rules (human-readable)
- `policies/policy.rego` — compiled Rego policy (auto-generated)
- `agent.py` — governed agent with demo tool calls
- `docker-compose.yml` — OPA policy engine config

OPA must be running before the agent. The generated `docker-compose.yml` starts OPA on `http://localhost:8181` and mounts the project's `policies/` directory. Edit `policies/policy.yaml`, recompile with `kitelogik compile policies/policy.yaml`, and re-run to experiment.

### Option A2 — Existing project with tool functions

If you already have an agent with tool functions, install kitelogik and add governance to your project:

```bash
pip install kitelogik
```

**Step 1 — Write a policy.** Create `policy.yaml` with rules for your tools:

```yaml
version: 1
package: kitelogik.main

rules:
  - name: allow_reads
    when:
      action:
        - get_customer
        - list_transactions
      scope: read_customer
    then: allow

  - name: block_dangerous
    when:
      action: run_shell_command
    then: deny
    reason: "Shell access is prohibited"
```

**Step 2 — Compile and start OPA.**

```bash
kitelogik compile policy.yaml                # generates policies/policy.rego
```

Create a `docker-compose.yml`:

```yaml
services:
  opa:
    image: openpolicyagent/opa:latest
    command: run --server --addr :8181 --watch /policies
    ports:
      - "8181:8181"
    volumes:
      - ./policies:/policies:ro
```

```bash
docker compose up -d
```

**Step 3 — Wrap your tools with governance.** See Stage 4 for the three integration patterns (`@governed` decorator, `GovernedToolbox`, or framework adapters).

### Option B — Clone the repo

```bash
git clone https://github.com/kitelogik/kitelogik
cd kitelogik
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

#### Step 1.1 — Quickstart (4 scenarios)

```bash
python quickstart.py
```

This runs four policy evaluations without an LLM or API key. You will see:
- An **ALLOW** — read operation, permitted by scope
- A **HITL** escalation — high-value refund, requires human approval
- A **BLOCK** — path traversal attempt, hard-blocked by security policy
- A **BLOCK** — code execution attempted without a sandbox

**What to notice:** The decisions are printed with latency. Gate evaluation is typically 2–8ms. The model is not involved; OPA is the decision-maker.

#### Step 1.2 — Exploration (8 scenarios)

```bash
python explore.py
```

Covers delegation, scope escalation prevention, injection detection, and role-based thresholds. Run this before reading any documentation — it gives you the vocabulary.

**What you should understand after Stage 1:**
- Policy decisions happen at tool execution, not at prompt I/O
- Every decision is ALLOW / HITL / BLOCK — no silent degradation
- Decisions are fast enough to be in the critical path of every tool call

---

## Stage 2 — Full Demo

**Goal:** See a real LLM hitting the policy gate, observe HITL escalation, and review gate decisions.
**Time:** ~30 minutes.
**Requires:** `ANTHROPIC_API_KEY`.

```bash
cp .env.example .env
# Edit .env — add your ANTHROPIC_API_KEY
make demo
```

This starts OPA and runs 13 scenarios using a real Claude model.

### What to do during the demo

1. Watch the terminal output — gate decisions (ALLOW / HITL / BLOCK) appear as each scenario runs
2. Scenario 6 (high-value refund) triggers HITL escalation — the agent pauses until the action is resolved
3. After the demo finishes, review the summary table showing per-scenario outcomes and latency

> **Enterprise Edition:** The real-time dashboard (`http://localhost:8050`) with live event feed, HITL approve/deny UI, audit log viewer, and CSV export is available in [Kite Logik Enterprise](https://github.com/kitelogik/kitelogik-enterprise).

### What you should understand after Stage 2

- The HITL flow: agent suspends, human decides, agent resumes or stops
- Blocked actions return a structured reason to the model (not a crash)
- The demo summary table shows per-scenario latency — governance overhead is <10ms

---

## Stage 3 — Understand the Policy Layer

**Goal:** Read and understand the existing Rego policies. Understand why decisions happen.
**Time:** 1–2 hours.
**Requires:** OPA CLI (`brew install opa` or `apt install opa`).

### Step 3.1 — Read the policies

Start with these in order:

```
kitelogik/policies/main.rego          Aggregates all sub-policies; final decision logic
kitelogik/policies/security.rego      Hard-deny rules (file paths, path traversal, shell execution)
kitelogik/policies/financial.rego     Role + scope + amount thresholds
kitelogik/policies/delegation.rego    Depth cap, per-depth financial limits
```

**Key pattern to internalize:**

```rego
# Every file opens with this. No exceptions.
default allow := false

# allow rules are additive — all conditions must hold.
allow if {
    input.action == "approve_refund"
    "approve_refund_under_100" in input.context.session_scopes
    input.context.user_role == "support_agent"
    is_number(input.args.amount)
    input.args.amount >= 0
    input.args.amount <= 100
}
```

If you changed `allow if` to `deny if` you would get the opposite. But you never need to — the default deny handles the negative case.

### Step 3.2 — Run the OPA test suite

```bash
opa test kitelogik/policies/ -v
```

You will see 36 tests pass. Each test is a named scenario: `test_tier1_allow_support_agent`, `test_path_traversal_blocked`, etc. Read through them — they are the specification for what the policy does.

### Step 3.3 — Test a policy decision interactively

```bash
# Start a Rego REPL with the policies loaded
opa run --repl kitelogik/policies/

# In the REPL, evaluate a decision:
> data.kitelogik.allow with input as {"action": "approve_refund", "args": {"amount": 50}, "context": {"user_role": "support_agent", "session_scopes": ["approve_refund_under_100"]}}
```

### Step 3.4 — Read the annotated examples

```
kitelogik/policies/examples/example_financial_thresholds.rego
kitelogik/policies/examples/example_role_based_access.rego
kitelogik/policies/examples/example_tool_allowlist.rego
```

Each is heavily annotated and includes common mistakes. Read the "Common mistakes" section of `example_financial_thresholds.rego` — these are the real footguns.

**What you should understand after Stage 3:**

- Why `is_number(amount)` matters (prevents `null` and `"50"` from matching a numeric comparison)
- The difference between `deny` and "no allow rule matched" (both result in a block, but hard-deny rules in `security.rego` cannot be overridden by scopes)
- Why every policy must start with `default allow := false`
- What `rule_matched` in a `PolicyDecision` tells you

---

## Stage 4 — Integrate Your Agent

**Goal:** Add governance to your existing AI agent code.
**Time:** 2–4 hours depending on your agent's architecture.

There are three integration patterns. Choose the one that fits your stack.

### Pattern A — `@governed` decorator (fastest)

Best for: existing tool functions you want to gate individually.

```python
from kitelogik import governed, PolicyGate, OPAClient, SessionContext

opa = OPAClient("http://localhost:8181")
gate = PolicyGate(opa_client=opa)

ctx = SessionContext(
    session_id="session_001",
    user_role="support_agent",
    session_scopes=["read_customer", "approve_refund_under_100"],
    sandbox_verified=False,
)

@governed(gate=gate, context=ctx)
async def approve_refund(customer_id: str, amount: float) -> str:
    # This only runs if OPA allows it
    return f"Refunded ${amount} to {customer_id}"

# In your agent loop:
result = await approve_refund("cust_001", 50.0)
# If blocked: result is a GovernanceError, not an exception
```

### Pattern B — `AgentSession` (full lifecycle)

Best for: new agent code, or agents where you want credential lifecycle and sandbox management built in.

```python
from kitelogik import AgentSession, OPAClient, PolicyGate, HITLQueue, CredentialBroker

async def run_agent():
    gate = PolicyGate(opa_client=OPAClient("http://localhost:8181"))
    queue = HITLQueue()
    broker = CredentialBroker()
    await queue.setup()

    token = broker.issue(
        role="support_agent",
        scopes=["read_customer", "approve_refund_under_100"],
        ttl_seconds=3600,
    )

    session = AgentSession(
        context=SessionContext(
            session_id="session_001",
            user_role=token.role,
            session_scopes=token.scopes,
            token_id=token.token_id,
            sandbox_verified=False,
        ),
        gate=gate,
        hitl_queue=queue,
        credential_broker=broker,
    )

    async with session:
        result = await session.run(
            task="Look up customer cust_001 and check their last 3 transactions.",
            tools=["read_customer_record", "list_transactions"],
        )
    # Token is revoked here — even on exception
```

### Pattern C — OpenAI or LangChain adapter

Best for: existing OpenAI or LangChain agent loops.

```python
# OpenAI
from kitelogik.adapters.openai import OpenAIAdapter

adapter = OpenAIAdapter(gate=gate, context=ctx)
results = await adapter.execute_all(response.choices[0].message.tool_calls)

# LangChain
from kitelogik.adapters.langchain import govern_toolkit

governed_tools = govern_toolkit(your_tools, gate=gate, context=ctx)
# Use governed_tools in your LangChain agent as-is
```

### Integration checklist

- [ ] OPA is running and reachable (`curl http://localhost:8181/health`)
- [ ] Session context includes correct role and scopes for the task
- [ ] Token is issued at session start and revoked at session end (the `async with` pattern handles this)
- [ ] Tool names in your code match the action names in your Rego policy exactly
- [ ] HITL queue is set up if any actions will trigger escalation
- [ ] You have a way to handle `GovernanceError` in your agent loop (log it, return it to the model as a tool result)

---

## Stage 5 — Write Custom Policies

**Goal:** Replace or extend the example financial policy with your domain's rules.
**Time:** 2–4 hours.

### Step 5.1 — Identify your policy domains

Make a list of:
1. **Actions** your agents can take (tool names)
2. **Roles** agents will have (`support_agent`, `manager`, `auditor`, ...)
3. **Thresholds** that matter ($, row count, file size, ...)
4. **Hard blocks** — things that must never happen regardless of role or scope

### Step 5.2 — One policy domain = one file

```
kitelogik/policies/
├── main.rego          ← modify to include your domain
├── security.rego      ← keep as-is; add your hard-deny rules here
├── financial.rego     ← adapt or replace
└── your_domain.rego   ← new file for your domain
```

Starter template for a new domain:

```rego
# SPDX-License-Identifier: Apache-2.0
# policies/your_domain.rego

package kitelogik.your_domain

import future.keywords.if
import future.keywords.in

default allow := false
default requires_hitl := false

# ── Tier 1: auto-approve safe reads ──────────────────────────────────────────
allow if {
    input.action in {"list_items", "get_item_details"}
    "read_items" in input.context.session_scopes
}

# ── Tier 2: escalate high-impact writes ──────────────────────────────────────
requires_hitl if {
    input.action == "delete_item"
    "delete_items" in input.context.session_scopes
    input.context.user_role in {"admin", "manager"}
}

# ── Hard deny: never allow bulk deletes regardless of scope ──────────────────
# (Add to security.rego instead if it applies to all domains)
```

Wire it in `kitelogik/policies/main.rego`:

```rego
import data.kitelogik.your_domain

allow           if { your_domain.allow }
requires_hitl   if { your_domain.requires_hitl }
```

### Step 5.3 — Write OPA tests before the policy

```rego
# policies/your_domain_test.rego
test_read_allowed if {
    data.kitelogik.your_domain.allow with input as {
        "action": "list_items",
        "args": {},
        "context": {"user_role": "agent", "session_scopes": ["read_items"]},
    }
}

test_delete_requires_hitl if {
    data.kitelogik.your_domain.requires_hitl with input as {
        "action": "delete_item",
        "args": {"item_id": "123"},
        "context": {"user_role": "admin", "session_scopes": ["delete_items"]},
    }
}

test_unknown_action_denied if {
    not data.kitelogik.your_domain.allow with input as {
        "action": "drop_database",
        "args": {},
        "context": {"user_role": "admin", "session_scopes": ["delete_items", "read_items"]},
    }
}
```

```bash
opa test kitelogik/policies/ -v    # all tests must pass before merging
```

### Policy authoring rules

1. **Test the deny cases, not just the allow cases.** The allow case is the happy path; the deny case is where bugs hurt.
2. **Never `default allow := true` even in test files.** Use `with input as {...}` to test allows instead.
3. **Guard every numeric comparison with `is_number()`.** Skipping this is the most common bypass vector.
4. **Add comments explaining the business rule, not the Rego syntax.** Future reviewers need context.
5. **Run `opa fmt --write kitelogik/policies/`** before committing. The CI pipeline enforces this.

---

## Stage 6 — Production Deployment

**Goal:** A stable, observable, operations-ready deployment.
**Time:** 1 day.

### Step 6.1 — OPA as a standalone service

Do not run OPA with `--watch` on local files in production. Use bundles instead.

```bash
opa build kitelogik/policies/ -o bundle.tar.gz
# Upload to S3/GCS/nginx bundle server
```

See `docs/opa-bundle-guide.md` for the full setup: signing, S3/GCS config, Kubernetes deployment, rollback procedure.

**Critical:** Set `OPA_BASE_URL` to your OPA service URL in every environment:
```bash
OPA_BASE_URL=http://opa.internal:8181
```

### Step 6.2 — Persistent storage

For production, switch from in-memory to SQLite at minimum:

```python
from kitelogik.anchor.credentials import PersistentCredentialBroker

broker = PersistentCredentialBroker("credentials.db")
```

For multi-node deployments, use PostgreSQL backends (see Stage 8).

### Step 6.3 — HITL workflow

Decide who reviews HITL escalations and how:

| Scenario | Setup |
|----------|-------|
| Single team, low volume | Use the HITL queue API programmatically; approve/deny via code or scripts |
| Dedicated reviewers | Enterprise Edition — real-time dashboard with approve/deny UI |
| High volume / compliance | Enterprise Edition — PostgreSQL queue, dashboard, audit export to your SIEM |

**Set a HITL timeout** appropriate for your workflow:
```python
queue = HITLQueue(action_timeout_seconds=1800)  # 30 min
```

Actions that time out are treated as deny. Make sure your SLA fits within the timeout.

### Step 6.4 — Secrets management

```bash
# .env (never committed)
ANTHROPIC_API_KEY=sk-ant-...
OPA_BASE_URL=http://opa.internal:8181
HITL_DB_PATH=/data/hitl.db
MEMORY_DB_PATH=/data/memory.db
```

In Kubernetes: use a `Secret` object and mount it as environment variables. Never commit credentials to git — the `.env` file is in `.gitignore`.

### Step 6.5 — Health checks

```bash
# OPA
curl http://opa:8181/health
```

Set up an alerting rule: if OPA is unreachable, page on-call. OPA unreachability means every agent tool call is being hard-blocked.

> **Enterprise Edition:** The dashboard provides a combined health endpoint (`/api/health`) that probes OPA, the HITL queue, and memory in a single call.

### Stage 6 checklist

- [ ] OPA running as a standalone service, not `--watch` on local files
- [ ] Policies deployed as signed bundles (see `docs/opa-bundle-guide.md`)
- [ ] `OPA_BASE_URL` set correctly in all environments
- [ ] SQLite databases on a persistent volume (not ephemeral container storage)
- [ ] HITL timeout set to match your review team's SLA
- [ ] Health check monitoring on OPA `/health` endpoint with alerting
- [ ] `.env` never committed; secrets injected at runtime
- [ ] Non-root user in container (Dockerfile already sets uid 1001)

---

## Stage 7 — Observability

**Goal:** Trace every agent action; integrate with your existing observability stack.
**Time:** Half day.

> **Enterprise Edition:** The real-time governance dashboard (live event feed, HITL approve/deny UI, memory browser, fleet view, audit log, trace viewer) is available in [Kite Logik Enterprise](https://github.com/kitelogik/kitelogik-enterprise).

### OpenTelemetry

Every gate evaluation produces a span. The span tree for one tool call looks like:

```
gate_evaluation (session_id=..., tool=approve_refund, outcome=allow, latency_ms=4)
├── credential_validation (token_id=..., valid=true)
├── schema_validation (tool=approve_refund, valid=true)
└── opa_evaluation (policy_version=sha256:abc..., rule_matched=financial.allow_tier1)
```

**Export to your existing collector:**
```bash
# .env
OTEL_EXPORTER_OTLP_ENDPOINT=http://your-collector:4318
```

Compatible with: Grafana Tempo, Jaeger, Honeycomb, Datadog, AWS X-Ray (via ADOT), any OTLP/HTTP collector.

> **Enterprise Edition:** The enterprise stack includes Grafana + Tempo for long-term trace retention and pre-provisioned dashboards.

### SIEM integration (Enterprise)

> **Enterprise Edition:** Direct SIEM integration (Splunk HEC, Datadog, Elastic webhooks) with managed connectors is available in [Kite Logik Enterprise](https://github.com/kitelogik/kitelogik-enterprise). Events are fire-and-forget — SIEM unavailability never affects governance decisions.

For OSS deployments, export governance events from the audit log or OTel traces to your SIEM pipeline.

---

## Stage 8 — Scale Up

**Goal:** Handle multiple agent deployments, high HITL volume, or multi-team governance.
**Time:** Varies.

### Delegation governance (OSS)

Delegation depth and scope narrowing are enforced by OPA (`delegation.rego`) in the OSS edition. You can manage multiple `AgentSession` instances with parent-child credential relationships using the `CredentialBroker.delegate()` method. Worker agents cannot escalate their own scopes.

### Enterprise scale features

The following are available in [Kite Logik Enterprise](https://github.com/kitelogik/kitelogik-enterprise):

| Feature | What it provides |
|---------|-----------------|
| **Governance Gateway** | Centralized HTTP API for policy enforcement across multiple agents. Agents call HTTP instead of an in-process gate. |
| **Multi-agent Orchestrator** | Spawn and coordinate multiple governed agent sessions with delegation chains, scope narrowing, and depth limits. |
| **PostgreSQL backends** | Drop-in replacements for SQLite: HITL queue, credentials, memory, audit — for HA multi-node deployments. |
| **Real-time Dashboard** | Live event feed, HITL approve/deny UI, audit log, memory browser, fleet view. |
| **Prometheus Metrics** | Policy decision counters, HITL queue gauges, gate latency histograms with Grafana dashboards. |
| **SIEM Connectors** | Splunk HEC, Datadog, Elastic webhook dispatchers. |

---

## Reference

### Common first mistakes

| Mistake | Fix |
|---------|-----|
| `OPA is unreachable` on startup | `docker compose up -d opa` first; check `OPA_BASE_URL` |
| All actions are blocked | Check that your session scopes match the policy — `session_scopes` in context must include the scope the policy requires |
| HITL action never resolves | Check `HITL_TIMEOUT_SECONDS` — if too short, the action times out before a human can review |
| `sandbox_verified=False` blocks code execution | Sandbox isolation is an Enterprise Edition feature. In OSS, avoid `execute_code` tool calls or write a policy that allows them for your use case |
| Policy change has no effect | OPA may be caching; restart OPA or use `opa build` + bundle reload |
| Amount `"50"` (string) passes scope check but fails threshold | Policy is working correctly — `is_number()` rejects strings. Fix the caller to send a float |

### Key files

| File | What it does |
|------|-------------|
| `kitelogik/__init__.py` | All public API exports |
| `kitelogik/tether/gate.py` | PolicyGate — the enforcement entry point |
| `kitelogik/tether/models.py` | `PolicyDecision`, `SessionContext`, `RiskTier` |
| `kitelogik/policies/main.rego` | Final allow/deny/requires_hitl aggregation |
| `kitelogik/policies/security.rego` | Unconditional hard-deny rules |
| `kitelogik/agents/session.py` | `AgentSession` — full lifecycle management |
| `kitelogik/anchor/queue.py` | `HITLQueue` — HITL async queue |
| `quickstart.py` | Minimal working example — start here |
| `explore.py` | 8 governance scenarios — reference implementation |
| `examples/getting-started/` | Self-contained getting-started example |
| `kitelogik/policies/compiler.py` | YAML → Rego policy compiler |

### Getting help

- **Docs:** `docs/architecture.md`, `docs/open-source.md`, `docs/opa-bundle-guide.md`
- **Examples:** `kitelogik/policies/examples/`, `quickstart.py`, `explore.py`
- **Tests as documentation:** `tests/test_gate.py`, `tests/adversarial/test_policy_bypass.py`
- **Issues:** https://github.com/kitelogik/kitelogik/issues
