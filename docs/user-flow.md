# Kite Logik — End-to-End User Flow

How a tool call travels through the governance pipeline, from the moment an AI agent decides to act to the moment the result is returned. Covers both the business perspective (what happens and why) and the technical perspective (what code runs and where).

---

## The Lifecycle at a Glance

```
  Developer writes rules  ──►  Agent runs  ──►  Every action is governed  ──►  Audit trail exists
       (Rego policies)         (Claude/GPT)     (allow / escalate / block)     (immutable, exportable)
```

There are five phases in the lifecycle of a governed AI agent:

1. **Define** — Write the rules that govern what agents can do
2. **Provision** — Start a session with scoped credentials and an isolated sandbox
3. **Enforce** — Every tool call is evaluated against policy before execution
4. **Escalate** — High-stakes actions pause for human review
5. **Observe** — Every decision is traced, audited, and exportable

---

## Phase 1: Define the Rules

### What happens (business perspective)

Before any agent runs, someone on your team decides what agents are allowed to do. These decisions are written as deterministic rules — not prompts, not guidelines, not system messages. They are evaluated by a policy engine (OPA) that the AI model cannot see, influence, or override.

Examples of rules you might write:

- Support agents can approve refunds up to $100 without human involvement
- Any refund over $1,000 requires a manager to approve it in real time
- No agent can ever read files outside of `/data/` regardless of role
- Agents spawned by other agents (delegation) cannot have more permissions than their parent
- No agent session can exceed $5 in API costs

### What happens (technical perspective)

Rules are Rego files in the `kitelogik/policies/` directory. Each domain (financial, security, delegation, agent lifecycle) gets its own file. Every file starts with `default allow := false` — nothing is permitted unless a rule explicitly allows it.

```rego
# policies/financial.rego
package kitelogik.financial

default allow := false

allow if {
    input.action == "approve_refund"
    input.context.user_role == "support_agent"
    "approve_refund" in input.context.session_scopes
    is_number(input.args.amount)
    input.args.amount <= 100
}
```

The `main.rego` file aggregates all domain policies into a single decision. Hard-deny rules (in `security.rego`) always win — no allow rule can override them:

```rego
# main.rego — deny always takes priority
allow if {
    not deny          # ← this guard is on every allow rule
    financial.allow
}
```

**Files involved:** `kitelogik/policies/*.rego`, `kitelogik/kitelogik/policies/library/*.rego`
**Validation:** `opa test kitelogik/policies/ -v` runs the test suite (194 tests)
**Interactive development:** `python -m kitelogik.policy_tester` for live Rego editing

---

## Phase 2: Provision a Session

### What happens (business perspective)

When an agent starts a task, it receives a temporary credential that defines exactly what it can do. This credential:

- Lists the specific tools the agent can call (its "scopes")
- Expires automatically after a set time (default: 1 hour)
- Is revoked immediately when the session ends — even if the session crashes
- Cannot be expanded after issue — only narrowed for child agents

If the agent needs to run code, it also gets an isolated container (sandbox) with no network access, limited memory, and a read-only filesystem.

### What happens (technical perspective)

The `AgentSession.run_async()` method handles provisioning:

**Step 2a — Sandbox spawn (optional)**

```
SandboxManager.spawn(session_id)
  → DockerRuntime._sync_spawn(session_id)
    → docker run --network=none --read-only --cap-drop=ALL --mem-limit=256m ...
  → SandboxInfo(status=HEALTHY, sandbox_id=...)
  → context.sandbox_verified = True
```

The container runs `sleep 3600` and waits for exec commands. Resource limits are unconditional — they cannot be disabled by configuration.

**Step 2b — Governance check: agent.spawn**

Before the agent loop starts, the spawn itself is evaluated by OPA:

```
PolicyGate.evaluate(GovernanceEvent(event_type="agent.spawn", ...))
  → OPAClient._post_to_opa({...})
  → PolicyDecision(allow=True/False, ...)
```

If the spawn is denied (e.g., too many active agents, or the requested scopes exceed what's permitted), the session is torn down before it begins.

**Step 2c — Credential issue**

```
CredentialBroker.issue(session_id, scopes=["read_customer", "approve_refund"], ttl_seconds=3600)
  → SessionToken(token_id="tok_a1b2c3...", scopes=[...], expires_at=...)
  → context.token_id = token.token_id
```

The token is generated using `secrets.token_hex(16)` (cryptographically secure). It is stored in memory (or SQLite for `PersistentCredentialBroker`) and validated on every subsequent tool call.

**Step 2d — Cleanup guarantee**

The session uses a `try/finally` block:

```python
try:
    result = await self._run_loop(prompt, max_iterations, on_event)
finally:
    if sandbox_info and self.sandbox_manager:
        await self.sandbox_manager.teardown(session_id)
    # Revoke token only if this session issued it (not delegated)
    if token and self.credential_broker:
        self.credential_broker.revoke(token.token_id)
```

The token is revoked and the container is destroyed even if the agent crashes, times out, or raises an exception. Note: delegated child sessions do not revoke their own token — the parent orchestrator handles child token revocation in its own cleanup block.

**Files involved:** `agents/session.py`, `anchor/credentials.py`, `sandbox/manager.py`, `sandbox/runtime.py`

---

## Phase 3: Enforce Every Tool Call

### What happens (business perspective)

The agent reasons about the user's request and decides to call a tool — for example, "approve a $50 refund for customer cust_001." Before that tool function runs, the governance pipeline evaluates the call:

1. **Is the credential valid?** — Is the session token active, unexpired, and unrevoked?
2. **Does the agent have the right scope?** — Is `approve_refund` in the token's scope list?
3. **Does the policy allow this specific call?** — OPA evaluates the action, the arguments, the role, and the scopes against the Rego rules.

The result is one of three outcomes:

| Outcome | What happens next |
|---------|-------------------|
| **Allow** | The tool executes. The result is sanitized before being returned to the agent. |
| **Escalate (HITL)** | The action is queued for human review. The agent pauses. |
| **Block** | The tool does not execute. The agent receives a structured denial reason. |

The agent cannot retry a blocked action — the denial message instructs the model not to reattempt it.

### What happens (technical perspective)

Every tool call flows through this pipeline:

```
Agent (Claude) calls tool "approve_refund" with args {customer_id: "cust_001", amount: 50}
  │
  ▼
ToolCallInput(action="approve_refund", tool_name="approve_refund", args={...})
  │
  ▼
PolicyGate.evaluate_tool_call(tool_call, context)
  │
  ├── Step 1: Credential validation
  │     CredentialBroker.validate(token_id)
  │     → Token found, not revoked, not expired → continue
  │     → Token invalid → PolicyDecision(deny=True, reason="credential_invalid")
  │
  ├── Step 2: Schema validation
  │     ToolCallInput validated by Pydantic
  │     → Valid → continue
  │     → Invalid → PolicyDecision(deny=True, reason="schema_validation_failed")
  │
  └── Step 3: OPA evaluation
        OPAClient._post_to_opa({action, args, context})
        → HTTP POST to http://opa:8181/v1/data/kitelogik/main
        → OPA evaluates all Rego rules
        → Returns: {allow: true/false, deny: true/false, risk_tier: "...", requires_hitl: true/false}
        → PolicyDecision(allow=True, risk_tier=OPERATIONAL, ...)
```

**If OPA is unreachable:** The gate fails closed — every call is denied with `risk_tier=SECURITY_CRITICAL` and `rule_matched=opa_connection_failure`. This is not configurable. An unreachable policy engine means zero agent actions are permitted.

**After allow — tool execution:**

```
execute_tool("approve_refund", {customer_id: "cust_001", amount: 50})
  │
  ▼
Raw tool output: '{"status": "approved", "transaction_id": "txn_123"}'
  │
  ▼
PolicyGate.sanitize_response(raw_output)
  → NFKC unicode normalization
  → Scan for 10 prompt injection patterns (regex)
  → If injection found: redact matching spans, log warning
  → Return SanitizedResponse(content="...", was_modified=False)
  │
  ▼
Sanitized output returned to agent context
```

The sanitizer runs on every tool output, every time. This defends against indirect prompt injection — malicious instructions hidden in database records, API responses, or file contents that the agent reads.

**After allow — audit record:**

```
AuditStore.record(
    session_id, tool_name, args, decision, context, outcome="allowed"
)
  → INSERT INTO audit_log (...) VALUES (...)
  → SQL triggers prevent UPDATE and DELETE — the record is immutable
```

**Files involved:** `tether/gate.py`, `tether/opa_client.py`, `tether/sanitizer.py`, `audit/store.py`

---

## Phase 4: Escalate High-Stakes Actions

### What happens (business perspective)

Some actions are too important to auto-approve but not dangerous enough to block outright. A $2,500 refund, for example: a legitimate support request, but one that needs a human to sign off.

When OPA returns `requires_hitl: true`, the tool call does not execute. Instead:

1. The action is placed in a review queue with all context (tool name, arguments, risk tier, session ID)
2. The agent session pauses — it is not doing anything while waiting
3. A human reviewer sees the pending action in the dashboard (or via the API)
4. The reviewer clicks **Approve** or **Deny**
5. If approved: the tool executes and the agent resumes with the result
6. If denied: the agent receives a denial message and continues without executing
7. If nobody responds within the timeout (default 5 minutes): the action is treated as denied

The agent tells the user what is happening at each step: "This refund requires manager approval. I've submitted it for review."

### What happens (technical perspective)

**Enqueue:**

```
PendingAction(
    id="act_a1b2c3d4e5f6",
    session_id="sess_001",
    tool_name="approve_refund",
    args={customer_id: "cust_001", amount: 2500},
    risk_tier="TRANSACTIONAL_HIGH",
    status=PENDING,
)
  │
  ▼
HITLQueue.enqueue(action)
  → INSERT INTO pending_actions (...) VALUES (?)
  → asyncio.Event created for this action_id
  │
  ▼
AuditStore.record(session_id, tool_name, args, decision, outcome="hitl_queued")
  → Compliance record written before any decision is received
```

**Wait:**

```
HITLQueue.wait_for_decision(action_id, timeout_seconds=300)
  → asyncio.wait_for(event.wait(), timeout=300)
  → Agent coroutine is suspended — no polling, no CPU usage
```

**Human decides (via dashboard or API):**

```
POST /approve/act_a1b2c3d4e5f6
  → HITLQueue.approve(action_id, decided_by="jane@company.com")
    → UPDATE pending_actions SET status='APPROVED', decided_by=?, decided_at=?
      WHERE id=? AND status='PENDING'
    → asyncio.Event.set()  ← wakes up the waiting agent immediately
```

The `WHERE status='PENDING'` clause ensures a decision is immutable once recorded. You cannot re-approve or re-deny an action.

**Resume:**

```
decided.status == APPROVED
  → execute_tool("approve_refund", args)
  → sanitize output
  → audit record: outcome="hitl_approved", hitl_decided_by="jane@company.com"
  → return result to agent
```

**Timeout path:**

If no decision arrives within the timeout, `wait_for_decision` catches `TimeoutError`, marks the action as `TIMED_OUT` in the database, and returns a denial to the agent.

A background expiry task (`start_expiry_task`) also runs every 30 seconds to catch actions where the waiting coroutine has already been cancelled (e.g., the agent session was killed).

**Files involved:** `anchor/queue.py`, `anchor/api.py`, `anchor/models.py`, `agents/session.py` (the `_handle_hitl` method)

---

## Phase 5: Observe Everything

### What happens (business perspective)

Every action the agent takes — allowed, blocked, or escalated — is recorded in an immutable audit log. This log is the compliance artifact: it proves what happened, what policy was in effect, who approved what, and when.

You can:

- **Watch in real time** — the dashboard shows a live feed of gate decisions as they happen
- **Export a session report** — a self-contained JSON document with every tool call, its policy decision, and a SHA-256 integrity hash
- **Replay against new rules** — re-evaluate historical decisions against your current policy to see what would change if you deployed a rule update
- **Forward to your SIEM** — Splunk, Elastic, or any HTTP webhook receiver

### What happens (technical perspective)

**OpenTelemetry spans:**

Every gate evaluation produces a span with attributes:

```
kitelogik.session_id = "sess_001"
kitelogik.tool_name  = "approve_refund"
kitelogik.policy.allow = true
kitelogik.policy.risk_tier = "TRANSACTIONAL_LOW"
kitelogik.policy.reason = "Allowed — risk tier: TRANSACTIONAL_LOW"
```

Spans contain only metadata — never raw prompt content, tool arguments, or model outputs. This is a security invariant enforced across the codebase.

The in-memory exporter holds the last 500 spans for the dashboard Traces tab. For long-term retention, configure `OTEL_EXPORTER_OTLP_ENDPOINT` to forward to Tempo, Jaeger, or any OTLP collector.

**Audit log:**

```
AuditStore — SQLite with SQL triggers:

  CREATE TRIGGER prevent_audit_update BEFORE UPDATE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END

  CREATE TRIGGER prevent_audit_delete BEFORE DELETE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END
```

Records cannot be modified or deleted after write. Each record includes:

- The full policy decision (allow/deny/risk_tier/requires_hitl)
- The SHA-256 hash of the policy files that were evaluated
- The session context (role, scopes, delegation depth, parent session)
- HITL metadata (who approved, when)

**Session export:**

```
AuditStore.export_session(session_id)
  → SELECT * FROM audit_log WHERE session_id = ?
  → SHA-256 hash of the records list (sorted keys, deterministic)
  → Returns: {session_id, records: [...], integrity_hash: "abc123...", policy_version: "def456..."}
```

The integrity hash lets the recipient verify that no records were omitted or tampered with after export.

**Policy replay:**

```
PolicyReplayer.replay_session(audit_store, session_id)
  → For each historical record:
    → Reconstruct the original SessionContext from stored context_json
    → Re-evaluate via PolicyGate.evaluate_tool_call() against current OPA rules
    → Compare: original_outcome vs replayed_outcome
  → Returns list of ReplayResult with outcome_changed=True/False
```

This tells you: "If we deploy this policy change, 3 out of 47 historical decisions would have been different." Run this before deploying policy updates to production.

**Files involved:** `observability/tracer.py`, `observability/siem.py`, `audit/store.py`, `audit/replay.py`, `dashboard/server.py`

---

## Multi-Agent Delegation

### What happens (business perspective)

A complex task might need multiple agents working in parallel. The orchestrator agent decomposes the task ("process today's refund queue") and delegates sub-tasks to worker agents. Each worker:

- Gets a **narrower credential** — if the parent can read customers and approve refunds, a worker might only get read access
- Runs in its **own sandbox** — workers are isolated from each other and from the parent
- Has a **tracked delegation depth** — workers can delegate further, but only up to a configured maximum (default: 2 levels)
- Cannot **escalate privileges** — requesting scopes beyond the parent's grant raises an error before the worker starts

If a worker triggers a HITL escalation, the approval request appears in the same queue as any other — the reviewer sees which parent session delegated it.

### What happens (technical perspective)

```
Orchestrator.delegate(task, scopes=["read_customer"], worker_role="reader")
  │
  ├── GovernanceEvent(event_type="agent.delegate", ...)
  │     → OPA evaluates delegation.rego
  │     → Checks: depth <= max, scopes ⊆ parent, not killed
  │
  ├── CredentialBroker.delegate(parent_token_id, requested_scopes, session_id)
  │     → Validates: requested_scopes ⊆ parent.scopes
  │     → Child token: expires_at <= parent.expires_at
  │     → delegation_depth = parent.delegation_depth + 1
  │
  ├── SandboxManager(DockerRuntime()) — new container for this worker
  │
  └── AgentSession(context=child_context, gate=gate, ...)
        → Worker runs its task
        → On completion: child token revoked, sandbox torn down
```

For parallel delegation:

```
Orchestrator.delegate_parallel([
    {"task": "Look up billing", "scopes": ["read_billing"]},
    {"task": "Check shipping",  "scopes": ["read_shipping"]},
])
  → asyncio.gather(delegate(task1), delegate(task2))
  → Both workers run concurrently
  → Results collected and returned to orchestrator
```

**Files involved:** `agents/orchestrator.py`, `anchor/credentials.py` (delegate method), `kitelogik/policies/delegation.rego`

---

## Integration Modes

Kite Logik supports three integration patterns. Choose based on your architecture:

### Embedded SDK (simplest)

```python
@governed(gate=gate, context=ctx)
async def my_tool(arg: str) -> str:
    return do_something(arg)
```

The policy gate runs in-process. No network hop for evaluation (OPA is still a separate service, but the gate logic is local). Best for single-agent applications.

### Governance Gateway (centralized)

Agents call tools through an HTTP API. The gateway handles the entire pipeline:

```
Agent → HTTP POST /v1/tools/call → Gateway → OPA → Tool → Sanitize → Audit → Response
```

Best for teams with multiple agents that need a single policy enforcement point. The gateway also provides fleet management endpoints (`/v1/fleet/status`, `/v1/agents/{id}/kill`).

### Full Control Plane (orchestrated)

`AgentSession` + `Orchestrator` manage the complete agent lifecycle: spawn governance, credential lifecycle, sandbox isolation, delegation chains, HITL blocking, memory with provenance, and audit. This is the pattern used by the demo (`agents/demo.py`).

Best for production deployments where agents spawn other agents and the full governance surface is required.

---

## Quick Reference: What Runs Where

| Component | Process | Storage | Network |
|-----------|---------|---------|---------|
| OPA | Standalone container | In-memory (or bundle from S3) | HTTP :8181 |
| PolicyGate | In agent process or gateway | None | Calls OPA |
| CredentialBroker | In agent process | In-memory or SQLite | None |
| HITLQueue | In agent process | SQLite | None |
| AuditStore | In agent process or gateway | SQLite | None |
| Sandbox | Docker container per session | Ephemeral (read-only + tmpfs) | None (network=none) |
| Dashboard | Standalone FastAPI | SQLite (events) | HTTP :8050, WebSocket |
| SIEM Webhook | In agent process | None | HTTPS to your SIEM |
| MCP Servers | Subprocess or HTTP | Varies | JSON-RPC |

For production multi-node deployments, SQLite backends are replaced with PostgreSQL (same API surface).
