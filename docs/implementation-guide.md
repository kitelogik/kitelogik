# Kite Logik — Implementation Guide

How to integrate Kite Logik into your AI agents, workflows, and systems. Four integration levels — from a single decorator to a centralized governance gateway.

**LLM provider support:** Levels 1, 2, and 4 are fully LLM-agnostic — they work with OpenAI, Anthropic, Cohere, Llama, Mistral, or any model that produces tool calls. Level 3 (`AgentSession`) uses the Anthropic SDK (Claude) for reasoning. See [Which LLM can I use?](#which-llm-can-i-use) for details.

---

## Prerequisites

All integration levels require:

1. **A policy engine** — choose one:

**Option A: Docker (recommended for getting started)**

```bash
docker compose up -d opa
```

This starts OPA with the bundled policies. One command, ready in seconds.

**Option B: OPA binary (no Docker)**

OPA is a single static binary (~50MB, no dependencies, starts in under a second).

```bash
# macOS
brew install opa

# Linux (amd64)
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x opa && sudo mv opa /usr/local/bin/

# Start OPA with your policies
opa run --server kitelogik/policies/
```

**Option C: Regorus (in-process, experimental)**

Regorus embeds a Rust-based Rego engine in-process. Requires building from source — see [microsoft/regorus](https://github.com/microsoft/regorus) for build instructions.

```python
from kitelogik.tether.regorus_client import RegorusClient

engine = RegorusClient(policy_dir="kitelogik/policies/")
gate = PolicyGate(opa_client=engine)
```

2. **Policies** — at least one policy file in `kitelogik/policies/`

Write policies in **YAML** (no Rego knowledge needed) or **Rego** (full control):

```bash
# YAML → Rego compilation
kitelogik compile kitelogik/policies/examples/example_rules.yaml

# Or hand-write Rego files directly in policies/
# Every file must start with: default allow := false
```

3. **Install Kite Logik**

```bash
pip install kitelogik
```

### When is Docker required?

| Purpose | Requires Docker? | When it's needed |
|---|---|---|
| Policy evaluation (OPA via Docker) | Yes — one command: `docker compose up -d opa` | Recommended for getting started |
| Policy evaluation (OPA binary) | No — OPA runs as a standalone binary | All levels |
| Policy evaluation (Regorus) | No — build from source, runs in-process | Experimental |
| Sandbox isolation (`SandboxManager`) | Yes — spawns hardened containers per session | Level 3 only, and optional (`sandbox_manager=None`) |

**No level requires Docker.** Use Regorus for zero-infrastructure policy evaluation, or install OPA as a standalone binary. Docker is only needed for sandbox isolation (Level 3), and even that is optional (`sandbox_manager=None`).

**Level 3 without Docker** still gives you credential lifecycle, HITL escalation, audit trail, memory with provenance, and output sanitization. The sandbox is the one piece that drops out.

---

## Level 1: Decorator or Toolbox

**Effort:** 5 minutes. No restructuring of existing code.

**What you get:** Every tool call evaluated by OPA before execution. Denied calls raise `GovernanceError`. Return values scanned for prompt injection and sanitized.

**What you don't get:** No HITL, no sandbox, no audit trail, no credential lifecycle.

### Pattern A: `@governed` decorator

Wrap individual functions. Works with sync and async.

```python
from kitelogik import PolicyGate, SessionContext, governed

# OPA server (start with: docker compose up -d opa)
from kitelogik import OPAClient
gate = PolicyGate(opa_client=OPAClient())

ctx  = SessionContext(
    session_id="sess_001",
    user_role="support_agent",
    session_scopes=["read_customer", "approve_refund"],
)

# Wrap any existing function
@governed(gate=gate, context=ctx)
async def approve_refund(customer_id: str, amount: float) -> str:
    return payment_api.refund(customer_id, amount)

# Call it normally — governance runs before the function body
result = await approve_refund("cust_001", 50.0)
```

If OPA denies the call, `GovernanceError` is raised and the function never executes:

```python
from kitelogik import GovernanceError

try:
    result = await approve_refund("cust_001", 50.0)
except GovernanceError as e:
    print(f"Blocked: {e}")
    print(f"Risk tier: {e.decision.risk_tier}")
    print(f"Rule: {e.decision.rule_matched}")
```

### Pattern B: `GovernedToolbox`

Register many tools, call by name. Framework-agnostic.

```python
from kitelogik import GovernedToolbox

toolbox = GovernedToolbox(gate=gate, context=ctx)
toolbox.register("approve_refund", approve_refund_fn)
toolbox.register("read_customer", read_customer_fn)
toolbox.register("list_transactions", list_transactions_fn)

# In your agent loop — dispatch by tool name
result = await toolbox.call("approve_refund", {"customer_id": "c1", "amount": 50})
```

### Plan-before-execute evaluation

`GovernedToolbox` supports evaluating a proposed sequence of actions before executing any of them. This catches composite policy violations that per-call evaluation would miss.

Per-call evaluation checks each tool call independently — it sees "read customer data" (allowed) and "approve $200 refund" (allowed) as two separate events. Plan evaluation sees them together and can enforce policies like "reading customer data and then approving a refund above $200 in the same session requires HITL review" or "no plan with more than 20 steps."

```python
steps = [
    {"tool_name": "read_customer", "args": {"customer_id": "c1"}},
    {"tool_name": "approve_refund", "args": {"customer_id": "c1", "amount": 200}},
]
decision = await toolbox.evaluate_plan(steps)
# GovernanceError raised if the plan is denied
```

Plan evaluation flows through the same OPA pipeline as tool calls — write Rego rules in `kitelogik/policies/agent_plan.rego` to control what sequences of actions are permitted. This is a differentiator: most guardrails tools only evaluate individual calls, not the plan that produced them.

---

## Level 2: Framework Adapters

**Effort:** 10 minutes. Drop-in for existing agent loops.

**What you get:** Same as Level 1, but integrated at the framework level. Denied calls return structured messages to the model (the agent loop continues, the model sees the refusal and can respond).

### OpenAI

```python
from kitelogik import PolicyGate, OPAClient, SessionContext
from kitelogik.adapters.openai import OpenAIAdapter
import openai

gate = PolicyGate(opa_client=OPAClient())
ctx  = SessionContext(
    session_id="sess_001",
    user_role="support_agent",
    session_scopes=["read_customer", "approve_refund"],
)

adapter = OpenAIAdapter(gate=gate, context=ctx)
adapter.register("get_customer_record", get_customer_fn, schema={
    "name": "get_customer_record",
    "description": "Look up a customer by ID",
    "parameters": {
        "type": "object",
        "properties": {"customer_id": {"type": "string"}},
        "required": ["customer_id"],
    },
})
adapter.register("approve_refund", approve_refund_fn, schema={...})

# Your existing OpenAI loop — only two lines change:
client   = openai.AsyncOpenAI()
messages = [{"role": "user", "content": "Refund $50 to cust_001"}]

while True:
    response = await client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        tools=adapter.openai_tool_schemas(),        # ← governed schemas
    )
    choice = response.choices[0]
    if choice.finish_reason != "tool_calls":
        break

    messages.append(choice.message)
    tool_results = await adapter.execute_all(       # ← governed execution
        choice.message.tool_calls
    )
    messages.extend(tool_results)
```

### LangChain

**Wrap new functions:**

```python
from kitelogik.adapters.langchain import as_governed_tool

governed_refund = as_governed_tool(
    name="approve_refund",
    fn=approve_refund_fn,
    gate=gate,
    context=ctx,
    description="Approve a refund for a customer.",
)

agent = create_react_agent(llm, tools=[governed_refund])
```

**Wrap existing tools (one line):**

```python
from kitelogik.adapters.langchain import govern_toolkit

# Take any existing toolkit and add governance
raw_tools = SQLDatabaseToolkit(db=db, llm=llm).get_tools()
governed_tools = govern_toolkit(raw_tools, gate=gate, context=ctx)
agent = create_react_agent(llm, tools=governed_tools)
```

Requires: `pip install langchain-core`

### CrewAI

```python
from kitelogik.adapters.crewai import CrewAIAdapter

adapter = CrewAIAdapter(gate=gate, context=ctx)
adapter.register("search_web", search_web_fn, description="Search the web")
adapter.register("read_file", read_file_fn, description="Read a file")

# Pass governed tools to your CrewAI agent
tools = adapter.crewai_tools()
agent = Agent(role="researcher", tools=tools, ...)
```

Requires: `pip install crewai`

### OpenAI Agents SDK

```python
from kitelogik.adapters.openai_agents import OpenAIAgentsAdapter

adapter = OpenAIAgentsAdapter(gate=gate, context=ctx)
adapter.register(
    "search", search_fn,
    description="Search docs",
    params={"query": {"type": "string"}},
)

tools = adapter.agent_tools()
agent = Agent(name="researcher", tools=tools, ...)
```

Requires: `pip install openai-agents`

### LangGraph

```python
from kitelogik.adapters.langgraph import GovernedLangGraphToolNode

tool_node = GovernedLangGraphToolNode(
    tools=[tool_a, tool_b],
    gate=gate,
    context=ctx,
)

# Use in your LangGraph state graph
graph.add_node("tools", tool_node)
```

Requires: `pip install langgraph`

### Google ADK

```python
from kitelogik.adapters.google_adk import GoogleADKAdapter

adapter = GoogleADKAdapter(gate=gate, context=ctx)
adapter.register("search", search_fn, description="Search the web")

tools = adapter.adk_tools()
```

Requires: `pip install google-adk`

### PydanticAI

```python
from kitelogik.adapters.pydantic_ai import PydanticAIAdapter

adapter = PydanticAIAdapter(gate=gate, context=ctx)
adapter.register("search", search_fn, description="Search the web")

tools = adapter.pydantic_tools()
```

Requires: `pip install pydantic-ai`

### LlamaIndex

```python
from kitelogik.adapters.llamaindex import LlamaIndexAdapter

adapter = LlamaIndexAdapter(gate=gate, context=ctx)
adapter.register("query_index", query_fn, description="Query the index")

tools = adapter.llamaindex_tools()
```

Requires: `pip install llama-index`

### Semantic Kernel

```python
from kitelogik.adapters.semantic_kernel import SemanticKernelAdapter

adapter = SemanticKernelAdapter(gate=gate, context=ctx)
adapter.register("summarize", summarize_fn, description="Summarize text")

functions = adapter.kernel_functions()
```

Requires: `pip install semantic-kernel`

### Haystack

```python
from kitelogik.adapters.haystack import HaystackAdapter

adapter = HaystackAdapter(gate=gate, context=ctx)
adapter.register("retrieve", retrieve_fn, description="Retrieve documents")

tools = adapter.haystack_tools()
```

Requires: `pip install haystack-ai`

### Dify

```python
from kitelogik.adapters.dify import DifyAdapter

adapter = DifyAdapter(gate=gate, context=ctx)
adapter.register("classify", classify_fn, description="Classify input")

tools = adapter.dify_tools()
```

Requires: `pip install dify-plugin`

---

## Level 3: Full Agent Session

**Effort:** 30 minutes. Complete governance surface.

**What you get:** Everything. Credential lifecycle, HITL escalation, sandbox isolation, audit trail, memory with provenance, output sanitization. The agent spawn itself is governed by OPA.

**LLM note:** `AgentSession` uses the Anthropic SDK (Claude) for its reasoning loop. This is the only Anthropic-coupled component in Kite Logik. The governance primitives it wires together — `PolicyGate`, `CredentialBroker`, `HITLQueue`, `AuditStore`, `SandboxManager` — are all provider-agnostic. If you're using GPT-4o, Llama, Mistral, or any other model, you have two options: use a Level 2 adapter with your own session loop (wiring in credentials, HITL, and audit manually), or use the Governance Gateway (Level 4), which provides the full enforcement pipeline over HTTP regardless of which model calls it.

### Setup

```python
from kitelogik import (
    AgentSession, PolicyGate, OPAClient, SessionContext,
    CredentialBroker, HITLQueue, MemoryStore,
)
from kitelogik.audit.store import AuditStore

# Initialize components
opa     = OPAClient()
broker  = CredentialBroker()
gate    = PolicyGate(opa_client=opa, credential_broker=broker)
queue   = HITLQueue()
memory  = MemoryStore()
audit   = AuditStore()

await queue.setup()
await memory.setup()
await audit.setup()
```

### Issue a scoped credential

```python
token = broker.issue(
    session_id="sess_001",
    scopes=["read_customer", "approve_refund"],
    ttl_seconds=3600,  # expires in 1 hour
)

ctx = SessionContext(
    session_id="sess_001",
    user_role="support_agent",
    session_scopes=token.scopes,
    token_id=token.token_id,
)
```

The token defines the ceiling of what the agent can do. OPA checks every tool call against these scopes. No prompt instruction can expand them.

### Run a governed session

```python
session = AgentSession(
    gate=gate,
    context=ctx,
    hitl_queue=queue,
    credential_broker=broker,
    memory_store=memory,
    audit_store=audit,
)

result = await session.run_async("Process refund for cust_001, $50")
print(result.final_output)
```

What happens under the hood:

1. OPA evaluates `agent.spawn` — if denied, session tears down before it begins
2. Agent loop starts — Claude reasons about the task and calls tools
4. Every tool call flows through: credential validation → schema validation → OPA evaluation
5. Allowed calls execute, output is sanitized, audit record is written
6. HITL calls pause the agent until a human approves/denies
7. On completion (or crash): token revoked, session cleaned up

### Multi-agent delegation

```python
from kitelogik import Orchestrator

orchestrator = Orchestrator(
    gate=gate,
    parent_context=ctx,
    credential_broker=broker,
    hitl_queue=queue,
    memory_store=memory,
    audit_store=audit,
)

# Serial delegation — child gets narrower scopes than parent
result = await orchestrator.delegate(
    task="Look up billing history for cust_001",
    scopes=["read_billing"],  # must be ⊆ parent scopes
)

# Parallel delegation — fan-out to multiple workers
results = await orchestrator.delegate_parallel([
    {"task": "Check billing", "scopes": ["read_billing"]},
    {"task": "Check shipping", "scopes": ["read_shipping"]},
])
```

Delegation invariants enforced by OPA and the credential broker:
- Child scopes must be a subset of parent scopes
- Child token expires no later than parent token
- Delegation depth is tracked and capped (default: 2 levels)
- If a child triggers HITL, it appears in the same queue with parent session context

### HITL review

The HITL queue API provides programmatic approve/deny:

```python
await queue.approve(action_id, decided_by="reviewer@example.com")
await queue.deny(action_id, decided_by="reviewer@example.com", reason="Amount too high")
status = await queue.get_status(action_id)
```

> **Enterprise Edition:** The real-time dashboard with approve/deny UI and the Governance Gateway REST endpoints (`/v1/hitl/{id}/approve`, `/v1/hitl/{id}/deny`) are available in [Kite Logik Enterprise](mailto:licensing@kitelogik.com).

---

## Level 4: Governance Gateway (Enterprise)

> **Enterprise Edition:** The Governance Gateway is available in [Kite Logik Enterprise](mailto:licensing@kitelogik.com).

**What you get:** A single HTTP API that all agents call tools through. Centralized policy enforcement, fleet management, and audit. Best for teams with multiple agents.

Agents call tools via HTTP:

```
POST /v1/tools/call
{
    "tool_name": "approve_refund",
    "args": {"customer_id": "cust_001", "amount": 50},
    "session_id": "sess_001",
    "user_role": "support_agent"
}
```

The gateway handles the full pipeline: auth → schema → OPA → tool execution → sanitize → audit → response. Framework adapters translate OpenAI `tool_calls` and Anthropic `tool_use` blocks into gateway requests automatically.

---

## Writing Policies

### YAML Policies (Recommended Starting Point)

If you don't know Rego, start here. Write rules in YAML and compile them to Rego:

```yaml
# policies/my_rules.yaml
version: 1
package: kitelogik.my_rules
rules:
  - name: block_large_refunds
    when:
      action: approve_refund
      args.amount: { gt: 1000 }
    then: deny
    reason: "Refunds over $1000 require manager approval"

  - name: allow_reads_for_support
    when:
      action: { in: [read_customer, list_transactions] }
      context.user_role: { in: [support_agent, manager] }
      context.session_scopes: { contains: read_customer }
    then: allow
    risk_tier: INFORMATIONAL
```

```bash
kitelogik compile policies/my_rules.yaml              # generates policies/my_rules.rego
kitelogik compile policies/my_rules.yaml --check      # validate without generating
kitelogik validate                                     # check all .rego syntax
kitelogik test -v                                      # run OPA tests
```

**v1 YAML scope:** Action allowlists, amount thresholds, role/scope checks, risk tier assignment, `in`/`contains`/`gt`/`lt`/`eq` operators. Complex multi-rule interactions (delegation cascades, plan evaluation) require hand-written Rego.

### Rego Policies (Full Control)

Policies live in `kitelogik/policies/`. Each domain gets its own file. Every file starts with `default allow := false`.

### Minimal policy

```rego
# policies/main.rego
package kitelogik.main

default allow := false
default deny := false

# Allow read-only tools for any authenticated session
allow if {
    not deny
    input.action == "read_customer"
    "read_customer" in input.context.session_scopes
}
```

### Using the starter library

The `kitelogik/policies/library/` directory contains ready-to-use policies:

| Policy | What it does |
|---|---|
| `tool_allowlist.rego` | Only permit explicitly listed tools |
| `pii_protection.rego` | Block access to PII fields without the right scope |
| `read_only.rego` | Enforce read-only mode for specific roles |
| `cost_cap.rego` | Deny calls when session cost budget is exhausted |
| `rate_limiting.rego` | Cap tool calls per session |

### CLI tools

```bash
# Compile YAML to Rego
kitelogik compile policies/my_rules.yaml

# Check Rego syntax
kitelogik validate

# Run all OPA tests
kitelogik test -v

# Dry-run a governance event against policies
kitelogik check '{"action":"approve_refund","tool_name":"approve_refund","args":{"amount":50},"context":{"session_id":"s1","user_role":"support_agent","session_scopes":["approve_refund"],"sandbox_verified":false}}'

# Governance compliance audit (OWASP ASI mapping)
kitelogik compliance
```

### Interactive development

```bash
python -m kitelogik.policy_tester
```

Live Rego editing with immediate feedback — modify a rule, see the decision change.

---

## 2-Tier Policy Hierarchy

For teams that need global (org-wide) and project-specific policies evaluated together, the `HierarchicalEvaluator` merges decisions from two policy tiers with deny-overrides semantics.

```python
from kitelogik.tether.hierarchy import HierarchicalEvaluator
from kitelogik.tether.opa_client import OPAClient

# Two separate OPA packages (or Regorus instances)
global_engine = OPAClient(base_url="http://opa:8181", package="kitelogik.global")
project_engine = OPAClient(base_url="http://opa:8181", package="kitelogik.project")

evaluator = HierarchicalEvaluator(
    global_evaluator=global_engine,
    project_evaluator=project_engine,
)

# Use as a drop-in PolicyEvaluator
gate = PolicyGate(opa_client=evaluator)
```

**Merge rules:**
- A global deny always wins — project policies can only further restrict, never loosen
- Global deny short-circuits: project evaluation is skipped entirely (performance optimization)
- Risk tier takes the higher of the two tiers
- HITL required if either tier requires it
- Every decision includes a `resolution_trace` showing what each tier decided

```python
decision = await gate.evaluate_tool_call(tool_call, context)
for step in decision.resolution_trace:
    print(f"  [{step.tier}] allow={step.allow} deny={step.deny} reason={step.reason}")
```

---

## Compliance CLI

Validate your policy set against governance best practices and OWASP Agentic Security Initiative controls:

```bash
kitelogik compliance
```

Output includes:
- **Default-deny posture** — checks that all policy files declare `default deny` or `default allow`
- **Event type coverage** — validates all 5 governance event types are covered (tool_call, agent.spawn, agent.delegate, agent.plan, agent.budget)
- **Test coverage** — checks that every policy file has a corresponding `_test.rego`
- **OWASP ASI mapping** — maps your policies to 10 OWASP Agentic Security controls (ASI-01 through ASI-10)

```
  PASS  Default-deny posture: all policy files declare defaults
  PASS  Event coverage: all 5 governance event types covered
  PASS  Test coverage: all policy files have corresponding tests
  PASS  OWASP Agentic Security: 10/10 controls addressed
```

---

## Quickstart

The fastest path from zero to a working demo:

```bash
# 1. Clone and install
git clone https://github.com/kitelogik/kitelogik.git
cd kitelogik
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 2. Run the guided walkthrough (no API key needed)
python quickstart.py

# 3. Run the full 13-scenario demo with live dashboard
#    (requires ANTHROPIC_API_KEY in .env and OPA running)
cp .env.example .env
make demo
```

**Alternative: OPA server** (for team-wide policy management):

```bash
pip install -e .
opa run --server policies/             # or: docker compose up -d opa
python quickstart.py
```

The quickstart evaluates three tool calls and shows each possible outcome:
- **ALLOW** — read-only lookup, auto-approved by policy
- **HITL** — high-value refund, escalated for human review
- **BLOCK** — unsandboxed shell execution, hard denied

---

## Integration Decision Tree

```
Do you have existing tool functions?
├── Yes → Do you use a supported framework?
│         │   (OpenAI, LangChain, CrewAI, OpenAI Agents SDK, LangGraph,
│         │    Google ADK, PydanticAI, LlamaIndex, Semantic Kernel,
│         │    Haystack, Dify)
│         ├── Yes → Level 2: Framework adapter
│         └── No  → Level 1: @governed decorator or GovernedToolbox
│
└── No → Are you building a new agent from scratch?
         ├── Yes, using Claude → Level 3: AgentSession
         ├── Yes, using another LLM → Level 2 adapter + your own session loop
         └── Multiple agents, centralized enforcement → Level 4: Gateway

Do you know Rego?
├── No  → Start with YAML policies (kitelogik compile)
└── Yes → Write Rego directly in policies/
```

---

## What Runs Where

| Component | What it does | Required for |
|---|---|---|
| OPA or Regorus | Evaluates Rego policies | All levels (choose one) |
| `PolicyGate` | Sends events to policy engine, enforces decisions | All levels |
| `@governed` / `GovernedToolbox` | Wraps tool functions with governance | Level 1 |
| Framework adapters | Translates framework tool formats | Level 2 |
| `CredentialBroker` | Issues and validates session tokens | Level 3+ |
| `HITLQueue` | Queues actions for human review | Level 3+ |
| `SandboxManager` | Spawns/tears down Docker containers | Level 3+ (optional) |
| `AuditStore` | Immutable audit log | Level 3+ (optional) |
| `MemoryStore` | Agent memory with provenance | Level 3+ (optional) |
| `AgentSession` | Full governed agent loop (Claude) | Level 3 |
| `Orchestrator` | Multi-agent delegation | Level 3 |
| Gateway server | Centralized HTTP enforcement | Level 4 |
| Dashboard | Real-time UI for HITL and monitoring | Level 3+ (optional) |

Level 3 components are modular — pass `None` for any you don't need:

```python
# Minimal Level 3 — just governance + credentials, no sandbox or audit
session = AgentSession(
    gate=gate,
    context=ctx,
    credential_broker=broker,
    hitl_queue=queue,
    # sandbox_manager=None    ← no sandbox
    # audit_store=None        ← no audit
    # memory_store=None       ← no memory
)
```

---

## Which LLM Can I Use?

Kite Logik's governance layer has no knowledge of which model generates tool calls. It receives a tool name and arguments, evaluates them against OPA policy, and returns allow/escalate/block. The LLM provider only matters for the reasoning loop — the part that decides *which* tools to call.

| Integration level | LLM support | Why |
|---|---|---|
| **Level 1** — `@governed`, `GovernedToolbox` | Any | Wraps plain Python functions. No LLM dependency. |
| **Level 2** — Framework adapters | Any model supported by the framework | 11 adapters: OpenAI, LangChain, CrewAI, OpenAI Agents SDK, LangGraph, Google ADK, PydanticAI, LlamaIndex, Semantic Kernel, Haystack, Dify. Each works with any model the framework supports. |
| **Level 3** — `AgentSession` | Claude only | The reasoning loop imports the Anthropic SDK. |
| **Level 4** — Governance Gateway | Any | HTTP API. Any agent that can make a POST request can use it. |

### What's provider-agnostic vs what's coupled

Every governance primitive is provider-agnostic:

- `PolicyGate` — OPA evaluation, response sanitization
- `CredentialBroker` — session token lifecycle (issue, validate, revoke, delegate)
- `HITLQueue` — human-in-the-loop escalation and blocking waits
- `AuditStore` — immutable audit log
- `SandboxManager` — container lifecycle
- `MemoryStore` — agent memory with provenance
- `Orchestrator` — multi-agent delegation (uses `AgentSession` internally, so currently Claude)

The only Anthropic-specific piece is the reasoning loop inside `AgentSession` — the code that sends a prompt to Claude, parses the response, extracts tool calls, and iterates. Everything that happens *around* that loop (policy evaluation, credential checks, HITL blocking, sandbox management, audit recording) is model-independent.

### Using GPT-4o, Llama, or other models with full governance

If you want the complete governance surface (credentials, HITL, sandbox, audit) with a non-Claude model, compose the primitives around your own agent loop:

```python
from kitelogik import (
    PolicyGate, OPAClient, SessionContext, CredentialBroker,
    HITLQueue, GovernedToolbox,
)
from kitelogik.adapters.openai import OpenAIAdapter
from kitelogik.audit.store import AuditStore
import openai

# Set up governance primitives (all provider-agnostic)
broker = CredentialBroker()
gate   = PolicyGate(opa_client=OPAClient(), credential_broker=broker)
queue  = HITLQueue()
audit  = AuditStore()
await queue.setup()
await audit.setup()

# Issue scoped credentials
token = broker.issue("sess_001", scopes=["read_customer", "approve_refund"], ttl_seconds=3600)
ctx = SessionContext(
    session_id="sess_001",
    user_role="support_agent",
    session_scopes=token.scopes,
    token_id=token.token_id,
)

# Use the OpenAI adapter for tool dispatch
adapter = OpenAIAdapter(gate=gate, context=ctx)
adapter.register("read_customer", read_customer_fn, schema={...})
adapter.register("approve_refund", approve_refund_fn, schema={...})

# Your own agent loop — GPT-4o, Llama, Mistral, anything
client = openai.AsyncOpenAI()
messages = [{"role": "user", "content": "Process refund for cust_001"}]

try:
    while True:
        response = await client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            tools=adapter.openai_tool_schemas(),
        )
        choice = response.choices[0]
        if choice.finish_reason != "tool_calls":
            break
        messages.append(choice.message)
        tool_results = await adapter.execute_all(choice.message.tool_calls)
        messages.extend(tool_results)
finally:
    # Same cleanup guarantees as AgentSession
    broker.revoke(token.token_id)
```

This gives you policy enforcement, credential lifecycle, and response sanitization with GPT-4o. Add HITL blocking and audit recording by calling `queue.enqueue()` and `audit.record()` at the appropriate points in your loop. The governance primitives are the same ones `AgentSession` uses internally — you're just driving the reasoning loop yourself.
