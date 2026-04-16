# Integrating Kite Logik with LangChain / LangGraph

Two patterns depending on your starting point:

- **New tools** — use `as_governed_tool()` to wrap a function as a governed `BaseTool`
- **Existing toolkit** — use `govern_toolkit()` to add governance to a list of `BaseTool` instances

Both patterns are drop-in compatible with `create_react_agent`, `AgentExecutor`, LangGraph, and any other LangChain runtime.

## Prerequisites

```bash
pip install -e ".[dev]"    # kitelogik
pip install langchain-core langchain langchain-openai   # or your LLM package
docker compose up -d opa   # policy engine
```

## Pattern 1 — New tool functions

```python
from langchain_openai import ChatOpenAI
from langchain.agents import create_react_agent, AgentExecutor
from kitelogik import OPAClient, PolicyGate, SessionContext
from kitelogik.adapters.langchain import as_governed_tool

# 1. Configure governance
gate    = PolicyGate(opa_client=OPAClient())
context = SessionContext(
    session_id="sess_001",
    user_role="support_agent",
    session_scopes=["read_customer", "approve_refund_under_100"],
)

# 2. Your existing tool functions — unchanged
def get_customer_record(customer_id: str) -> str:
    return f"Customer {customer_id}: Jane Smith, active account"

def approve_refund(customer_id: str, amount: float) -> str:
    return f"Refund of ${amount} approved for {customer_id}"

# 3. Wrap as governed LangChain tools
tools = [
    as_governed_tool(
        name="get_customer_record",
        fn=get_customer_record,
        gate=gate,
        context=context,
        description="Look up a customer record by customer_id.",
    ),
    as_governed_tool(
        name="approve_refund",
        fn=approve_refund,
        gate=gate,
        context=context,
        description="Approve a refund. Args: customer_id (str), amount (float in USD).",
    ),
]

# 4. Use exactly as before — no other changes
llm   = ChatOpenAI(model="gpt-4o")
agent = create_react_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools)
result = executor.invoke({"input": "Refund $50 to customer cust_001"})
```

## Pattern 2 — Govern an existing toolkit

```python
from langchain_community.agent_toolkits import SQLDatabaseToolkit
from kitelogik.adapters.langchain import govern_toolkit

# Existing toolkit — no changes to how you set it up
raw_tools = SQLDatabaseToolkit(db=db, llm=llm).get_tools()

# Wrap all tools with governance in one call
governed_tools = govern_toolkit(raw_tools, gate=gate, context=context)

# Use governed_tools anywhere you would use raw_tools
agent = create_react_agent(llm, governed_tools, prompt)
```

Every tool in `governed_tools` passes through the policy gate before executing. The original tool objects are not mutated.

## Pattern 3 — LangGraph

```python
from langgraph.prebuilt import create_react_agent

# governed tools work directly with LangGraph
graph = create_react_agent(llm, tools=governed_tools)
result = graph.invoke({"messages": [("user", "Refund $50 to cust_001")]})
```

## What blocked calls look like to the agent

When a call is denied by policy, the tool returns a `[BLOCKED]` message rather than raising an exception. The agent loop continues; the model handles the refusal gracefully.

```
Observation: [BLOCKED] Tool 'approve_refund' denied by policy: amount exceeds auto-approval limit
Thought: I need to escalate this to a manager...
```

This keeps your agent loop clean — no try/except around tool calls needed.

## Using @governed for inline functions

For simple cases where you define the tool inline:

```python
from kitelogik import governed, GovernanceError

@governed(gate=gate, context=context)
def search_knowledge_base(query: str) -> str:
    return vector_db.search(query)

# Then wrap as a LangChain tool the normal way
from langchain_core.tools import tool

@tool
@governed(gate=gate, context=context)
def governed_search(query: str) -> str:
    """Search the internal knowledge base."""
    return vector_db.search(query)
```

Note: stack `@governed` *below* `@tool` so governance runs before LangChain's tool machinery.

## Async agents

`as_governed_tool()` registers both `_run` (sync) and `_arun` (async) on the returned tool. Async agents and chains call `_arun` automatically:

```python
# Works with async agent executors
result = await executor.ainvoke({"input": "..."})
```

## Per-session context

In production, each user session should have its own `SessionContext` with scoped credentials:

```python
from kitelogik import CredentialBroker

broker = CredentialBroker()

def create_session_tools(session_id: str, user_role: str, scopes: list[str]):
    token = broker.issue(session_id=session_id, scopes=scopes, ttl_seconds=300)
    context = SessionContext(
        session_id=session_id,
        user_role=user_role,
        session_scopes=token.scopes,
        token_id=token.token_id,
    )
    return [
        as_governed_tool("get_customer_record", get_customer_record, gate, context, "..."),
        as_governed_tool("approve_refund", approve_refund, gate, context, "..."),
    ], token

# Per request:
tools, token = create_session_tools("sess_abc", "support_agent", ["read_customer"])
try:
    result = executor.invoke({"input": user_message})
finally:
    broker.revoke(token.token_id)   # always revoke when done
```

## Policy configuration

Add your tool names to the relevant role in `kitelogik/policies/` and they will be governed automatically:

```rego
# policies/financial.rego
allow if {
    input.action == "approve_refund"
    "approve_refund_under_100" in input.context.session_scopes
    input.context.user_role in {"support_agent", "manager"}
    input.args.amount <= 100
}
```

```bash
# Test before deploying
python -m kitelogik.policy_tester \
  --policy policies/financial.rego \
  --input '{"action":"approve_refund","args":{"amount":50},"context":{"user_role":"support_agent","session_scopes":["approve_refund_under_100"]}}'
```

## Next steps

- [OpenAI integration](openai.md)
- [Risk tiers and HITL escalation](../architecture.md#three-enforcement-layers)
- [Writing policies](../../kitelogik/policies/examples/)
