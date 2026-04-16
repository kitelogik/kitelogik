# Integrating Kite Logik with Any Agent Framework

If your framework isn't listed here, the `GovernedToolbox` gives you a framework-agnostic integration point that works wherever tools are dispatched as `(name, args_dict)` pairs.

## The universal pattern

```python
from kitelogik import OPAClient, PolicyGate, SessionContext
from kitelogik import GovernedToolbox, GovernanceError

# 1. Configure governance (once per process)
gate = PolicyGate(opa_client=OPAClient())

# 2. Create a context per session
context = SessionContext(
    session_id="sess_001",
    user_role="support_agent",
    session_scopes=["read_customer", "approve_refund_under_100"],
)

# 3. Register your tools
toolbox = GovernedToolbox(gate=gate, context=context)
toolbox.register("get_customer_record", get_customer_record_fn)
toolbox.register("approve_refund",      approve_refund_fn)

# 4. In your framework's tool dispatch hook:
result = await toolbox.call("approve_refund", {"customer_id": "c1", "amount": 50})
```

That's the entire integration. Replace step 4 with whatever your framework calls to execute a tool.

## CrewAI

```python
from crewai import Agent, Task, Crew
from crewai.tools import BaseTool
from kitelogik import GovernedToolbox, GovernanceError

toolbox = GovernedToolbox(gate=gate, context=context)
toolbox.register("search_docs", search_docs_fn)

class GovernedSearchTool(BaseTool):
    name: str = "search_docs"
    description: str = "Search internal documentation."

    def _run(self, query: str) -> str:
        try:
            return toolbox.call_sync("search_docs", {"query": query})
        except GovernanceError as e:
            return f"Blocked: {e}"

agent = Agent(role="researcher", tools=[GovernedSearchTool()])
```

## AutoGen

```python
import autogen
from kitelogik import GovernedToolbox

toolbox = GovernedToolbox(gate=gate, context=context)
toolbox.register("get_customer_record", get_customer_record_fn)

# Register as an AutoGen function
async def governed_get_customer_record(customer_id: str) -> str:
    return await toolbox.call("get_customer_record", {"customer_id": customer_id})

assistant = autogen.AssistantAgent(
    name="assistant",
    llm_config={
        "functions": [{
            "name": "get_customer_record",
            "description": "Look up a customer.",
            "parameters": {
                "type": "object",
                "properties": {"customer_id": {"type": "string"}},
                "required": ["customer_id"],
            },
        }]
    },
)

user_proxy = autogen.UserProxyAgent(
    name="user_proxy",
    function_map={"get_customer_record": governed_get_customer_record},
)
```

## Haystack

```python
from haystack.components.tools import Tool
from kitelogik import GovernedToolbox

toolbox = GovernedToolbox(gate=gate, context=context)
toolbox.register("web_search", web_search_fn)

def governed_web_search(query: str) -> str:
    return toolbox.call_sync("web_search", {"query": query})

search_tool = Tool(
    name="web_search",
    description="Search the web.",
    function=governed_web_search,
    parameters={"query": {"type": "str", "description": "search query"}},
)
```

## Raw tool dispatch loop (any framework)

If your framework gives you a `(tool_name, args_dict)` tuple from the model response, plug governance in at the dispatch point:

```python
async def dispatch(tool_name: str, args: dict) -> str:
    try:
        return await toolbox.call(tool_name, args)
    except GovernanceError as e:
        # Return denial to the model — don't raise
        return f"[BLOCKED] {e.decision.reason}"
    except KeyError:
        return f"[ERROR] Unknown tool: {tool_name}"
```

## The @governed decorator (function-level)

For finer control, govern individual functions rather than routing through a toolbox:

```python
from kitelogik import governed, GovernanceError

@governed(gate=gate, context=context)
async def approve_refund(customer_id: str, amount: float) -> str:
    return await payment_api.refund(customer_id, amount)

# Call it from anywhere — governance runs first
try:
    result = await approve_refund("cust_001", 50.0)
except GovernanceError as e:
    print(f"Risk tier: {e.decision.risk_tier}")
    print(f"Reason: {e.decision.reason}")
```

The decorator works with sync and async functions and is framework-agnostic.

## Checking the decision before executing

If you need to inspect the policy decision before acting on it:

```python
from kitelogik import ToolCallInput

tool_call = ToolCallInput(
    action="approve_refund",
    tool_name="approve_refund",
    args={"customer_id": "cust_001", "amount": 5000.0},
)
decision = await gate.evaluate_tool_call(tool_call, context)

print(decision.allow)          # False
print(decision.requires_hitl)  # True  — escalate to human
print(decision.risk_tier)      # TRANSACTIONAL_HIGH
print(decision.reason)         # "Amount exceeds auto-approval limit"
```

Use this pattern when your framework needs to handle HITL escalation natively rather than raising an exception.
