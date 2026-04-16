# Integrating Kite Logik with OpenAI

Kite Logik governance can be added to an existing OpenAI function-calling agent in under 10 lines. No changes to your model, messages, or API client are needed — only tool execution is intercepted.

## Prerequisites

```bash
pip install -e ".[dev]"    # kitelogik
pip install openai
docker compose up -d opa   # policy engine
```

## Quickstart

```python
import json
import asyncio
import openai
from kitelogik import OPAClient, PolicyGate, SessionContext
from kitelogik.adapters.openai import OpenAIAdapter

# 1. Configure governance
gate    = PolicyGate(opa_client=OPAClient())
context = SessionContext(
    session_id="sess_001",
    user_role="support_agent",
    session_scopes=["read_customer", "approve_refund_under_100"],
)

# 2. Your existing tool functions — unchanged
def get_customer_record(customer_id: str) -> str:
    return f'{{"id": "{customer_id}", "name": "Jane Smith", "status": "active"}}'

def approve_refund(customer_id: str, amount: float) -> str:
    return f'{{"status": "approved", "amount": {amount}, "customer": "{customer_id}"}}'

# 3. Register tools with the adapter
adapter = OpenAIAdapter(gate=gate, context=context)
adapter.register(
    "get_customer_record",
    get_customer_record_fn,
    schema={
        "name": "get_customer_record",
        "description": "Look up a customer record by ID.",
        "parameters": {
            "type": "object",
            "properties": {"customer_id": {"type": "string"}},
            "required": ["customer_id"],
        },
    },
)
adapter.register(
    "approve_refund",
    approve_refund_fn,
    schema={
        "name": "approve_refund",
        "description": "Approve a refund for a customer.",
        "parameters": {
            "type": "object",
            "properties": {
                "customer_id": {"type": "string"},
                "amount":      {"type": "number"},
            },
            "required": ["customer_id", "amount"],
        },
    },
)

# 4. Your existing OpenAI agent loop — two lines changed
async def run_agent(prompt: str) -> str:
    client   = openai.AsyncOpenAI()
    messages = [{"role": "user", "content": prompt}]

    while True:
        response = await client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            tools=adapter.openai_tool_schemas(),   # ← was: your manual tool list
        )
        choice = response.choices[0]

        if choice.finish_reason != "tool_calls":
            return choice.message.content

        messages.append(choice.message)
        tool_results = await adapter.execute_all(choice.message.tool_calls)  # ← was: manual dispatch
        messages.extend(tool_results)

asyncio.run(run_agent("Refund $50 to customer cust_001"))
```

That's it. The two changed lines are:
- `tools=adapter.openai_tool_schemas()` — returns your registered schemas
- `await adapter.execute_all(...)` — executes tool calls through the governance pipeline

## What happens to blocked calls

When a call is denied by policy, the model receives a structured denial rather than a Python exception:

```json
{"blocked": true, "reason": "Action blocked by governance policy."}
```

The agent loop continues. The model sees the denial and responds accordingly (e.g. "I'm unable to process that refund — it exceeds the authorised limit.").

To customize the denial message:

```python
adapter = OpenAIAdapter(
    gate=gate,
    context=context,
    deny_message="This action requires manager approval.",
)
```

## Executing tool calls one at a time

```python
# execute() handles a single tool call
result = await adapter.execute(tool_call)
messages.append(result)
```

`execute_all()` runs them concurrently with `asyncio.gather`. If you need sequential execution (e.g. one tool's output feeds the next's args), use `execute()` in a loop.

## Using the @governed decorator instead

If you prefer to govern individual functions rather than an agent loop:

```python
from kitelogik import governed, GovernanceError

@governed(gate=gate, context=context)
async def approve_refund(customer_id: str, amount: float) -> str:
    return payment_api.refund(customer_id, amount)

try:
    result = await approve_refund("cust_001", 50.0)
except GovernanceError as e:
    print(f"Blocked: {e.decision.reason}")
    print(f"Risk tier: {e.decision.risk_tier}")
```

The decorator works regardless of which agent framework calls the function.

## Policy configuration

The adapter uses `user_role` and `session_scopes` from your `SessionContext` to evaluate policies. The `kitelogik/policies/` directory controls what each role can do:

```rego
# policies/financial.rego
allow if {
    input.action == "approve_refund"
    "approve_refund_under_100" in input.context.session_scopes
    input.context.user_role in {"support_agent", "manager"}
    input.args.amount <= 100
}
```

Test policy changes without touching agent code:

```bash
python -m kitelogik.policy_tester \
  --policy policies/financial.rego \
  --input '{"action": "approve_refund", "args": {"amount": 50}, "context": {"user_role": "support_agent", "session_scopes": ["approve_refund_under_100"]}}'
```

## Next steps

- [Risk tiers and HITL escalation](../architecture.md#three-enforcement-layers)
- [Writing policies](../../kitelogik/policies/examples/)
- [LangChain integration](langchain.md)
