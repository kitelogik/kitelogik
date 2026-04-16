# SPDX-License-Identifier: Apache-2.0
"""
Mock tool implementations for Phase 1 demo.

Each tool has:
  - A schema (ToolParam) passed to the Anthropic API so the model knows what's available
  - An executor function that returns a JSON string result

In Phase 2, these are replaced by real MCP server integrations.
"""

import json
from typing import Any

from anthropic.types import ToolParam

_MOCK_CUSTOMERS: dict[str, dict[str, Any]] = {
    "cust_001": {
        "id": "cust_001",
        "name": "Alice Johnson",
        "email": "alice@example.com",
        "tier": "gold",
        "total_orders": 47,
    },
    "cust_002": {
        "id": "cust_002",
        "name": "Bob Smith",
        "email": "bob@example.com",
        "tier": "silver",
        "total_orders": 12,
    },
}

TOOL_SCHEMAS: list[ToolParam] = [
    {
        "name": "read_customer_record",
        "description": "Read a customer record by ID. Returns name, email, tier, and order count.",
        "input_schema": {
            "type": "object",
            "properties": {
                "customer_id": {"type": "string", "description": "The customer ID (e.g. cust_001)"},
            },
            "required": ["customer_id"],
        },
    },
    {
        "name": "approve_refund",
        "description": (
            "Approve a refund for a customer order. "
            "Subject to policy limits: support agents up to $100, managers up to $1000."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "customer_id": {"type": "string", "description": "The customer ID"},
                "amount": {"type": "number", "description": "Refund amount in USD"},
                "reason": {"type": "string", "description": "Reason for the refund"},
            },
            "required": ["customer_id", "amount", "reason"],
        },
    },
    {
        "name": "send_notification",
        "description": "Send a notification message to a customer via email.",
        "input_schema": {
            "type": "object",
            "properties": {
                "customer_id": {"type": "string", "description": "The customer ID"},
                "message": {"type": "string", "description": "Message to send to the customer"},
            },
            "required": ["customer_id", "message"],
        },
    },
    {
        "name": "read_file",
        "description": "Read the contents of a file at the given path.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "execute_code",
        "description": (
            "Execute Python code inside the session sandbox and return the output. "
            "Requires an active verified sandbox (sandbox_verified=true). "
            "Blocked by policy if no sandbox is present."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Python expression or statement to run"},
            },
            "required": ["code"],
        },
    },
    {
        "name": "query_memory",
        "description": "Retrieve a previously stored fact from the agent memory store by key.",
        "input_schema": {
            "type": "object",
            "properties": {
                "key": {"type": "string", "description": "The memory key to look up"},
            },
            "required": ["key"],
        },
    },
    {
        "name": "write_memory",
        "description": "Store a fact in the agent memory store for later recall.",
        "input_schema": {
            "type": "object",
            "properties": {
                "key": {"type": "string", "description": "The memory key"},
                "value": {"type": "string", "description": "The value to store"},
            },
            "required": ["key", "value"],
        },
    },
]


def execute_tool(tool_name: str, args: dict[str, Any]) -> str:
    """
    Execute a tool by name and return a JSON string result.

    Parameters
    ----------
    tool_name : str
            Name of the tool to execute.
    args : dict of str to Any
            Arguments to pass to the tool executor.

    Returns
    -------
    str
            JSON-encoded result string.
    """
    if tool_name == "read_customer_record":
        customer_id = args.get("customer_id", "")
        customer = _MOCK_CUSTOMERS.get(customer_id)
        if customer:
            return json.dumps(customer)
        return json.dumps({"error": f"Customer '{customer_id}' not found"})

    if tool_name == "approve_refund":
        return json.dumps(
            {
                "status": "approved",
                "customer_id": args.get("customer_id"),
                "amount": args.get("amount"),
                "currency": "USD",
                "transaction_id": "txn_mock_12345",
                "message": "Refund approved and queued for processing.",
            }
        )

    if tool_name == "send_notification":
        return json.dumps(
            {
                "status": "sent",
                "customer_id": args.get("customer_id"),
                "message_id": "msg_mock_67890",
            }
        )

    if tool_name == "read_file":
        # This executor is only reached if the policy gate allows the call.
        # In practice, any sensitive path is hard-blocked before getting here.
        path = args.get("path", "")
        return json.dumps({"error": f"File read not permitted: '{path}'"})

    if tool_name == "execute_code":
        # Only reached when sandbox_verified=True has passed the policy gate.
        # Returns a mock result referencing the sandbox container.
        code = args.get("code", "")
        return json.dumps(
            {
                "output": f"[sandbox] executed: {code}",
                "exit_code": 0,
                "runtime": "docker-sandbox",
            }
        )

    return json.dumps({"error": f"Unknown tool: '{tool_name}'"})
