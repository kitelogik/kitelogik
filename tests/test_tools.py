# SPDX-License-Identifier: Apache-2.0
"""
Tests for agents.tools — execute_tool() and TOOL_SCHEMAS.
"""

import json

from kitelogik.agents.tools import TOOL_SCHEMAS, execute_tool


def test_read_customer_record_known_customer():
    result = json.loads(execute_tool("read_customer_record", {"customer_id": "cust_001"}))
    assert result["name"] == "Alice Johnson"
    assert result["tier"] == "gold"


def test_read_customer_record_unknown_customer():
    result = json.loads(execute_tool("read_customer_record", {"customer_id": "cust_999"}))
    assert "error" in result
    assert "cust_999" in result["error"]


def test_approve_refund_returns_approved_status():
    result = json.loads(
        execute_tool(
            "approve_refund", {"customer_id": "cust_001", "amount": 50.0, "reason": "Damaged item"}
        )
    )
    assert result["status"] == "approved"
    assert result["customer_id"] == "cust_001"
    assert result["amount"] == 50.0


def test_send_notification_returns_sent_status():
    result = json.loads(
        execute_tool(
            "send_notification", {"customer_id": "cust_002", "message": "Your order is ready"}
        )
    )
    assert result["status"] == "sent"
    assert result["customer_id"] == "cust_002"


def test_read_file_returns_error_message():
    result = json.loads(execute_tool("read_file", {"path": "/etc/passwd"}))
    assert "error" in result
    assert "/etc/passwd" in result["error"]


def test_execute_code_returns_sandbox_output():
    result = json.loads(execute_tool("execute_code", {"code": "print(1+1)"}))
    assert result["exit_code"] == 0
    assert "sandbox" in result["runtime"]


def test_unknown_tool_returns_error():
    result = json.loads(execute_tool("nonexistent_tool", {}))
    assert "error" in result
    assert "nonexistent_tool" in result["error"]


def test_tool_schemas_contains_all_expected_tools():
    names = {s["name"] for s in TOOL_SCHEMAS}
    assert "read_customer_record" in names
    assert "approve_refund" in names
    assert "send_notification" in names
    assert "read_file" in names
    assert "execute_code" in names
    assert "query_memory" in names
    assert "write_memory" in names


def test_tool_schemas_have_required_input_schema_fields():
    for schema in TOOL_SCHEMAS:
        assert "name" in schema
        assert "description" in schema
        assert "input_schema" in schema
        assert schema["input_schema"]["type"] == "object"
