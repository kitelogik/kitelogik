# SPDX-License-Identifier: Apache-2.0
"""
Tests for MCPClient and ServerRegistry.

MCPClient HTTP calls are mocked with respx so no real server is needed.
"""

import json

import pytest
import respx
from httpx import Response

from kitelogik.mcp.client import MCPCallError, MCPClient
from kitelogik.mcp.models import MCPServer
from kitelogik.mcp.registry import ServerRegistry

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_server() -> MCPServer:
    return MCPServer(
        name="test-server",
        endpoint="http://localhost:8200",
        version="1.0.0",
        sha256="test-sha",
        tools=["read_customer_record", "approve_refund"],
        approved_by="test",
        approved_at="2026-03-19",
    )


@pytest.fixture
def registry(mock_server, tmp_path):
    bom_path = tmp_path / "registry.json"
    bom_path.write_text(
        json.dumps(
            {
                "version": "1.0",
                "servers": [mock_server.model_dump()],
            }
        )
    )
    return ServerRegistry(bom_path=str(bom_path))


@pytest.fixture
def client(registry):
    return MCPClient(registry=registry)


# ── Registry tests ────────────────────────────────────────────────────────────


def test_registry_loads_server(registry):
    servers = registry.list_servers()
    assert len(servers) == 1
    assert servers[0].name == "test-server"


def test_registry_tool_lookup(registry):
    server = registry.get_server_for_tool("read_customer_record")
    assert server is not None
    assert server.name == "test-server"


def test_registry_unknown_tool_returns_none(registry):
    assert registry.get_server_for_tool("nonexistent_tool") is None


def test_registry_is_registered(registry):
    assert registry.is_registered("read_customer_record")
    assert not registry.is_registered("delete_everything")


# ── MCPClient tests ───────────────────────────────────────────────────────────


@respx.mock
async def test_client_successful_call(client):
    expected = {"customer_id": "cust_001", "name": "Alice Johnson"}
    respx.post("http://localhost:8200/rpc").mock(
        return_value=Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": "1",
                "result": {
                    "content": [{"type": "text", "text": json.dumps(expected)}],
                    "isError": False,
                },
            },
        )
    )

    result = await client.call_tool("read_customer_record", {"customer_id": "cust_001"})
    assert not result.is_error
    assert len(result.content) == 1
    assert "Alice Johnson" in result.content[0].text


@respx.mock
async def test_client_unregistered_tool_raises(client):
    with pytest.raises(MCPCallError, match="not registered"):
        await client.call_tool("delete_everything", {})


@respx.mock
async def test_client_server_error_response(client):
    respx.post("http://localhost:8200/rpc").mock(
        return_value=Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": "1",
                "error": {"code": -32602, "message": "Unknown tool"},
            },
        )
    )

    result = await client.call_tool("read_customer_record", {})
    assert result.is_error
    assert "Unknown tool" in result.content[0].text


@respx.mock
async def test_client_http_error_raises(client):
    respx.post("http://localhost:8200/rpc").mock(
        return_value=Response(500, text="Internal Server Error")
    )

    with pytest.raises(MCPCallError, match="HTTP 500"):
        await client.call_tool("read_customer_record", {})


@respx.mock
async def test_client_connection_error_raises(client):
    import httpx

    respx.post("http://localhost:8200/rpc").mock(side_effect=httpx.ConnectError("refused"))

    with pytest.raises(MCPCallError, match="Cannot reach"):
        await client.call_tool("read_customer_record", {})


@respx.mock
async def test_result_to_text(client):
    respx.post("http://localhost:8200/rpc").mock(
        return_value=Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": "1",
                "result": {
                    "content": [
                        {"type": "text", "text": "line one"},
                        {"type": "text", "text": "line two"},
                    ],
                    "isError": False,
                },
            },
        )
    )

    result = await client.call_tool("read_customer_record", {})
    text = client.result_to_text(result)
    assert "line one" in text
    assert "line two" in text
