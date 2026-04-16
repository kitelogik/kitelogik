# SPDX-License-Identifier: Apache-2.0
"""Tests for the MCP stdio transport."""

import asyncio

import pytest

from kitelogik.mcp.stdio_transport import StdioTransport, StdioTransportError


def test_transport_not_running_by_default():
    transport = StdioTransport(command=["echo", "test"])
    assert transport.is_running is False


async def test_send_request_when_not_running():
    transport = StdioTransport(command=["echo", "test"])
    with pytest.raises(StdioTransportError, match="not running"):
        await transport.send_request("tools/list")


async def test_send_notification_when_not_running():
    transport = StdioTransport(command=["echo", "test"])
    with pytest.raises(StdioTransportError, match="not running"):
        await transport.send_notification("initialized")


async def test_start_and_stop():
    """Start a simple process and stop it cleanly."""
    transport = StdioTransport(command=["cat"], startup_timeout=5.0)
    await transport.start()
    assert transport.is_running is True

    await transport.stop()
    assert transport.is_running is False


async def test_stop_idempotent():
    """Stopping an already-stopped transport is safe."""
    transport = StdioTransport(command=["echo", "test"])
    await transport.stop()  # Should not raise


async def test_start_idempotent():
    """Starting an already-running transport is safe."""
    transport = StdioTransport(command=["cat"])
    await transport.start()
    await transport.start()  # Should not raise or restart
    assert transport.is_running is True
    await transport.stop()


async def test_request_timeout():
    """Request times out when the server doesn't respond."""
    # Use a process that reads stdin but produces no stdout (cat echoes back)
    transport = StdioTransport(command=["bash", "-c", "cat > /dev/null"], request_timeout=0.1)
    await transport.start()

    try:
        with pytest.raises(StdioTransportError, match="timed out"):
            await transport.send_request("tools/list", timeout=0.1)
    finally:
        await transport.stop()


async def test_stop_cancels_pending_requests():
    """Stopping transport cancels pending futures."""
    # Use a process that reads stdin but produces no stdout
    transport = StdioTransport(command=["bash", "-c", "cat > /dev/null"], request_timeout=10.0)
    await transport.start()

    # Start a request that will never get a response
    task = asyncio.create_task(transport.send_request("tools/list"))
    await asyncio.sleep(0.05)  # Let it send

    await transport.stop()

    with pytest.raises(StdioTransportError):
        await task
