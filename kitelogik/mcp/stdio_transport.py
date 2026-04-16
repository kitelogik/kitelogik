# SPDX-License-Identifier: Apache-2.0
"""
StdioTransport — subprocess-based JSON-RPC transport for MCP servers.

Communicates with MCP servers over stdin/stdout using JSON-RPC 2.0,
per the MCP specification for stdio transport.

Usage
-----
    transport = StdioTransport(command=["npx", "my-mcp-server"])
    await transport.start()

    result = await transport.send_request("tools/list", {})
    print(result)

    await transport.stop()

Supply chain verification still applies: the ServerRegistry BOM check
runs before any tool call is dispatched.
"""

import asyncio
import json
import logging
import uuid

logger = logging.getLogger(__name__)


class StdioTransportError(Exception):
    """Raised when the stdio transport encounters an error."""


class StdioTransport:
    """
    Async JSON-RPC 2.0 transport over stdin/stdout.

    Spawns an MCP server as a subprocess and communicates via stdin/stdout
    using newline-delimited JSON-RPC messages.

    Parameters
    ----------
    command : list[str]
            The command to spawn the MCP server process.
    env : dict[str, str] | None
            Optional environment variables for the subprocess.
    startup_timeout : float
            Seconds to wait for the process to start.
    request_timeout : float
            Default timeout for individual requests.
    """

    def __init__(
        self,
        command: list[str],
        env: dict[str, str] | None = None,
        startup_timeout: float = 10.0,
        request_timeout: float = 30.0,
    ) -> None:
        self._command = command
        self._env = env
        self._startup_timeout = startup_timeout
        self._request_timeout = request_timeout
        self._process: asyncio.subprocess.Process | None = None
        self._pending: dict[str, asyncio.Future] = {}
        self._reader_task: asyncio.Task | None = None

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.returncode is None

    async def start(self) -> None:
        """Start the MCP server subprocess."""
        if self.is_running:
            return

        self._process = await asyncio.create_subprocess_exec(
            *self._command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._env,
        )
        self._reader_task = asyncio.create_task(self._read_loop(), name="stdio_transport_reader")
        logger.info("StdioTransport started: pid=%d cmd=%s", self._process.pid, self._command)

    async def stop(self) -> None:
        """Stop the MCP server subprocess."""
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None

        if self._process:
            self._process.stdin.close()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except TimeoutError:
                self._process.kill()
                await self._process.wait()
            logger.info("StdioTransport stopped: pid=%d", self._process.pid)
            self._process = None

        # Cancel any pending requests
        for future in self._pending.values():
            if not future.done():
                future.set_exception(StdioTransportError("Transport stopped"))
        self._pending.clear()

    async def send_request(
        self,
        method: str,
        params: dict | None = None,
        timeout: float | None = None,
    ) -> dict:
        """
        Send a JSON-RPC request and wait for the response.

        Parameters
        ----------
        method : str
                The JSON-RPC method name (e.g., "tools/list", "tools/call").
        params : dict | None
                Request parameters.
        timeout : float | None
                Override the default request timeout.

        Returns
        -------
        dict
                The "result" field from the JSON-RPC response.

        Raises
        ------
        StdioTransportError
                If the transport is not running, the request times out, or
                the server returns an error.
        """
        if not self.is_running:
            raise StdioTransportError("Transport is not running. Call start() first.")

        request_id = str(uuid.uuid4())
        message = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }

        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future

        line = json.dumps(message) + "\n"
        self._process.stdin.write(line.encode())
        await self._process.stdin.drain()

        try:
            result = await asyncio.wait_for(future, timeout=timeout or self._request_timeout)
        except TimeoutError:
            self._pending.pop(request_id, None)
            raise StdioTransportError(
                f"Request timed out after {timeout or self._request_timeout}s: {method}"
            )

        return result

    async def send_notification(self, method: str, params: dict | None = None) -> None:
        """Send a JSON-RPC notification (no response expected)."""
        if not self.is_running:
            raise StdioTransportError("Transport is not running.")

        message = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }
        line = json.dumps(message) + "\n"
        self._process.stdin.write(line.encode())
        await self._process.stdin.drain()

    async def _read_loop(self) -> None:
        """Read JSON-RPC responses from the subprocess stdout."""
        try:
            while self.is_running:
                line = await self._process.stdout.readline()
                if not line:
                    break

                try:
                    response = json.loads(line.decode().strip())
                except json.JSONDecodeError:
                    logger.warning("Non-JSON line from MCP server: %s", line[:200])
                    continue

                request_id = response.get("id")
                if request_id and request_id in self._pending:
                    future = self._pending.pop(request_id)
                    if "error" in response:
                        error = response["error"]
                        future.set_exception(
                            StdioTransportError(
                                f"JSON-RPC error {error.get('code', '?')}: "
                                f"{error.get('message', '?')}"
                            )
                        )
                    else:
                        future.set_result(response.get("result", {}))
                elif "method" in response:
                    # Server-initiated notification — log and skip
                    logger.debug("MCP server notification: method=%s", response.get("method"))
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("StdioTransport reader loop error")
