# SPDX-License-Identifier: Apache-2.0
"""
MCPClient — async JSON-RPC 2.0 client for MCP tool servers.

Only calls tools listed in the ServerRegistry (BOM). Responses are
returned as MCPToolResult for the sanitizer to process before the
content is injected back into the agent context.

Supply chain integrity: call verify_manifests() at startup to confirm
each registered server's tool list matches the registry snapshot hash.
Servers with manifest mismatches are blocked from receiving tool calls.
"""

import hashlib
import json
import logging
import uuid

import httpx

from kitelogik.tether.sanitizer import sanitize_tool_output

from .models import MCPContent, MCPServer, MCPToolResult, MCPVerificationStatus
from .registry import ServerRegistry

logger = logging.getLogger(__name__)

_SKIP_VERIFICATION_SENTINELS = {"", "dev-placeholder"}


class MCPCallError(Exception):
    pass


class MCPSupplyChainError(Exception):
    """
      Raised when a registered MCP server's tool manifest does not match the
      hash recorded in registry.json at snapshot time.

      This indicates either:
    - The server was updated/replaced without updating the BOM
    - A supply chain compromise: the server is serving unexpected tools

      Do not call tools on this server until the registry is reviewed and updated.
    """

    pass


class MCPClient:
    """
    Thin async HTTP client that wraps MCP tool invocation.

    All calls are validated against the ``ServerRegistry`` before dispatch.
    The transport is plain JSON-RPC 2.0 over HTTP POST.

    Supply chain protection: call ``verify_manifests()`` after init. Any server
    whose tool list hash doesn't match the registry is added to the blocklist
    and will raise ``MCPSupplyChainError`` on attempted use.

    Parameters
    ----------
    registry : ServerRegistry
            The MCP server registry (BOM).
    timeout : float
            HTTP request timeout in seconds.
    """

    def __init__(
        self,
        registry: ServerRegistry,
        timeout: float = 10.0,
    ) -> None:
        self._registry = registry
        self._timeout = timeout
        self._blocked_servers: set[str] = set()  # server names blocked by manifest mismatch
        self._verification_results: list[MCPVerificationStatus] = []

    @staticmethod
    def _hash_tool_names(tool_names: list[str]) -> str:
        """Canonical hash of a sorted tool-name list. Deterministic across runs."""
        canonical = json.dumps(sorted(tool_names), separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    async def _fetch_manifest_hash(self, server: MCPServer) -> tuple[str, str | None]:
        """
        Fetch the tool manifest from ``server`` via tools/list.

        Returns
        -------
        tuple[str, str | None]
                ``(actual_hash, error_string)``. Returns ``(None, error)`` on failure.
        """
        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "tools/list",
            "params": {},
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{server.endpoint}/rpc",
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
        except httpx.ConnectError as e:
            return None, f"Cannot reach {server.endpoint}: {e}"
        except httpx.TimeoutException:
            return None, f"Timed out connecting to {server.endpoint}"

        if resp.status_code != 200:
            return None, f"HTTP {resp.status_code} from {server.endpoint}"

        try:
            body = resp.json()
            tools = body.get("result", {}).get("tools", [])
            tool_names = [t["name"] for t in tools if "name" in t]
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            return None, f"Failed to parse tools/list response: {e}"

        return self._hash_tool_names(tool_names), None

    async def verify_manifests(self) -> list[MCPVerificationStatus]:
        """
        Verify each registered server's tool manifest against the registry hash.

        Servers with ``sha256_manifest == ""`` or ``"dev-placeholder"`` are skipped
        (development/staging environments where the manifest is not yet locked).

        Any server whose actual hash differs from the registered hash is added to
        the internal blocklist. Subsequent ``call_tool()`` calls to that server
        raise ``MCPSupplyChainError`` without making a network request.

        Returns
        -------
        list[MCPVerificationStatus]
                Verification status for each server (including skipped ones).
        """
        results: list[MCPVerificationStatus] = []

        for server in self._registry.list_servers():
            registered_hash = server.sha256_manifest

            if registered_hash in _SKIP_VERIFICATION_SENTINELS:
                logger.warning(
                    "MCP manifest verification skipped for '%s' (no hash in registry). "
                    "Update registry.json with sha256_manifest before production use.",
                    server.name,
                )
                results.append(
                    MCPVerificationStatus(
                        server_name=server.name,
                        endpoint=server.endpoint,
                        registered_hash=registered_hash,
                        actual_hash=None,
                        match=True,  # treat as pass when skipped
                        error="verification skipped — no manifest hash registered",
                    )
                )
                continue

            actual_hash, error = await self._fetch_manifest_hash(server)
            match = actual_hash is not None and actual_hash == registered_hash

            if not match and error is None:
                # Manifest mismatch — block this server
                self._blocked_servers.add(server.name)
                logger.error(
                    "MCPSupplyChainError: server '%s' manifest hash mismatch. "
                    "Registered: %s  Actual: %s  — server blocked.",
                    server.name,
                    registered_hash[:16],
                    (actual_hash or "?")[:16],
                )
            elif error:
                logger.warning(
                    "MCP manifest verification failed for '%s': %s",
                    server.name,
                    error,
                )

            results.append(
                MCPVerificationStatus(
                    server_name=server.name,
                    endpoint=server.endpoint,
                    registered_hash=registered_hash,
                    actual_hash=actual_hash,
                    match=match,
                    error=error,
                )
            )

        self._verification_results = results
        return results

    def get_verification_status(self) -> list[MCPVerificationStatus]:
        """Return the cached results from the most recent verify_manifests() call."""
        return list(self._verification_results)

    async def call_tool(
        self,
        tool_name: str,
        args: dict,
    ) -> MCPToolResult:
        server = self._registry.get_server_for_tool(tool_name)
        if server is None:
            raise MCPCallError(
                f"Tool '{tool_name}' is not registered in the MCP BOM. "
                "Add it to mcp/registry.json before calling."
            )
        if server.name in self._blocked_servers:
            raise MCPSupplyChainError(
                f"Tool call to '{tool_name}' on server '{server.name}' is blocked: "
                "tool manifest hash mismatch detected during verify_manifests(). "
                "Review mcp/registry.json and re-run verification before unblocking."
            )
        return await self._dispatch(server, tool_name, args)

    async def _dispatch(
        self,
        server: MCPServer,
        tool_name: str,
        args: dict,
    ) -> MCPToolResult:
        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": args},
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            try:
                resp = await client.post(
                    f"{server.endpoint}/rpc",
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
            except httpx.ConnectError as e:
                raise MCPCallError(
                    f"Cannot reach MCP server '{server.name}' at {server.endpoint}: {e}"
                ) from e
            except httpx.TimeoutException as e:
                raise MCPCallError(
                    f"MCP server '{server.name}' timed out after {self._timeout}s"
                ) from e

        if resp.status_code != 200:
            raise MCPCallError(f"MCP server '{server.name}' returned HTTP {resp.status_code}")

        body = resp.json()

        if "error" in body:
            err = body["error"]
            return MCPToolResult(
                content=[MCPContent(type="text", text=str(err.get("message", err)))],
                is_error=True,
            )

        result = body.get("result", {})
        content_list = result.get("content", [])

        sanitized_content: list[MCPContent] = []
        any_modified = False
        all_patterns: list[str] = []
        for c in content_list:
            raw_text = c.get("text", "")
            sr = sanitize_tool_output(raw_text)
            if sr.was_modified:
                any_modified = True
                all_patterns.extend(sr.injection_patterns_found)
                logger.warning(
                    "Indirect prompt injection detected in MCP response from '%s' "
                    "(tool=%s). Patterns redacted: %s",
                    server.name,
                    tool_name,
                    sr.injection_patterns_found,
                )
            sanitized_content.append(MCPContent(type=c.get("type", "text"), text=sr.content))

        return MCPToolResult(
            content=sanitized_content,
            is_error=result.get("isError", False),
            sanitized=any_modified,
            injection_patterns_found=all_patterns,
        )

    def result_to_text(self, result: MCPToolResult) -> str:
        return "\n".join(c.text for c in result.content)
