# SPDX-License-Identifier: Apache-2.0
"""
ServerRegistry — loads the MCP Bill of Materials from registry.json.

Every tool call that routes through an MCP server must be listed in the
registry. Unknown tools or unregistered servers are rejected at the gate.
"""

import json
from pathlib import Path

from .models import MCPServer

_DEFAULT_BOM = Path(__file__).parent / "registry.json"


class ServerRegistry:
    """
    In-memory registry of approved MCP servers loaded from the BOM file.

    The BOM acts as an allowlist: if a tool is not listed under a known
    server entry, the client will refuse to call it.

    Parameters
    ----------
    bom_path : str | Path
            Path to the BOM JSON file. Defaults to ``mcp/registry.json``.
    """

    def __init__(self, bom_path: str | Path = _DEFAULT_BOM) -> None:
        self._servers: list[MCPServer] = []
        self._tool_index: dict[str, MCPServer] = {}
        self._load(Path(bom_path))

    def _load(self, path: Path) -> None:
        data = json.loads(path.read_text())
        for entry in data.get("servers", []):
            server = MCPServer(**entry)
            self._servers.append(server)
            for tool in server.tools:
                self._tool_index[tool] = server

    def get_server_for_tool(self, tool_name: str) -> MCPServer | None:
        return self._tool_index.get(tool_name)

    def list_servers(self) -> list[MCPServer]:
        return list(self._servers)

    def is_registered(self, tool_name: str) -> bool:
        return tool_name in self._tool_index
