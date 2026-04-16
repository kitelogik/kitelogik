# SPDX-License-Identifier: Apache-2.0
from dataclasses import dataclass

from pydantic import BaseModel


class MCPServer(BaseModel):
    name: str
    endpoint: str
    version: str
    sha256: str
    tools: list[str]
    approved_by: str
    approved_at: str
    # sha256_manifest: SHA-256 of the sorted tool-name list returned by tools/list at
    # registry snapshot time. Set to "dev-placeholder" to skip verification (dev only).
    sha256_manifest: str = ""


class MCPContent(BaseModel):
    type: str
    text: str


class MCPToolResult(BaseModel):
    content: list[MCPContent]
    is_error: bool = False
    sanitized: bool = False  # True if any content was modified by the sanitizer
    injection_patterns_found: list[str] = []  # Patterns redacted across all content blocks


@dataclass
class MCPVerificationStatus:
    server_name: str
    endpoint: str
    registered_hash: str  # sha256_manifest from registry.json
    actual_hash: str | None  # hash fetched at verify_manifests() time; None on error
    match: bool  # True iff registered_hash == actual_hash
    error: str | None  # Connection or parse error during verification
