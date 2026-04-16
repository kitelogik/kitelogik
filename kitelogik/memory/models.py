# SPDX-License-Identifier: Apache-2.0
"""
Memory models — provenance metadata for every entry in the agent memory store.

Trust tiers determine how much weight the agent should give to recalled facts
and whether the value was sanitized before storage.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class TrustTier(StrEnum):
    """
    Trust level assigned to a data source feeding into agent memory.

    Attributes
    ----------
    TRUSTED : str
            Internal verified systems (authoritative).
    INTERNAL : str
            Internal but not cryptographically verified.
    DELEGATED : str
            Written by a delegated worker agent (depth > 0).
    EXTERNAL : str
            External tool outputs / MCP responses (sanitized).
    UNTRUSTED : str
            Unknown origin — treat as adversarial.
    """

    TRUSTED = "TRUSTED"
    INTERNAL = "INTERNAL"
    DELEGATED = "DELEGATED"
    EXTERNAL = "EXTERNAL"
    UNTRUSTED = "UNTRUSTED"


@dataclass
class MemoryEntry:
    """
    A single entry in the agent memory store with provenance metadata.

    Parameters
    ----------
    key : str
            Unique identifier for this memory entry.
    value : str
            The stored value.
    trust_tier : ``TrustTier``
            Trust level of the data source that produced this entry.
    source : str
            Origin descriptor, e.g. ``"agent"``, ``"mcp:mock-server"``,
            ``"internal:crm"``.
    session_id : str
            The agent session that wrote this entry.
    created_at : datetime
            Timestamp of first write.
    updated_at : datetime
            Timestamp of most recent write.
    sanitized : bool
            ``True`` if the sanitizer modified the value on write.
    tenant_id : str or None
            Multi-tenant isolation identifier.
    """

    key: str
    value: str
    trust_tier: TrustTier
    source: str
    session_id: str
    created_at: datetime
    updated_at: datetime
    sanitized: bool = False
    tenant_id: str | None = None
