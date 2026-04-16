# SPDX-License-Identifier: Apache-2.0
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class ActionStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    TIMED_OUT = "TIMED_OUT"


@dataclass
class PendingAction:
    id: str
    session_id: str
    tool_name: str
    args: dict[str, Any]
    risk_tier: str
    status: ActionStatus
    created_at: datetime
    decided_at: datetime | None = None
    decided_by: str | None = None
    denial_reason: str | None = None
    tenant_id: str | None = None  # Multi-tenant isolation identifier


@dataclass
class SessionToken:
    token_id: str
    session_id: str
    scopes: list[str]
    issued_at: datetime
    expires_at: datetime
    revoked: bool = False
    parent_token_id: str | None = None
    delegation_depth: int = 0

    def is_valid(self) -> bool:
        return not self.revoked and datetime.now(UTC) < self.expires_at

    def has_scope(self, scope: str) -> bool:
        return self.is_valid() and scope in self.scopes
