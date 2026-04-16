# SPDX-License-Identifier: Apache-2.0
"""
CredentialBroker — issues and validates short-lived session-scoped tokens.

Tokens are stored in-memory by default. PersistentCredentialBroker adds a
SQLite write-through backing store so tokens survive process restarts.
"""

import json
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .models import SessionToken


class CredentialBroker:
    """Issues short-lived tokens scoped to a specific session and scope list.

    A token is valid only while its session is active. Revoking the session
    token immediately invalidates it for all subsequent ``has_scope()`` checks.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, SessionToken] = {}

    def issue(
        self,
        session_id: str,
        scopes: list[str],
        ttl_seconds: int = 3600,
    ) -> SessionToken:
        token = SessionToken(
            token_id=f"tok_{secrets.token_hex(16)}",
            session_id=session_id,
            scopes=list(scopes),
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
        )
        self._tokens[token.token_id] = token
        return token

    def revoke(self, token_id: str) -> bool:
        token = self._tokens.get(token_id)
        if token is None:
            return False
        token.revoked = True
        return True

    def revoke_session(self, session_id: str) -> int:
        count = 0
        for token in self._tokens.values():
            if token.session_id == session_id and not token.revoked:
                token.revoked = True
                count += 1
        return count

    def validate(self, token_id: str) -> SessionToken | None:
        token = self._tokens.get(token_id)
        if token is None or not token.is_valid():
            return None
        return token

    def get_scopes(self, token_id: str) -> list[str]:
        token = self.validate(token_id)
        return token.scopes if token else []

    def delegate(
        self,
        parent_token_id: str,
        requested_scopes: list[str],
        session_id: str,
    ) -> SessionToken:
        """Issue a child token with scopes ⊆ parent scopes.

        Parameters
        ----------
        parent_token_id : str
                Token ID of the parent whose scopes constrain the child.
        requested_scopes : list[str]
                Scopes for the child token; must be a subset of parent scopes.
        session_id : str
                Session to associate with the child token.

        Returns
        -------
        SessionToken
                Newly issued child token.

        Raises
        ------
        ValueError
                If the parent token is invalid, expired/revoked, or if any
                requested scope exceeds the parent's granted scopes.
        """
        parent = self.validate(parent_token_id)
        if parent is None:
            raise ValueError(f"Parent token '{parent_token_id}' is invalid or expired")

        forbidden = set(requested_scopes) - set(parent.scopes)
        if forbidden:
            raise ValueError(
                f"Requested scopes exceed parent grant — forbidden: {sorted(forbidden)}"
            )

        child = SessionToken(
            token_id=f"tok_{secrets.token_hex(16)}",
            session_id=session_id,
            scopes=list(requested_scopes),
            issued_at=datetime.now(UTC),
            expires_at=parent.expires_at,  # child cannot outlive parent
            parent_token_id=parent_token_id,
            delegation_depth=parent.delegation_depth + 1,
        )
        self._tokens[child.token_id] = child
        return child


_CREATE_TOKENS_TABLE = """
                       CREATE TABLE IF NOT EXISTS session_tokens
                       (
                           token_id
                           TEXT
                           PRIMARY
                           KEY,
                           session_id
                           TEXT
                           NOT
                           NULL,
                           scopes_json
                           TEXT
                           NOT
                           NULL,
                           issued_at
                           TEXT
                           NOT
                           NULL,
                           expires_at
                           TEXT
                           NOT
                           NULL,
                           revoked
                           INTEGER
                           NOT
                           NULL
                           DEFAULT
                           0,
                           parent_token_id
                           TEXT,
                           delegation_depth
                           INTEGER
                           NOT
                           NULL
                           DEFAULT
                           0
                       ) \
                       """


def _token_to_row(t: SessionToken) -> tuple:
    return (
        t.token_id,
        t.session_id,
        json.dumps(t.scopes),
        t.issued_at.isoformat(),
        t.expires_at.isoformat(),
        1 if t.revoked else 0,
        t.parent_token_id,
        t.delegation_depth,
    )


def _row_to_token(row: tuple) -> SessionToken:
    (
        token_id,
        session_id,
        scopes_json,
        issued_at,
        expires_at,
        revoked,
        parent_token_id,
        delegation_depth,
    ) = row
    return SessionToken(
        token_id=token_id,
        session_id=session_id,
        scopes=json.loads(scopes_json),
        issued_at=datetime.fromisoformat(issued_at),
        expires_at=datetime.fromisoformat(expires_at),
        revoked=bool(revoked),
        parent_token_id=parent_token_id,
        delegation_depth=delegation_depth,
    )


class PersistentCredentialBroker(CredentialBroker):
    """SQLite write-through subclass of ``CredentialBroker``.

    Tokens are written to SQLite on every issue/revoke/delegate call.
    On construction all unexpired tokens are loaded into the in-memory cache
    so subsequent ``validate()`` calls are always fast (no DB read per call).

    Suitable for single-process deployments that require token persistence
    across restarts. For multi-process or distributed environments, replace
    with a Vault or Redis backend.

    Parameters
    ----------
    db_path : str
            Path to the SQLite database file.
    """

    def __init__(self, db_path: str = "credentials.db") -> None:
        super().__init__()
        self._db_path = str(Path(db_path).resolve())
        self._setup()
        self._load_unexpired()

    # ── internal helpers ────────────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _setup(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(_CREATE_TOKENS_TABLE)
            conn.commit()

    def _load_unexpired(self) -> None:
        """Populate in-memory cache from DB, skipping expired tokens."""
        cutoff = datetime.now(UTC).isoformat()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM session_tokens WHERE expires_at > ?", (cutoff,)
            ).fetchall()
        for row in rows:
            token = _row_to_token(tuple(row))
            self._tokens[token.token_id] = token

    def _upsert(self, token: SessionToken) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO session_tokens
                (token_id, session_id, scopes_json, issued_at, expires_at,
                 revoked, parent_token_id, delegation_depth)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(token_id) DO
                UPDATE SET
                    revoked = excluded.revoked
				""",
                _token_to_row(token),
            )
            conn.commit()

    # ── overrides — write-through to SQLite ────────────────────────────────

    def issue(self, session_id: str, scopes: list[str], ttl_seconds: int = 3600) -> SessionToken:
        token = super().issue(session_id, scopes, ttl_seconds)
        self._upsert(token)
        return token

    def revoke(self, token_id: str) -> bool:
        result = super().revoke(token_id)
        if result:
            token = self._tokens.get(token_id)
            if token:
                self._upsert(token)
        return result

    def revoke_session(self, session_id: str) -> int:
        count = super().revoke_session(session_id)
        with self._connect() as conn:
            conn.execute(
                "UPDATE session_tokens SET revoked = 1 WHERE session_id = ? AND revoked = 0",
                (session_id,),
            )
            conn.commit()
        return count

    def delegate(
        self,
        parent_token_id: str,
        requested_scopes: list[str],
        session_id: str,
    ) -> SessionToken:
        child = super().delegate(parent_token_id, requested_scopes, session_id)
        self._upsert(child)
        return child
