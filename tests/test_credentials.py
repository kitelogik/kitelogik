# SPDX-License-Identifier: Apache-2.0
"""
Tests for anchor.credentials.CredentialBroker and PersistentCredentialBroker.
"""

import pytest

from kitelogik.anchor.credentials import CredentialBroker, PersistentCredentialBroker


@pytest.fixture
def broker():
    return CredentialBroker()


def test_issue_returns_token(broker):
    token = broker.issue("sess_1", scopes=["read_customer"])
    assert token.token_id.startswith("tok_")
    assert token.session_id == "sess_1"
    assert "read_customer" in token.scopes
    assert token.is_valid()


def test_validate_valid_token(broker):
    token = broker.issue("sess_2", scopes=["approve_refund"])
    result = broker.validate(token.token_id)
    assert result is not None
    assert result.token_id == token.token_id


def test_validate_unknown_token_returns_none(broker):
    assert broker.validate("tok_doesnotexist") is None


def test_revoke_invalidates_token(broker):
    token = broker.issue("sess_3", scopes=["read_customer"])
    ok = broker.revoke(token.token_id)
    assert ok is True
    assert broker.validate(token.token_id) is None


def test_revoke_unknown_token_returns_false(broker):
    assert broker.revoke("tok_ghost") is False


def test_revoke_session_invalidates_all_tokens(broker):
    t1 = broker.issue("sess_4", scopes=["read_customer"])
    t2 = broker.issue("sess_4", scopes=["send_notifications"])
    t3 = broker.issue("sess_5", scopes=["read_customer"])

    count = broker.revoke_session("sess_4")
    assert count == 2
    assert broker.validate(t1.token_id) is None
    assert broker.validate(t2.token_id) is None
    assert broker.validate(t3.token_id) is not None  # different session


def test_get_scopes_valid_token(broker):
    token = broker.issue("sess_6", scopes=["read_customer", "send_notifications"])
    scopes = broker.get_scopes(token.token_id)
    assert "read_customer" in scopes
    assert "send_notifications" in scopes


def test_get_scopes_invalid_token_returns_empty(broker):
    assert broker.get_scopes("tok_invalid") == []


def test_has_scope(broker):
    token = broker.issue("sess_7", scopes=["read_customer"])
    assert token.has_scope("read_customer")
    assert not token.has_scope("approve_refund")


def test_expired_token_is_invalid(broker):
    token = broker.issue("sess_8", scopes=["read_customer"], ttl_seconds=0)
    # ttl=0 means expires_at == issued_at, so immediately invalid
    assert not token.is_valid()
    assert broker.validate(token.token_id) is None


# ── PersistentCredentialBroker (SQLite write-through) ──────────────────────


@pytest.fixture
def persistent_broker(tmp_path):
    return PersistentCredentialBroker(db_path=str(tmp_path / "test_creds.db"))


def test_persistent_issue_and_validate(persistent_broker):
    token = persistent_broker.issue("sess_p1", scopes=["read_customer"])
    assert persistent_broker.validate(token.token_id) is not None


def test_persistent_revoke_persists(tmp_path):
    """Token revoked via one instance must be invalid when loaded fresh from DB."""
    db = str(tmp_path / "revoke.db")
    b1 = PersistentCredentialBroker(db_path=db)
    token = b1.issue("sess_p2", scopes=["read_customer"])
    b1.revoke(token.token_id)

    b2 = PersistentCredentialBroker(db_path=db)
    # Revoked token loaded from DB must still be invalid
    assert b2.validate(token.token_id) is None


def test_persistent_survives_restart(tmp_path):
    """Token issued in one process instance is valid in a new instance."""
    db = str(tmp_path / "persist.db")
    b1 = PersistentCredentialBroker(db_path=db)
    token = b1.issue("sess_p3", scopes=["read_customer"])

    b2 = PersistentCredentialBroker(db_path=db)
    result = b2.validate(token.token_id)
    assert result is not None
    assert result.token_id == token.token_id
    assert "read_customer" in result.scopes


def test_persistent_expired_not_loaded(tmp_path):
    """Expired tokens are not loaded into the in-memory cache on startup."""
    db = str(tmp_path / "expired.db")
    b1 = PersistentCredentialBroker(db_path=db)
    token = b1.issue("sess_p4", scopes=["read_customer"], ttl_seconds=0)

    b2 = PersistentCredentialBroker(db_path=db)
    assert b2.validate(token.token_id) is None


# ── Error path additions ────────────────────────────────────────────────────


def test_token_expired_with_negative_ttl_is_rejected(broker):
    """Negative TTL produces a token that is already expired at issue time."""
    token = broker.issue("sess_neg", scopes=["read_customer"], ttl_seconds=-10)
    assert not token.is_valid()
    assert broker.validate(token.token_id) is None


def test_revoke_already_revoked_token_is_idempotent(broker):
    """Revoking a token that is already revoked must not error and return True."""
    token = broker.issue("sess_idem", scopes=["read_customer"])
    first = broker.revoke(token.token_id)
    second = broker.revoke(token.token_id)
    assert first is True
    assert second is True
    assert broker.validate(token.token_id) is None


def test_validate_returns_none_for_explicitly_revoked_token(broker):
    """validate() must return None for a revoked (not just expired) token."""
    token = broker.issue("sess_rev_check", scopes=["send_notifications"])
    broker.revoke(token.token_id)
    result = broker.validate(token.token_id)
    assert result is None


def test_token_expired_at_boundary_is_rejected(broker):
    """Token issued with ttl=0 expires at the exact moment of issue — must be rejected."""
    token = broker.issue("sess_boundary", scopes=["read_customer"], ttl_seconds=0)
    # expires_at == issued_at; any subsequent check finds now >= expires_at
    assert not token.is_valid()
    assert broker.validate(token.token_id) is None


def test_validate_nonexistent_token_id_returns_none(broker):
    """validate() with a token_id that was never issued must return None."""
    assert broker.validate("tok_" + "0" * 32) is None


# ── Delegation ─────────────────────────────────────────────────────────────


def test_delegate_child_has_subset_scopes(broker):
    parent = broker.issue("sess_deleg", scopes=["read_customer", "send_notifications"])
    child = broker.delegate(parent.token_id, ["read_customer"], session_id="sess_child")
    assert child.scopes == ["read_customer"]
    assert child.parent_token_id == parent.token_id
    assert child.delegation_depth == 1


def test_delegate_child_cannot_exceed_parent_scopes(broker):
    parent = broker.issue("sess_deleg2", scopes=["read_customer"])
    with pytest.raises(ValueError, match="forbidden"):
        broker.delegate(parent.token_id, ["read_customer", "approve_refund"], session_id="sess_c2")


def test_delegate_revoked_parent_raises(broker):
    parent = broker.issue("sess_deleg3", scopes=["read_customer"])
    broker.revoke(parent.token_id)
    with pytest.raises(ValueError, match="invalid or expired"):
        broker.delegate(parent.token_id, ["read_customer"], session_id="sess_c3")


def test_delegate_child_expires_no_later_than_parent(broker):
    parent = broker.issue("sess_deleg4", scopes=["read_customer"], ttl_seconds=60)
    child = broker.delegate(parent.token_id, ["read_customer"], session_id="sess_c4")
    assert child.expires_at == parent.expires_at


def test_delegate_depth_increments(broker):
    p = broker.issue("sess_depth", scopes=["read_customer"])
    c1 = broker.delegate(p.token_id, ["read_customer"], session_id="sess_d1")
    c2 = broker.delegate(c1.token_id, ["read_customer"], session_id="sess_d2")
    assert c1.delegation_depth == 1
    assert c2.delegation_depth == 2
