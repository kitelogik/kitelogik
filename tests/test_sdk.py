# SPDX-License-Identifier: Apache-2.0
"""
Tests for the kitelogik SDK entrypoint.

Verifies:
  - All names in kitelogik.__all__ are importable
  - Key classes are the correct types (not stubs)
  - quickstart.py can be imported without error
"""

import importlib

import kitelogik


def test_all_names_importable():
    """Every name in __all__ must be importable from kitelogik."""
    missing = []
    for name in kitelogik.__all__:
        if not hasattr(kitelogik, name):
            missing.append(name)
    assert missing == [], f"Names missing from kitelogik namespace: {missing}"


def test_key_types_are_correct_classes():
    """Spot-check that exports are the real classes, not strings or None."""
    assert callable(kitelogik.AgentSession)
    assert callable(kitelogik.PolicyGate)
    assert callable(kitelogik.OPAClient)
    assert callable(kitelogik.HITLQueue)
    assert callable(kitelogik.MemoryStore)
    assert callable(kitelogik.SessionContext)


def test_all_list_is_non_empty():
    assert len(kitelogik.__all__) >= 10


def test_quickstart_importable():
    """quickstart.py must import cleanly (no broken imports or syntax errors)."""
    spec = importlib.util.spec_from_file_location(
        "quickstart",
        "quickstart.py",
    )
    mod = importlib.util.module_from_spec(spec)
    # Loading without executing __main__ — just confirms imports resolve
    spec.loader.exec_module(mod)
    assert callable(getattr(mod, "main", None)), "quickstart.py must define main()"


def test_opa_client_constructor():
    """OPAClient should accept a base_url kwarg without raising."""
    client = kitelogik.OPAClient(base_url="http://localhost:8181")
    assert client is not None


def test_session_context_constructor():
    """SessionContext should construct with required fields."""
    ctx = kitelogik.SessionContext(
        session_id="test_sdk_001",
        user_role="support_agent",
        session_scopes=["read_customer"],
    )
    assert ctx.session_id == "test_sdk_001"
    assert ctx.user_role == "support_agent"


def test_risk_tier_enum_has_expected_values():
    rt = kitelogik.RiskTier
    assert hasattr(rt, "INFORMATIONAL")
    assert hasattr(rt, "TRANSACTIONAL_HIGH")
    assert hasattr(rt, "SECURITY_CRITICAL")
