# SPDX-License-Identifier: Apache-2.0
"""
Tests for benchmark.py.

Verifies:
  - _pct() returns correct percentile for a known sample
  - bench_type() returns (name, samples) with correct count
  - main() with mocked OPA unreachable exits gracefully
  - main() with mocked OPA runs all three scenarios
"""

import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from benchmark import _pct, bench_type
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import PolicyDecision, RiskTier, SessionContext

# ── _pct ──────────────────────────────────────────────────────────────────────


def test_pct_returns_median_for_p50():
    samples = list(range(1, 101))  # 1..100
    p50 = _pct(samples, 50)
    assert 49 <= p50 <= 51  # median of 1..100 is ~50.5


def test_pct_returns_max_for_small_sample():
    samples = [1.0, 5.0, 10.0]  # fewer than 100 samples → falls back to max
    result = _pct(samples, 95)
    assert result == 10.0


def test_pct_p99_is_near_top():
    samples = list(range(1, 201))
    p99 = _pct(samples, 99)
    assert p99 >= 190  # p99 of 1..200 is ~198


# ── bench_type ─────────────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_bench_type_returns_correct_count():
    """bench_type with runs=10 should return exactly 10 samples."""
    allow_decision = PolicyDecision(
        allow=True,
        deny=False,
        risk_tier=RiskTier.INFORMATIONAL,
        requires_hitl=False,
        reason="allowed",
    )
    mock_gate = MagicMock(spec=PolicyGate)
    mock_gate.evaluate_tool_call = AsyncMock(return_value=allow_decision)

    context = SessionContext(
        session_id="bench_test",
        user_role="support_agent",
        session_scopes=["read_customer"],
    )

    name, samples = await bench_type(
        name="test_scenario",
        tool_name="list_transactions",
        args={"customer_id": "cust_001"},
        context=context,
        gate=mock_gate,
        runs=10,
        concurrency=2,
    )

    assert name == "test_scenario"
    assert len(samples) == 10
    assert all(isinstance(s, float) for s in samples)
    assert all(s >= 0 for s in samples)


@pytest.mark.anyio
async def test_bench_type_calls_gate_correct_times():
    allow_decision = PolicyDecision(
        allow=True,
        deny=False,
        risk_tier=RiskTier.INFORMATIONAL,
        requires_hitl=False,
        reason="allowed",
    )
    mock_gate = MagicMock(spec=PolicyGate)
    mock_gate.evaluate_tool_call = AsyncMock(return_value=allow_decision)

    context = SessionContext(
        session_id="bench_test_2",
        user_role="support_agent",
        session_scopes=["read_customer"],
    )

    _, samples = await bench_type(
        name="count_check",
        tool_name="list_transactions",
        args={"customer_id": "cust_001"},
        context=context,
        gate=mock_gate,
        runs=5,
        concurrency=5,
    )

    assert mock_gate.evaluate_tool_call.call_count == 5


# ── main() graceful OPA failure ────────────────────────────────────────────────


@pytest.mark.anyio
async def test_main_exits_gracefully_when_opa_unreachable(capsys):
    from benchmark import main
    from kitelogik.tether.opa_client import OPAConnectionError

    with patch("benchmark.OPAClient") as MockOPA:
        instance = MagicMock()
        instance.health = AsyncMock(side_effect=OPAConnectionError("refused"))
        MockOPA.return_value = instance

        # Should not raise — prints error and returns
        await main(runs=10, concurrency=1, opa_url="http://localhost:9999")

    captured = capsys.readouterr()
    assert "OPA is not running" in captured.out


@pytest.mark.anyio
async def test_main_runs_all_three_scenarios():
    from benchmark import main

    allow_decision = PolicyDecision(
        allow=True,
        deny=False,
        risk_tier=RiskTier.INFORMATIONAL,
        requires_hitl=False,
        reason="allowed",
    )

    with patch("benchmark.OPAClient") as MockOPA, patch("benchmark.PolicyGate") as MockGate:
        opa_instance = MagicMock()
        opa_instance.health = AsyncMock(return_value=True)
        MockOPA.return_value = opa_instance

        gate_instance = MagicMock()
        gate_instance.evaluate_tool_call = AsyncMock(return_value=allow_decision)
        MockGate.return_value = gate_instance

        await main(runs=5, concurrency=2, opa_url="http://localhost:8181")

    # 3 scenarios × 5 runs = 15 total calls
    assert gate_instance.evaluate_tool_call.call_count == 15
