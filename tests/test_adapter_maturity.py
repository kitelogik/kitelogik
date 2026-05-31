# SPDX-License-Identifier: Apache-2.0
"""Tests for the adapter maturity registry in kitelogik.adapters."""

from pathlib import Path

from kitelogik.adapters import ADAPTER_MATURITY

_ADAPTERS_DIR = Path(__file__).parent.parent / "kitelogik" / "adapters"
_VALID_TIERS = {"stable", "beta", "experimental"}


def _adapter_module_names() -> set[str]:
    return {p.stem for p in _ADAPTERS_DIR.glob("*.py") if p.stem not in {"__init__", "_base"}}


def test_every_adapter_module_has_a_maturity_tier():
    # A new adapter module added without a tier (or a typo'd key) fails here.
    assert set(ADAPTER_MATURITY) == _adapter_module_names()


def test_all_tiers_are_valid():
    assert set(ADAPTER_MATURITY.values()) <= _VALID_TIERS


def test_eleven_adapters_registered():
    assert len(ADAPTER_MATURITY) == 11
