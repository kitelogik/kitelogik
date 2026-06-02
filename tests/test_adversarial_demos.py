# SPDX-License-Identifier: Apache-2.0
"""Smoke tests for the adversarial lifecycle demos in examples/adversarial.

Each demo self-asserts its expected outcome, so a clean exit (return code
0) means the attack was caught as documented. The memory demo runs in any
environment; the gate-based demos are skipped unless an OPA server is
reachable at localhost:8181.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

_REPO_ROOT = Path(__file__).parent.parent
_DEMO_DIR = _REPO_ROOT / "examples" / "adversarial"

_NEEDS_OPA = {
    "delegation_scope_escalation",
    "plan_step_injection",
    "budget_exhaustion_runaway",
}
_DEMOS = [
    "delegation_scope_escalation",
    "plan_step_injection",
    "budget_exhaustion_runaway",
    "memory_poisoning_minja",
]


def _opa_reachable() -> bool:
    try:
        return httpx.get("http://localhost:8181/health", timeout=1.0).status_code == 200
    except Exception:
        return False


@pytest.mark.parametrize("demo", _DEMOS)
def test_adversarial_demo_runs(demo: str):
    if demo in _NEEDS_OPA and not _opa_reachable():
        pytest.skip("OPA not reachable at localhost:8181")

    result = subprocess.run(
        [sys.executable, str(_DEMO_DIR / f"{demo}.py")],
        cwd=_REPO_ROOT,
        env={**os.environ, "PYTHONPATH": str(_REPO_ROOT)},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"{demo} failed:\n{result.stdout}\n{result.stderr}"
