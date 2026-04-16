# SPDX-License-Identifier: Apache-2.0
"""In-process Rego policy evaluator using regorus (Rust-based).

Provides the same interface as OPAClient but evaluates policies in-process
without requiring an external OPA server. Ideal for development, testing,
and lightweight deployments where running OPA as a separate service is
unnecessary overhead.

Requires the optional ``regoruspy`` package::

    pip install kitelogik[regorus]
"""

from __future__ import annotations

import asyncio
import logging
import threading
from pathlib import Path

from .models import GovernanceEvent, PolicyDecision, PolicyInput, result_to_decision

logger = logging.getLogger(__name__)

_DEFAULT_POLICY_DIR = Path(__file__).parent.parent / "policies"


def _require_regorus():  # type: ignore[no-untyped-def]
    try:
        import regorus  # type: ignore[import-untyped]

        return regorus
    except ImportError:
        raise ImportError(
            "regoruspy is required for in-process policy evaluation. "
            "Install it with: pip install kitelogik[regorus]"
        ) from None


class RegorusClient:
    """In-process Rego evaluator using the regorus engine.

    Implements the same ``evaluate`` / ``evaluate_event`` / ``health``
    interface as ``OPAClient``, so it can be used as a drop-in replacement
    via the ``PolicyEvaluator`` protocol.

    Parameters
    ----------
    policy_dir : str or Path
            Directory containing ``.rego`` policy files. All ``.rego`` files
            (including subdirectories) are loaded on init.
    data : dict or None
            Optional data dict to set as ``data`` in the Rego engine.
    """

    def __init__(
        self,
        policy_dir: str | Path = _DEFAULT_POLICY_DIR,
        data: dict | None = None,
    ) -> None:
        regorus = _require_regorus()
        self._engine = regorus.Engine()
        self._lock = threading.Lock()
        self._policy_dir = Path(policy_dir)
        self._package_path = "data.kitelogik.main"

        # Load all .rego files from the policy directory
        rego_files = sorted(self._policy_dir.rglob("*.rego"))
        if not rego_files:
            raise FileNotFoundError(
                f"No .rego files found in {self._policy_dir} "
                f"(searched: {self._policy_dir}/**/*.rego). "
                "If you have YAML policies, compile them first: "
                "kitelogik compile policies/my_policy.yaml"
            )

        for rego_file in rego_files:
            self._engine.add_policy_from_file(str(rego_file))
            logger.debug("Loaded policy: %s", rego_file)

        if data is not None:
            self._engine.add_data_json(__import__("json").dumps(data))

        logger.info(
            "RegorusClient initialized with %d policy files from %s",
            len(rego_files),
            self._policy_dir,
        )

    def _evaluate_sync(self, input_data: dict) -> dict:
        """Evaluate input against loaded policies synchronously.

        Thread-safe: a lock serialises access to the shared engine state
        (set_input_json + eval_query must be atomic).
        """
        import json

        input_json = json.dumps(input_data)
        with self._lock:
            self._engine.set_input_json(input_json)
            result_json = self._engine.eval_query(self._package_path)
        result = json.loads(result_json)

        # regorus returns {"result": [{"expressions": [{"value": {...}}]}]}
        # Extract the value from the first expression of the first result
        if result and "result" in result:
            results = result["result"]
            if results and "expressions" in results[0]:
                expressions = results[0]["expressions"]
                if expressions:
                    return expressions[0].get("value", {})

        return {}

    async def health(self) -> bool:
        """Always returns True — the engine is in-process."""
        return True

    async def evaluate(self, policy_input: PolicyInput) -> PolicyDecision:
        """Evaluate a tool call against loaded Rego policies."""
        input_data = policy_input.model_dump()
        result = await asyncio.to_thread(self._evaluate_sync, input_data)
        return result_to_decision(result)

    async def evaluate_event(self, event: GovernanceEvent) -> PolicyDecision:
        """Evaluate a governance event against loaded Rego policies."""
        input_data = event.model_dump()
        result = await asyncio.to_thread(self._evaluate_sync, input_data)
        return result_to_decision(result)
