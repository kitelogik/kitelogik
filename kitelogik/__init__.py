# SPDX-License-Identifier: Apache-2.0
"""
Kite Logik — governance middleware for enterprise AI agents.

Quickstart::

    from kitelogik import AgentSession, OPAClient, PolicyGate, HITLQueue, SessionContext

    opa    = OPAClient()
    gate   = PolicyGate(opa_client=opa)
    queue  = HITLQueue()
    context = SessionContext(session_id="s1", user_role="support_agent",
                             session_scopes=["read_customer"])
    session = AgentSession(gate=gate, context=context, hitl_queue=queue)
    result  = await session.run_async("Look up customer cust_001")

See quickstart.py for a complete working example.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    __version__ = _pkg_version("kitelogik")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"

from kitelogik.agents.session import AgentSession, SessionResult
from kitelogik.anchor.credentials import CredentialBroker
from kitelogik.anchor.queue import HITLQueue
from kitelogik.edition import Edition, edition, load_plugin
from kitelogik.governed import GovernanceError, GovernedToolbox, governed
from kitelogik.memory.models import TrustTier
from kitelogik.memory.store import MemoryStore
from kitelogik.policies.compiler import compile_yaml, compile_yaml_string
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.hierarchy import HierarchicalEvaluator
from kitelogik.tether.models import (
    PolicyDecision,
    ResolutionStep,
    RiskTier,
    SessionContext,
    ToolCallInput,
)
from kitelogik.tether.opa_client import OPAClient, OPAConnectionError
from kitelogik.tether.regorus_client import RegorusClient

__all__ = [
    # Version
    "__version__",
    # Zero-restructuring integration
    "governed",
    "GovernedToolbox",
    "GovernanceError",
    # Session execution
    "AgentSession",
    "SessionResult",
    # Policy engine
    "PolicyGate",
    "HierarchicalEvaluator",
    "SessionContext",
    "PolicyDecision",
    "ResolutionStep",
    "RiskTier",
    "ToolCallInput",
    "OPAClient",
    "OPAConnectionError",
    "RegorusClient",
    # Oversight & credentials
    "HITLQueue",
    "CredentialBroker",
    # Memory
    "MemoryStore",
    "TrustTier",
    # Policy compilation
    "compile_yaml",
    "compile_yaml_string",
    # Edition
    "Edition",
    "edition",
    "load_plugin",
]
