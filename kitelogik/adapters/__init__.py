# SPDX-License-Identifier: Apache-2.0
"""
Framework adapters — drop-in governance for popular agent frameworks.

    from kitelogik.adapters.openai           import OpenAIAdapter
    from kitelogik.adapters.langchain        import as_governed_tool, govern_toolkit
    from kitelogik.adapters.crewai           import CrewAIAdapter
    from kitelogik.adapters.openai_agents    import OpenAIAgentsAdapter
    from kitelogik.adapters.langgraph        import as_governed_node, govern_graph_tools
    from kitelogik.adapters.google_adk       import GoogleADKAdapter
    from kitelogik.adapters.pydantic_ai      import PydanticAIAdapter
    from kitelogik.adapters.llamaindex       import LlamaIndexAdapter
    from kitelogik.adapters.semantic_kernel   import SemanticKernelAdapter
    from kitelogik.adapters.haystack         import HaystackAdapter
    from kitelogik.adapters.dify             import DifyAdapter

Each adapter wraps the framework's native tool-calling interface and routes
every call through the Kite Logik policy gate before execution.

Note: Framework-specific adapters require their respective packages to be
installed. They are lazy-imported at call time.
"""

# Adapter maturity — the single source of truth for which framework adapters
# ship and how battle-tested each one is. Tiers:
#
#   stable — has a dedicated test suite and has been exercised through real
#            integration fixes; wire it into production with confidence.
#   beta   — governance flow is tested in CI, but real-framework integration
#            is less proven (some framework-native tests require the framework
#            installed and are skipped in the default test run).
#   experimental — early, minimal coverage. (None currently.)
#
# The governance pipeline is identical across every tier — the tier reflects
# integration maturity with the framework, not the strength of enforcement.
ADAPTER_MATURITY: dict[str, str] = {
    "openai": "stable",
    "openai_agents": "stable",
    "langchain": "stable",
    "langgraph": "stable",
    "crewai": "stable",
    "google_adk": "stable",
    "pydantic_ai": "stable",
    "llamaindex": "beta",
    "semantic_kernel": "beta",
    "haystack": "beta",
    "dify": "beta",
}
