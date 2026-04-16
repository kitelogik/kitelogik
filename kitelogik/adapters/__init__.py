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
