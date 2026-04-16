# SPDX-License-Identifier: Apache-2.0
"""
LLM client abstraction for AgentSession.

Defines a Protocol that any LLM provider can implement, plus the default
AnthropicLLMClient that wraps the Anthropic Python SDK.

To use a non-Anthropic provider with AgentSession, implement the
LLMClient protocol and pass it via ``llm_client=`` at construction::

    session = AgentSession(
        gate=gate,
        context=context,
        llm_client=MyOpenAIClient(api_key="..."),
    )
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@dataclass
class ToolCall:
    """A tool call extracted from an LLM response."""

    id: str
    name: str
    input: dict[str, Any]


@dataclass
class LLMResponse:
    """Normalized response from any LLM provider."""

    stop_reason: str  # "end_turn" | "tool_use"
    text_content: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw_content: Any = None  # Provider-specific content for message history


@runtime_checkable
class LLMClient(Protocol):
    """Protocol for LLM provider clients.

    Implement this to use any LLM with AgentSession. The three methods
    map to the core interaction pattern: create a message, format tool
    results, and build assistant messages for the conversation history.
    """

    async def create_message(
        self,
        *,
        model: str,
        messages: list[dict],
        tools: list[dict],
        system: str,
        max_tokens: int = 4096,
    ) -> LLMResponse: ...

    def format_tool_result(self, tool_call_id: str, content: str) -> dict:
        """Format a tool result for inclusion in the message history."""
        ...

    def format_assistant_message(self, raw_content: Any) -> dict:
        """Format the raw response content as an assistant message."""
        ...


class AnthropicLLMClient:
    """Default LLM client using the Anthropic Python SDK.

    If no ``api_key`` is provided, falls back to the ``ANTHROPIC_API_KEY``
    environment variable.

    Parameters
    ----------
    api_key : str or None, optional
            Anthropic API key. Falls back to the ``ANTHROPIC_API_KEY``
            environment variable when not provided.
    """

    def __init__(self, api_key: str | None = None) -> None:
        import anthropic

        key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Copy .env.example to .env and add your key, "
                "or set the environment variable before running."
            )
        self._client = anthropic.AsyncAnthropic(api_key=key)

    async def create_message(
        self,
        *,
        model: str,
        messages: list[dict],
        tools: list[dict],
        system: str,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """
        Send a message to Claude and return a normalized response.

        Returns
        -------
        ``LLMResponse``
                Normalized response with stop reason, text, and tool calls.
        """
        response = await self._client.messages.create(
            model=model,
            max_tokens=max_tokens,
            tools=tools,
            system=system,
            messages=messages,
        )

        text_content = None
        tool_calls = []

        for block in response.content:
            if hasattr(block, "text"):
                text_content = block.text
            if block.type == "tool_use":
                tool_calls.append(
                    ToolCall(
                        id=block.id,
                        name=block.name,
                        input=dict(block.input),
                    )
                )

        return LLMResponse(
            stop_reason=response.stop_reason,
            text_content=text_content,
            tool_calls=tool_calls,
            raw_content=response.content,
        )

    def format_tool_result(self, tool_call_id: str, content: str) -> dict:
        """Format a tool result in Anthropic's expected format."""
        return {
            "type": "tool_result",
            "tool_use_id": tool_call_id,
            "content": content,
        }

    def format_assistant_message(self, raw_content: Any) -> dict:
        """Format Anthropic response content as an assistant message."""
        return {"role": "assistant", "content": raw_content}
