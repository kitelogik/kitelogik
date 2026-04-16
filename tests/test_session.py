# SPDX-License-Identifier: Apache-2.0
from unittest.mock import AsyncMock, MagicMock

import pytest

from kitelogik.agents.llm import LLMResponse, ToolCall
from kitelogik.agents.session import AgentSession
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import PolicyDecision, RiskTier, SessionContext


def _make_decision(
    allow: bool = True,
    deny: bool = False,
    risk_tier: RiskTier = RiskTier.INFORMATIONAL,
    requires_hitl: bool = False,
    reason: str = "Allowed",
) -> PolicyDecision:
    return PolicyDecision(
        allow=allow,
        deny=deny,
        risk_tier=risk_tier,
        requires_hitl=requires_hitl,
        reason=reason,
    )


def _make_llm_response(
    stop_reason: str,
    text: str | None = None,
    tool_calls: list[ToolCall] | None = None,
) -> LLMResponse:
    return LLMResponse(
        stop_reason=stop_reason,
        text_content=text,
        tool_calls=tool_calls or [],
        raw_content=f"raw_{stop_reason}",
    )


def _make_mock_llm(*responses: LLMResponse) -> MagicMock:
    """Create a mock LLMClient that returns the given responses in sequence."""
    mock = MagicMock()
    mock.create_message = AsyncMock(side_effect=list(responses))
    mock.format_tool_result = MagicMock(
        side_effect=lambda tid, content: {
            "type": "tool_result",
            "tool_use_id": tid,
            "content": content,
        }
    )
    mock.format_assistant_message = MagicMock(
        side_effect=lambda raw: {"role": "assistant", "content": raw}
    )
    return mock


@pytest.fixture
def mock_gate() -> PolicyGate:
    gate = MagicMock(spec=PolicyGate)
    gate.evaluate_tool_call = AsyncMock()
    gate.evaluate = AsyncMock(return_value=_make_decision(allow=True))
    gate.sanitize_response = MagicMock(
        return_value=MagicMock(content='{"result": "ok"}', was_modified=False)
    )
    return gate


@pytest.fixture
def ctx() -> SessionContext:
    return SessionContext(
        session_id="test_sess_001",
        user_role="support_agent",
        session_scopes=["read_customer", "approve_refund_under_100"],
    )


async def test_allowed_tool_call_is_recorded(mock_gate: PolicyGate, ctx: SessionContext):
    mock_gate.evaluate_tool_call.return_value = _make_decision(allow=True)

    mock_llm = _make_mock_llm(
        _make_llm_response(
            "tool_use",
            tool_calls=[
                ToolCall(
                    id="tu_001", name="read_customer_record", input={"customer_id": "cust_001"}
                )
            ],
        ),
        _make_llm_response("end_turn", text="Customer Alice found."),
    )

    session = AgentSession(gate=mock_gate, context=ctx, llm_client=mock_llm)
    result = await session.run_async("Look up customer cust_001")

    assert len(result.tool_calls) == 1
    assert result.tool_calls[0]["tool"] == "read_customer_record"
    assert len(result.blocked_calls) == 0
    assert result.final_response == "Customer Alice found."


async def test_hard_blocked_tool_call_is_recorded(mock_gate: PolicyGate, ctx: SessionContext):
    mock_gate.evaluate_tool_call.return_value = _make_decision(
        allow=False,
        deny=True,
        risk_tier=RiskTier.SECURITY_CRITICAL,
        reason="Hard blocked by security policy",
    )

    mock_llm = _make_mock_llm(
        _make_llm_response(
            "tool_use",
            tool_calls=[ToolCall(id="tu_001", name="read_file", input={"path": ".env"})],
        ),
        _make_llm_response("end_turn", text="Access was denied."),
    )

    session = AgentSession(gate=mock_gate, context=ctx, llm_client=mock_llm)
    result = await session.run_async("Read the .env file")

    assert len(result.blocked_calls) == 1
    assert result.blocked_calls[0]["tool"] == "read_file"
    assert result.blocked_calls[0]["decision"]["deny"] is True
    assert len(result.tool_calls) == 0


async def test_hitl_tool_call_is_recorded(mock_gate: PolicyGate, ctx: SessionContext):
    mock_gate.evaluate_tool_call.return_value = _make_decision(
        allow=False,
        deny=False,
        risk_tier=RiskTier.TRANSACTIONAL_HIGH,
        requires_hitl=True,
        reason="Requires human approval",
    )

    mock_llm = _make_mock_llm(
        _make_llm_response(
            "tool_use",
            tool_calls=[
                ToolCall(
                    id="tu_001",
                    name="approve_refund",
                    input={"customer_id": "cust_001", "amount": 2000.0, "reason": "Fault"},
                )
            ],
        ),
        _make_llm_response("end_turn", text="Refund pending approval."),
    )

    session = AgentSession(gate=mock_gate, context=ctx, llm_client=mock_llm)
    result = await session.run_async("Approve a $2000 refund for cust_001")

    assert len(result.hitl_required) == 1
    assert result.hitl_required[0]["tool"] == "approve_refund"
    assert result.hitl_required[0]["decision"]["requires_hitl"] is True
    assert len(result.tool_calls) == 0


async def test_end_turn_without_tool_use_returns_response(
    mock_gate: PolicyGate, ctx: SessionContext
):
    mock_llm = _make_mock_llm(
        _make_llm_response("end_turn", text="Here is what you asked for."),
    )

    session = AgentSession(gate=mock_gate, context=ctx, llm_client=mock_llm)
    result = await session.run_async("What is 2 + 2?")

    assert result.final_response == "Here is what you asked for."
    assert len(result.tool_calls) == 0
    mock_gate.evaluate_tool_call.assert_not_called()


async def test_sanitize_response_called_on_allowed_tool(mock_gate: PolicyGate, ctx: SessionContext):
    mock_gate.evaluate_tool_call.return_value = _make_decision(allow=True)

    mock_llm = _make_mock_llm(
        _make_llm_response(
            "tool_use",
            tool_calls=[
                ToolCall(
                    id="tu_001",
                    name="read_customer_record",
                    input={"customer_id": "cust_001"},
                )
            ],
        ),
        _make_llm_response("end_turn", text="Done."),
    )

    session = AgentSession(gate=mock_gate, context=ctx, llm_client=mock_llm)
    await session.run_async("Look up customer cust_001")

    # sanitize_response must be called for every allowed tool execution
    mock_gate.sanitize_response.assert_called_once()
