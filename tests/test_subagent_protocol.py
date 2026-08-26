"""Tests for the subagent spawning protocol (spec §6 Subagents)."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from mavr.agents.subagents.protocol import (
    SpawnProtocolError,
    SubagentOutput,
    SubagentSpec,
    clamp_budget,
    inherit_budget,
    inherit_timeout,
    summarize_subagent_outputs,
    validate_request,
)
from mavr.orchestrator.runtime import SubagentRequest
from mavr.schemas import entities as schema


def _parent(**budget) -> schema.Agent:
    now = datetime.now(UTC)
    return schema.Agent(
        id="11111111-1111-4111-8111-111111111111",
        role=schema.AgentRole.RESEARCH,
        status=schema.AgentStatus.RUNNING,
        campaign_id="22222222-2222-4222-8222-222222222222",
        budget=schema.AgentBudgets(
            max_tokens=budget.get("max_tokens", 100_000),
            max_time_seconds=budget.get("max_time_seconds", 600),
            max_tool_calls=budget.get("max_tool_calls", 50),
            max_network_requests=budget.get("max_network_requests", 20),
        ),
        created_at=now,
        updated_at=now,
    )


# ---- request schema -------------------------------------------------------


def test_valid_request_passes() -> None:
    p = _parent()
    req = validate_request(SubagentRequest(objective="scan host"), parent=p)
    # Inheritance applied: defaults clamped to parent's smaller budget.
    assert req.budget is not None and req.budget.max_tokens <= p.budget.max_tokens


@pytest.mark.parametrize(
    "kwargs",
    [
        {"objective": "   "},                      # blank objective
        {"objective": "x", "timeout_seconds": -5},  # negative timeout
        {"objective": "x", "allowed_tools": ("",)},  # blank tool name
    ],
)
def test_invalid_request_rejected(kwargs) -> None:
    with pytest.raises(SpawnProtocolError):
        validate_request(SubagentRequest(objective=kwargs.pop("objective", "ok"), **kwargs), parent=_parent())


def test_spec_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        SubagentSpec(objective="x", sneaky_field=1)


def test_active_testing_requires_completion_criteria() -> None:
    with pytest.raises(SpawnProtocolError):
        validate_request(
            SubagentRequest(objective="fuzz", active_testing_allowed=True),
            parent=_parent(),
        )
    ok = validate_request(
        SubagentRequest(
            objective="fuzz",
            active_testing_allowed=True,
            completion_criteria="no crash for 60s",
        ),
        parent=_parent(),
    )
    assert ok.active_testing_allowed


def test_parent_without_campaign_rejected() -> None:
    p = _parent()
    orphan = p.model_copy(update={"campaign_id": None})
    with pytest.raises(SpawnProtocolError):
        validate_request(SubagentRequest(objective="x"), parent=orphan)


# ---- budget / timeout inheritance -----------------------------------------


def test_clamp_budget_component_wise() -> None:
    child = schema.AgentBudgets(
        max_tokens=999_999, max_time_seconds=10, max_tool_calls=3, max_network_requests=99
    )
    parent = schema.AgentBudgets(
        max_tokens=100, max_time_seconds=1000, max_tool_calls=5, max_network_requests=7
    )
    c = clamp_budget(child, parent)
    assert (c.max_tokens, c.max_time_seconds, c.max_tool_calls, c.max_network_requests) == (
        100, 10, 3, 7)


def test_inherit_budget_none_defaults_to_parent() -> None:
    p = _parent().budget
    assert inherit_budget(None, p) == p


def test_timeout_bounded_by_parent_time_budget() -> None:
    b = _parent(max_time_seconds=120).budget
    assert inherit_timeout(10_000, b) == 120
    assert inherit_timeout(-1, b) == 0
    assert inherit_timeout(50, b) == 50


def test_validate_request_adjusts_budget_and_timeout() -> None:
    p = _parent(max_time_seconds=300, max_tokens=1_000).budget
    req = validate_request(
        SubagentRequest(
            objective="x",
            budget=schema.AgentBudgets(max_tokens=50_000, max_time_seconds=9_000),
            timeout_seconds=9_999,
        ),
        parent=_parent(max_time_seconds=300, max_tokens=1_000),
    )
    assert req.budget is not None
    assert req.budget.max_tokens <= p.max_tokens
    assert req.timeout_seconds <= p.max_time_seconds == 300


# ---- output citation rules ------------------------------------------------


OUTS = {
    "a": SubagentOutput(agent_id="aaaa", task_id="t1"),
    "b": SubagentOutput(agent_id="bbbb", task_id="t2"),
}


def test_summary_cites_outputs() -> None:
    s = summarize_subagent_outputs(
        parent=_parent(),
        outputs=OUTS,
        claims=[("port 80 open", ("a",)), ("reflected XSS", ("b", "a"))],
    )
    assert "[cite:a] port 80 open" in s.splitlines()[1]
    assert "[cite:b]" in s and "[cite:a]" in s.splitlines()[2]


def test_claim_without_citation_rejected() -> None:
    with pytest.raises(SpawnProtocolError):
        summarize_subagent_outputs(
            parent=_parent(), outputs=OUTS, claims=[("uncited claim", ())]
        )


def test_unknown_citation_rejected() -> None:
    with pytest.raises(SpawnProtocolError):
        summarize_subagent_outputs(
            parent=_parent(), outputs=OUTS, claims=[("made up", ("ghost",))]
        )
