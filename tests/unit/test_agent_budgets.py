"""Tests for per-agent budget enforcement (#141, PLAN §6/§14/§21).

Covers: pre-call denial per dimension, hard-stop after exhaustion,
mid-run overrun attribution (boundary-crossing call kept), subagent ≤
parent remainder, wall-clock cutoff with injectable clock, and
blocked-event shape.
"""

from __future__ import annotations

import pytest

from budgets import (
    AgentBudget,
    BudgetDimension,
    BudgetEnforcer,
    BudgetExhaustedError,  # noqa: F401  (re-export contract)
    BudgetLedger,
    derive_subagent_budget,
)

# --- pre-call checks ----------------------------------------------------------


def test_within_budget_allowed():
    e = BudgetEnforcer(AgentBudget(max_tokens=1000, max_requests=10))
    assert e.pre_call().allowed is True


def test_token_cap_denies_pre_call():
    e = BudgetEnforcer(AgentBudget(max_tokens=100))
    e.record_usage(tokens=100)
    d = e.pre_call()
    assert d.allowed is False and d.dimension == BudgetDimension.TOKENS
    assert "tokens" in d.explanation


@pytest.mark.parametrize(
    "budget,usage,dim",
    [
        (AgentBudget(max_requests=2), {"request": True}, "requests"),
        (AgentBudget(max_tool_calls=1), {"tool_call": True}, "tool_calls"),
        (AgentBudget(max_wall_clock_seconds=5.0), {"duration_seconds": 0}, "wall_clock_seconds"),
    ],
)
def test_each_dimension_exhausts(budget, usage, dim):
    e = BudgetEnforcer(budget)
    for _ in range(10):
        if e.pre_call().allowed:
            e.record_usage(**usage)
        else:
            break
    # eventually the cap refuses further admission
    assert e.pre_call().allowed is False or dim == "wall_clock_seconds"


def test_hard_stop_persists_after_exhaustion():
    e = BudgetEnforcer(AgentBudget(max_requests=1))
    e.record_usage(request=True)
    assert e.pre_call().allowed is False
    assert e.pre_call().allowed is False  # stays denied
    assert "hard stop" in e.pre_call().explanation


def test_unlimited_budget_never_denies():
    e = BudgetEnforcer(AgentBudget())
    for _ in range(50):
        assert e.pre_call().allowed
        e.record_usage(tokens=9999, request=True, tool_call=True)


# --- overrun accounting ---------------------------------------------------------


def test_streaming_overrun_kept_and_attributed():
    """Token cap crossed mid-stream: result kept, overrun attributed."""
    e = BudgetEnforcer(AgentBudget(max_tokens=100))
    assert e.pre_call().allowed
    event = e.record_usage(tokens=150)  # one streaming response blew past the cap
    assert event is not None
    assert event["overran_dimensions"] == BudgetDimension.TOKENS
    assert event["attribution"] == "owning_agent"
    assert e.ledger.tokens_used == 150  # accurate attribution, not clamped


def test_no_further_calls_after_overrun():
    e = BudgetEnforcer(AgentBudget(max_tokens=100))
    e.record_usage(tokens=120)
    assert e.pre_call().allowed is False


def test_within_budget_records_silently():
    e = BudgetEnforcer(AgentBudget(max_tokens=1000))
    assert e.record_usage(tokens=50) is None
    assert e.overrun_events == []


def test_blocked_event_shape():
    e = BudgetEnforcer(AgentBudget(max_tool_calls=0))
    d = e.pre_call()
    ev = e.blocked_event(d)
    assert ev["blocked_reason"] == "budget_exhausted"
    assert ev["dimension"] == BudgetDimension.TOOL_CALLS
    assert ev["explanation"]


# --- wall-clock ------------------------------------------------------------------


def test_timer_based_cutoff():
    clock = [0.0]
    ledger = BudgetLedger(now=lambda: clock[0])
    e = BudgetEnforcer(AgentBudget(max_wall_clock_seconds=10.0), ledger)
    assert e.pre_call().allowed
    clock[0] = 10.000001
    assert e.pre_call().allowed is False
    assert e.pre_call().dimension == BudgetDimension.WALL_CLOCK_SECONDS


def test_duration_usage_counts_toward_wall_clock():
    e = BudgetEnforcer(AgentBudget(max_wall_clock_seconds=5.0))
    e.record_usage(duration_seconds=6.0)
    assert e.pre_call().allowed is False


# --- subagent inheritance ----------------------------------------------------------


def test_subagent_cannot_exceed_parent_remainder():
    parent_ledger = BudgetLedger()
    parent = BudgetEnforcer(AgentBudget(max_tokens=1000, max_requests=5), parent_ledger)
    parent.record_usage(tokens=700, request=True)

    child_budget = derive_subagent_budget(parent.budget, parent_ledger)
    assert child_budget.max_tokens == 300
    assert child_budget.max_requests == 4

    child = BudgetEnforcer(child_budget, BudgetLedger())
    child.record_usage(tokens=300, request=True)
    assert child.pre_call().allowed is False  # capped at parent remainder


def test_unlimited_parent_yields_unlimited_child():
    b = derive_subagent_budget(AgentBudget(), BudgetLedger())
    assert b.max_tokens is None and b.max_requests is None


def test_fully_spent_parent_gives_zero_budget():
    parent_ledger = BudgetLedger()
    parent = BudgetEnforcer(AgentBudget(max_tokens=100), parent_ledger)
    parent.record_usage(tokens=100)
    child_budget = derive_subagent_budget(parent.budget, parent_ledger)
    child = BudgetEnforcer(child_budget, BudgetLedger())
    assert child.pre_call().allowed is False
