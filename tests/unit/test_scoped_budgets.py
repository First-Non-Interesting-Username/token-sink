"""Tests for scoped budget enforcement (issue #106, PLAN §5/§6/§14)."""

from __future__ import annotations

import threading

import pytest

from budgets.scoped import (
    SOFT_WARNING_FRACTION,
    BudgetScopeManager,
    ScopedBudgetExhausted,
)


def make_manager(**overrides) -> BudgetScopeManager:
    limits = {
        "global": {
            "tokens": 10_000,
            "requests": 100,
            "wall_clock_seconds": None,
            "tool_calls": 500,
        },
        "campaign": {
            "tokens": 5_000,
            "requests": None,
            "wall_clock_seconds": None,
            "tool_calls": None,
        },
        "agent": {"tokens": 1_000, "requests": 10, "wall_clock_seconds": None, "tool_calls": 20},
    }
    limits.update(overrides)
    return BudgetScopeManager(limits=limits)


# --- pre-flight rejection ---------------------------------------------------


def test_hard_cap_rejected_before_dispatch():
    mgr = make_manager()
    with pytest.raises(ScopedBudgetExhausted) as exc:
        mgr.check({"tokens": 2_000}, campaign_id="c1", agent_id="a1")
    assert exc.value.scope == "agent"  # innermost cap is the binding one
    # nothing billed by a refused check
    assert mgr._ledgers["agent"].spent["tokens"] == 0


def test_campaign_cap_refuses_when_agent_headroom_exists():
    mgr = make_manager()
    mgr._ledgers["campaign"].spent["tokens"] = 4_900
    with pytest.raises(ScopedBudgetExhausted) as exc:
        mgr.check({"tokens": 200}, campaign_id="c1", agent_id="a1")
    assert exc.value.scope == "campaign"


def test_global_cap_refuses_over_everything():
    mgr = make_manager()
    mgr._ledgers["global"].spent["tokens"] = 9_900
    with pytest.raises(ScopedBudgetExhausted):
        mgr.check({"tokens": 500}, campaign_id="c1", agent_id="a1")


# --- atomic reservation race --------------------------------------------------


def test_concurrent_callers_cannot_double_spend_last_tokens():
    mgr2 = BudgetScopeManager(
        limits={
            "global": {
                "tokens": 1_500,
                "requests": None,
                "wall_clock_seconds": None,
                "tool_calls": None,
            }
        }
    )
    successes: list[BudgetScopeManager] = []
    failures: list[Exception] = []

    def worker():
        try:
            res = mgr2.reserve({"tokens": 1_000}, campaign_id="c", agent_id="a")
            successes.append(mgr2)
            # hold the reservation open (simulating in-flight call)
            res.commit(tokens=800)
        except ScopedBudgetExhausted as e:
            failures.append(e)

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 1500 total / 1000 each: at most ONE caller can reserve before any commit
    assert len(failures) >= 2 or len(successes) == 1


def test_reservation_commit_bills_release_does_not():
    mgr = make_manager()
    r1 = mgr.reserve({"tokens": 400}, campaign_id="c1", agent_id="a1")
    # while r1 holds 400 tokens, remaining reflects the hold
    assert mgr.remaining("agent", "tokens") == 600
    r1.release()  # failed call — no billing
    assert mgr._ledgers["agent"].spent["tokens"] == 0
    assert mgr.remaining("agent", "tokens") == 1_000

    r2 = mgr.reserve({"tokens": 300}, campaign_id="c1", agent_id="a1")
    events = r2.commit(tokens=250)
    assert mgr._ledgers["agent"].spent["tokens"] == 250  # actual, not reserved
    assert isinstance(events, list)


def test_partial_commit_after_failure():
    """A timed-out call that already streamed some tokens bills only those."""
    mgr = make_manager()
    r = mgr.reserve({"tokens": 500}, campaign_id="c1", agent_id="a1")
    r.commit(tokens=120)
    assert mgr._ledgers["agent"].spent["tokens"] == 120


# --- soft warnings vs hard caps -----------------------------------------------


def test_soft_warning_at_80_percent_not_a_block():
    mgr = make_manager()
    events = mgr._bill(tokens=850)
    warnings = [e for e in events if e["type"] == "budget_warning"]
    assert warnings and warnings[0]["scope"] == "agent"
    # not exhausted: another small call still passes pre-flight
    mgr.reserve({"tokens": 50}, campaign_id="c1", agent_id="a1").commit(tokens=50)


def test_no_warning_below_threshold():
    mgr = make_manager()
    events = mgr._bill(tokens=100)
    assert not [e for e in events if e["type"] == "budget_warning"]
    assert SOFT_WARNING_FRACTION == 0.8


def test_campaign_exhaustion_pauses_and_emits_event():
    mgr = make_manager()
    events = mgr._bill(tokens=5_000)
    kinds = [e["type"] for e in events]
    assert "campaign_exhausted" in kinds
    assert mgr.paused_campaigns


# --- persistence -----------------------------------------------------------


def test_snapshot_restore_roundtrip_and_monotonicity():
    mgr = make_manager()
    mgr._bill(tokens=700)
    snap = mgr.snapshot()
    assert snap["agent"]["tokens"] == 700

    # crash, restore into a fresh manager
    fresh = make_manager()
    fresh.restore(snap)
    assert fresh._ledgers["agent"].spent["tokens"] == 700

    # usage after snapshot must survive restore (never unspent)
    fresh._bill(tokens=100)
    fresh.restore(snap)
    assert fresh._ledgers["agent"].spent["tokens"] == 800


def test_unlimited_dimensions_stay_unlimited():
    mgr = make_manager()
    mgr.check({"wall_clock_seconds": 999_999}, campaign_id="c1", agent_id="a1")


def test_holds_roll_back_on_refusal():
    mgr = make_manager()
    r = mgr.reserve({"tokens": 900}, campaign_id="c1", agent_id="a1")
    try:
        mgr.check({"tokens": 200}, campaign_id="c1", agent_id="a2")
        raised = False
    except ScopedBudgetExhausted:
        raised = True
    assert raised  # 900 held + 200 requested > 1000
    r.release()
    # after release the 200 fits again
    mgr.check({"tokens": 200}, campaign_id="c1", agent_id="a2")
