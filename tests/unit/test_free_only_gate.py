"""Unit tests for the free-only routing gate (issue #66, PLAN §7.3/§8.2)."""

from __future__ import annotations

import pytest

from providers.free_status import FreeStatus
from routers.decision_log import CandidatePlan
from routers.free_only import FreeOnlyGate, FreeOnlyViolation


def resolver(table: dict[tuple[str, str], FreeStatus]):
    """Resolver over an explicit table; anything missing resolves UNKNOWN."""
    return lambda p, m: table.get((p, m), FreeStatus.UNKNOWN)


def plan(provider: str, model: str, fallbacks: list[dict] | None = None) -> CandidatePlan:
    return CandidatePlan(
        router_id="r1",
        provider=provider,
        model=model,
        rationale="test",
        confidence=0.9,
        expected_cost=0.0,
        fallbacks=fallbacks or [],
    )


def test_free_model_passes():
    gate = FreeOnlyGate(resolver({("p", "m1"): FreeStatus.FREE}))
    routable, blocked = gate.filter([plan("p", "m1")])
    assert len(routable) == 1 and not blocked
    assert all(e.kind == "allowed" for e in gate.events)


def test_paid_model_blocked_with_event():
    gate = FreeOnlyGate(resolver({("p", "paid"): FreeStatus.PAID}))
    routable, blocked = gate.filter([plan("p", "paid")])
    assert not routable
    assert len(blocked) == 1
    assert blocked[0].status == "paid"
    kinds = [(e.kind, e.origin) for e in gate.events]
    assert ("blocked", "primary") in kinds


def test_unknown_status_blocked_fail_closed():
    # Not in the table => UNKNOWN => excluded until confirmed (§8.2)
    gate = FreeOnlyGate(resolver({}))
    routable, blocked = gate.filter([plan("p", "mystery")])
    assert not routable and len(blocked) == 1
    assert blocked[0].status == "unknown"
    assert "§8.2" in blocked[0].reason or "unknown" in blocked[0].reason


def test_fallback_chain_escaping_free_only_is_dropped():
    # Primary is free but a fallback is paid — whole candidate must be dropped.
    table = {("p", "free1"): FreeStatus.FREE}
    gate = FreeOnlyGate(resolver(table))
    cand = plan(
        "p",
        "free1",
        fallbacks=[
            {"provider": "p", "model": "paid1"},
        ],
    )
    table[("p", "paid1")] = FreeStatus.PAID
    routable, blocked = gate.filter([cand])
    assert not routable, "a fallback chain must not escape free-only mode"
    assert any(b.origin.startswith("fallback") for b in blocked)


def test_unknown_fallback_also_blocks_candidate():
    table = {("p", "free1"): FreeStatus.FREE}
    gate = FreeOnlyGate(resolver(table))
    cand = plan("p", "free1", fallbacks=[{"provider": "q", "model": "?"}])
    routable, blocked = gate.filter([cand])
    assert not routable
    assert any(b.status == "unknown" for b in blocked)


def test_all_free_chain_passes():
    table = {("p", "f1"): FreeStatus.FREE, ("p", "f2"): FreeStatus.FREE}
    gate = FreeOnlyGate(resolver(table))
    cand = plan("p", "f1", fallbacks=[{"provider": "p", "model": "f2"}])
    routable, _ = gate.filter([cand])
    assert len(routable) == 1


def test_mixed_candidates_only_free_survive():
    table = {("p", "free"): FreeStatus.FREE, ("p", "paid"): FreeStatus.PAID}
    gate = FreeOnlyGate(resolver(table))
    routable, blocked = gate.filter([plan("p", "free"), plan("p", "paid")])
    assert [c.model for c in routable] == ["free"]
    assert len(blocked) == 1


def test_enforce_selection_raises_on_paid_and_unknown():
    gate = FreeOnlyGate(resolver({("p", "ok"): FreeStatus.FREE}))
    with pytest.raises(FreeOnlyViolation):
        gate.enforce_selection("p", "paid")
    with pytest.raises(FreeOnlyViolation):
        gate.enforce_selection("p", "nope")
    gate.enforce_selection("p", "ok")  # must not raise


def test_disabled_gate_is_opt_in_only():
    # Disabled gates exist only for explicit operator override in tests;
    # default construction is enabled.
    assert FreeOnlyGate().enabled is True


def test_events_drained_once():
    gate = FreeOnlyGate(resolver({}))
    gate.filter([plan("p", "x")])
    first = gate.drain_events()
    assert first
    assert gate.drain_events() == []
