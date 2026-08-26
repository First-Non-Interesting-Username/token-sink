"""Safety tests: reviewer-panel independence guarantees (issue #122, §10.5).

Negative-path checks: a panel must never silently become non-independent,
and diversity constraints must hold even under adversarial candidate pools.
"""

from __future__ import annotations

import pytest

from routers.diversity import DiversityGate


def cand(provider: str, model: str, router_id: str = "r1"):
    return type("C", (), {"provider": provider, "model": model, "router_id": router_id})()


ONE_FAMILY = {
    "p/m1": "alpha",
    "p/m2": "alpha",
    "p/m3": "alpha",
}


@pytest.mark.safety
def test_all_same_family_pool_never_silent():
    """A pool of one family fills the panel but every fallback is flagged."""
    gate = DiversityGate(families=ONE_FAMILY, default_cap=1)
    cands = [cand("p", m) for m in ("m1", "m2", "m3")]
    panel, events = gate.compose_panel(cands, panel_size=4)
    assert len(panel) == 3
    warns = [e for e in events if e.kind == "fallback_warning"]
    assert warns, "single-family pool must produce explicit warnings"
    # The composed event must not claim full independence.
    assert all("within" not in w.detail or "degraded" in w.detail for w in warns)


@pytest.mark.safety
def test_no_panel_slot_exceeds_cap_without_warning():
    gate = DiversityGate(families=ONE_FAMILY, default_cap=1)
    cands = [cand("p", "m1"), cand("p", "m2"), cand("q", "other")]
    panel, _events = gate.compose_panel(cands, panel_size=2)
    fams = [m.family for m in panel]
    # With a diverse-enough tail available, no family exceeds the cap.
    assert fams.count("alpha") <= 1


@pytest.mark.safety
def test_free_only_interaction_shortfall_is_explicit():
    """Simulate free-only filtering upstream leaving only one family."""
    # Bare-name mapping so both free models resolve to the same family —
    # i.e. two differently-named SKUs of one underlying model lineage.
    gate = DiversityGate(
        families={"a": "alpha", "a-v2": "alpha"},
        default_cap=1,
    )
    # Only free alpha-family models survive the free-only gate (#66); the
    # second survivor maps to an unknown family but same provider lineage.
    free_only_survivors = [cand("free", "a"), cand("free", "a-v2")]
    panel, events = gate.compose_panel(free_only_survivors, panel_size=2)
    assert len(panel) == 2
    degraded = [e for e in events if e.kind == "fallback_warning" and "degraded" in e.detail]
    assert degraded, "joint free-only + diversity unsatisfiability must be surfaced, not absorbed"


@pytest.mark.safety
def test_events_are_audit_complete():
    """Every violation/fallback carries enough context to audit."""
    gate = DiversityGate(families=ONE_FAMILY, default_cap=1)
    _, events = gate.compose_panel(
        [cand("p", "m1"), cand("p", "m2")], panel_size=1, campaign_id="c-9"
    )
    for e in events:
        assert e.event_id and e.ts > 0 and e.campaign_id == "c-9"
        if e.kind in ("violation", "fallback_warning"):
            assert len(e.detail) > 10
