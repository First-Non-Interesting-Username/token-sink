"""Unit tests for model-family diversity enforcement (issue #122)."""

from __future__ import annotations

import pytest

from routers.diversity import DiversityGate, family_of


def cand(provider: str, model: str, router_id: str = "r1"):
    return type("C", (), {"provider": provider, "model": model, "router_id": router_id})()


FAMILIES = {
    "p/model-a": "alpha",
    "p/model-b": "alpha",
    "q/model-c": "beta",
    "r/model-d": "gamma",
}


def test_family_of_explicit_and_unknown():
    fam, unk = family_of("p", "model-a", FAMILIES)
    assert (fam, unk) == ("alpha", False)
    # Unknown family is its own value and flagged, never grouped.
    fam2, unk2 = family_of("zzz", "weird", FAMILIES)
    assert unk2 is True
    assert fam2 != ""


def test_panel_prefers_distinct_families():
    gate = DiversityGate(families=FAMILIES, default_cap=1)
    cands = [cand("p", "model-a"), cand("p", "model-b"), cand("q", "model-c")]
    panel, events = gate.compose_panel(cands, panel_size=3)
    # Only 2 families available for 3 slots: alpha appears twice BUT the
    # degraded pick must carry an explicit fallback_warning (never silent).
    assert len(panel) == 3
    if sum(1 for m in panel if m.family == "alpha") > 1:
        assert any(e.kind == "fallback_warning" and "degraded" in e.detail for e in events), (
            "degraded independence must be flagged"
        )
    # With a diverse pool available, distinct families are preferred:
    cands2 = cands + [cand("r", "model-d")]
    gate2 = DiversityGate(families=FAMILIES, default_cap=1)
    panel2, ev2 = gate2.compose_panel(cands2, panel_size=3)
    fams2 = [m.family for m in panel2]
    assert len(set(fams2)) == 3, "distinct families win when available"


def test_violation_event_when_cap_blocks_candidate():
    gate = DiversityGate(families=FAMILIES, default_cap=1)
    cands = [cand("p", "model-a"), cand("p", "model-b")]
    _, events = gate.compose_panel(cands, panel_size=1)
    # model-b is cap-exceeded; it is either rejected (violation event) or,
    # if needed to fill the panel, added with an explicit fallback_warning.
    if not any(e.kind == "fallback_warning" and "model-b" in e.detail for e in events):
        assert any(e.kind == "violation" and "model-b" in e.detail for e in events)


def test_fallback_fills_with_warning_when_families_scarce():
    gate = DiversityGate(families=FAMILIES, default_cap=1)
    cands = [cand("p", "model-a"), cand("p", "model-b")]
    panel, events = gate.compose_panel(cands, panel_size=2)
    assert len(panel) == 2
    warns = [e for e in events if e.kind == "fallback_warning"]
    assert warns, "degraded independence must be explicit, never silent"
    assert "distinct families" in warns[-1].detail or "degraded" in warns[-1].detail


def test_underfilled_panel_warns():
    gate = DiversityGate(families=FAMILIES, default_cap=1)
    panel, events = gate.compose_panel([cand("p", "model-a")], panel_size=4)
    assert len(panel) == 1
    assert any("underfilled" in e.detail for e in events if e.kind == "fallback_warning")


def test_per_campaign_cap_override():
    gate = DiversityGate(families=FAMILIES, default_cap=1, campaign_caps={"camp-7": 2})
    cands = [cand("p", "model-a"), cand("p", "model-b"), cand("q", "model-c")]
    panel, _ = gate.compose_panel(cands, panel_size=3, campaign_id="camp-7")
    # cap 2 allows both alpha models plus one beta — no fallback warning needed.
    assert len(panel) == 3
    assert not any(e.kind == "fallback_warning" and "degraded" in e.detail for e in gate.events)


def test_unknown_family_not_grouped_with_known():
    gate = DiversityGate(families=FAMILIES, default_cap=1)
    cands = [cand("x", "unknown-model-1"), cand("y", "unknown-model-2")]
    panel, events = gate.compose_panel(cands, panel_size=2)
    assert len(panel) == 2
    assert all(m.family_unknown for m in panel)
    # Each unknown-family selection flagged (unknown_family kind).
    assert sum(1 for e in events if e.kind == "unknown_family") == 2


def test_invalid_cap_rejected():
    gate = DiversityGate(default_cap=0)
    with pytest.raises(ValueError):
        gate.compose_panel([], panel_size=1)
    gate2 = DiversityGate(default_cap=1, campaign_caps={"bad": 0})
    with pytest.raises(ValueError):
        gate2.compose_panel([], panel_size=1, campaign_id="bad")
