"""Tests for the deterministic severity rubric (PLAN §10.3, issue #239).

Covers:
- Determinism: same axes → same severity, order-independent.
- Full band coverage of the weighted-score mapping.
- Severity changes require rationale and produce diff-visible entries.
- Reviewer disagreement spanning ≥ N levels escalates instead of averaging.
- Ambiguous-impact fixtures: underspecified narratives that must still
  resolve consistently once their axes are recorded.
"""

import pytest

from findings.lifecycle import LifecycleError
from findings.severity_rubric import (
    AXIS_WEIGHTS,
    ImpactAssessment,
    RubricError,
    Severity,
    apply_severity_change,
    assess_severity,
    evaluate_severity_panel,
    justification_prompt,
    score_to_severity,
    weighted_score,
)


def axes(**overrides) -> ImpactAssessment:
    """Baseline assessment with per-axis overrides for brevity."""
    base = dict(
        confidentiality=0,
        integrity=0,
        availability=0,
        reachability=0,
        preconditions=0,
    )
    base.update(overrides)
    return ImpactAssessment(**base)


# --- Determinism -------------------------------------------------------------


def test_same_axes_always_resolve_identically():
    a = axes(confidentiality=3, integrity=2, availability=1, reachability=3, preconditions=2)
    b = axes(preconditions=2, availability=1, integrity=2, confidentiality=3, reachability=3)
    assert assess_severity(a) == assess_severity(b) == Severity.HIGH


def test_zero_axes_is_none_and_maxes_are_critical():
    assert assess_severity(axes()) == Severity.NONE
    top = axes(confidentiality=3, integrity=3, availability=3, reachability=3, preconditions=3)
    assert assess_severity(top) == Severity.CRITICAL


# --- Band coverage ------------------------------------------------------------


def test_every_band_boundary_maps_to_expected_level():
    # Construct scores exactly at each inclusive upper bound.
    assert score_to_severity(0.0) == Severity.NONE
    assert score_to_severity(6.0) == Severity.LOW
    assert score_to_severity(12.0) == Severity.MEDIUM
    assert score_to_severity(19.0) == Severity.HIGH
    assert score_to_severity(25.5) == Severity.CRITICAL
    # Just past a boundary moves up a band.
    assert score_to_severity(6.5) == Severity.MEDIUM
    assert score_to_severity(19.5) == Severity.CRITICAL


def test_monotonic_in_each_axis():
    baseline = weighted_score(axes())
    for name in AXIS_WEIGHTS:
        bumped = axes(**{name: 1})
        assert weighted_score(bumped) > baseline


# --- Input validation (ambiguity must be explicit, not absorbed) -------------


@pytest.mark.parametrize("bad", [-1, 4, 1.5, "2", None])
def test_out_of_range_axis_rejected(bad):
    kwargs = dict(confidentiality=0, integrity=0, availability=0, reachability=0, preconditions=0)
    kwargs["integrity"] = bad
    with pytest.raises(RubricError):
        ImpactAssessment(**kwargs)


def test_bool_is_not_a_valid_axis_value():
    with pytest.raises(RubricError):
        ImpactAssessment(
            confidentiality=True,
            integrity=0,
            availability=0,
            reachability=0,
            preconditions=0,
        )


# --- Justification prompts ----------------------------------------------------


def test_justification_prompt_cites_all_axes():
    prompt = justification_prompt(Severity.HIGH)
    for axis in AXIS_WEIGHTS:
        assert axis in prompt
    assert "high" in prompt


# --- Severity changes: rationale + diff visibility ----------------------------


def test_change_requires_rationale():
    with pytest.raises(RubricError):
        apply_severity_change("f-1", Severity.LOW, Severity.HIGH, "   ")
    entry = apply_severity_change("f-1", Severity.LOW, Severity.HIGH, "found auth bypass")
    assert entry.previous_severity == "low"
    assert entry.new_severity == "high"
    assert entry.rationale == "found auth bypass"


def test_noop_change_refused():
    with pytest.raises(RubricError):
        apply_severity_change("f-1", Severity.MEDIUM, Severity.MEDIUM, "no reason")


def test_change_entry_is_diff_visible_across_stages():
    entry = apply_severity_change(
        "f-9",
        Severity.MEDIUM,
        Severity.CRITICAL,
        "impact analysis found tenant escape",
        stage_from="review_cycle_1",
        stage_to="impact_analysis",
    )
    assert entry.kind == "severity_change"
    assert entry.stage_from == "review_cycle_1"
    assert entry.stage_to == "impact_analysis"
    # A reader of the history sees before/after without recomputing anything.
    assert (entry.previous_severity, entry.new_severity) == ("medium", "critical")


# --- Reviewer disagreement / escalation ---------------------------------------


def rv(reviewer, sev):
    return {"reviewer": reviewer, "proposed_severity": sev}


def test_unanimous_panel_agrees():
    out = evaluate_severity_panel([rv("a", "high"), rv("b", "high"), rv("c", "high")])
    assert out.decision == "agree"
    assert out.resolved_severity == "high"


def test_minor_disagreement_resolves_to_median_not_average():
    out = evaluate_severity_panel([rv("a", "low"), rv("b", "medium"), rv("c", "medium")])
    assert out.decision == "agree"
    assert out.resolved_severity == "medium"


def test_two_level_spread_escalates_instead_of_averaging():
    # low → critical is a 3-level span; averaging would say 'medium'.
    out = evaluate_severity_panel([rv("a", "low"), rv("b", "critical")])
    assert out.decision == "escalate"
    assert out.resolved_severity is None
    assert out.span >= 2


def test_exactly_at_threshold_escalates():
    # none → high spans 3 indices with default threshold 2.
    out = evaluate_severity_panel([rv("a", "none"), rv("b", "high"), rv("c", "medium")])
    assert out.decision == "escalate"


def test_below_threshold_does_not_escalate():
    panel = [rv("a", "low"), rv("b", "medium"), rv("c", "high"), rv("d", "high")]
    out = evaluate_severity_panel(panel, escalation_span=3)
    assert out.decision == "agree"
    assert out.resolved_severity == Severity.HIGH.value  # median index of [low,medium,high,high]


def test_unknown_proposed_severity_rejected():
    with pytest.raises(RubricError):
        evaluate_severity_panel([rv("a", "catastrophic")])


def test_empty_panel_rejected():
    with pytest.raises(LifecycleError):
        evaluate_severity_panel([])


# --- Ambiguous-impact fixtures -------------------------------------------------
# Narratives under-specify impact; once axes are recorded the rubric must
# resolve each to ONE consistent level regardless of who evaluates it.


AMBIGUOUS_FIXTURES = [
    # "Reads some config file" — which file? But unauthenticated remote read
    # of any file is at least a real confidentiality hit with no preconds.
    {
        "narrative": "Unauthenticated endpoint returns contents of an internal config file.",
        "assessment": dict(
            confidentiality=2, integrity=0, availability=0, reachability=3, preconditions=3
        ),
        "expected": Severity.MEDIUM,
    },
    # "Might allow code execution" — hedged, but if integrity is fully
    # compromised remotely with no preconditions it lands high.
    {
        "narrative": "Deserialized user input may execute code under some conditions.",
        "assessment": dict(
            confidentiality=1, integrity=3, availability=1, reachability=3, preconditions=2
        ),
        "expected": Severity.HIGH,
    },
    # "Slow requests when cache misses" — mild DoS with preconditions.
    {
        "narrative": "Crafted queries occasionally exhaust worker threads.",
        "assessment": dict(
            confidentiality=0, integrity=0, availability=1, reachability=2, preconditions=1
        ),
        "expected": Severity.LOW,
    },
]


@pytest.mark.parametrize(
    "fixture", AMBIGUOUS_FIXTURES, ids=[f["narrative"][:30] for f in AMBIGUOUS_FIXTURES]
)
def test_ambiguous_fixture_resolves_consistently(fixture):
    a1 = axes(**fixture["assessment"])
    a2 = axes(**dict(reversed(list(fixture["assessment"].items()))))
    assert assess_severity(a1) == assess_severity(a2) == fixture["expected"]
