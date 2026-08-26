"""Unit tests for the severity scoring rubric (issue #239, PLAN §10.3).

Table-driven over: deterministic axis→severity mapping, rationale-required
severity changes with diff-visible history, reviewer-disagreement escalation,
and ambiguous-impact fixtures that must resolve consistently.
"""

from __future__ import annotations

import uuid

import pytest

from findings.lifecycle import Finding, RecordStore
from findings.severity import (
    ESCALATION_GAP,
    RUBRIC_VERSION,
    Severity,
    SeverityError,
    assess,
    escalation_required,
    record_severity,
)


def _axes(**overrides) -> dict:
    base = {
        "confidentiality": 0,
        "integrity": 0,
        "availability": 0,
        "reachability": 0,
        "preconditions": 0,
    }
    base.update(overrides)
    return base


# -- deterministic mapping ---------------------------------------------------


@pytest.mark.parametrize(
    ("axes", "expected"),
    [
        (_axes(), "NONE"),
        (_axes(confidentiality=1), "LOW"),
        (_axes(confidentiality="high"), "HIGH"),
        (_axes(reachability=4, confidentiality=4), "CRITICAL"),  # bump clamps at top
        (_axes(availability="critical"), "CRITICAL"),  # no damp without preconditions
        (_axes(preconditions="high", integrity="medium"), "LOW"),  # medium impact damped
        (_axes(integrity="high", reachability=4), "CRITICAL"),  # high +1
        (
            _axes(
                confidentiality="high",
                integrity="high",
                availability="high",
                reachability="high",
                preconditions="high",
            ),
            "HIGH",  # critical impact damped one level by heavy preconditions
        ),
    ],
)
def test_axis_mapping_table(axes: dict, expected: str) -> None:
    assert assess(axes)["severity"] == expected


def test_identical_inputs_resolve_identically() -> None:
    a = assess(_axes(confidentiality=2, reachability=3, preconditions=1))
    b = assess(_axes(confidentiality="medium", reachability="high", preconditions=1))
    assert a["severity"] == b["severity"] == "HIGH"
    assert a["impact_anchor"] == b["impact_anchor"] == "MEDIUM"


def test_rubric_version_present() -> None:
    result = assess(_axes(integrity=2))
    assert result["rubric_version"] == RUBRIC_VERSION


# -- validation ----------------------------------------------------------------


def test_missing_or_unknown_axes_rejected() -> None:
    with pytest.raises(SeverityError):
        assess({"confidentiality": 1})
    with pytest.raises(SeverityError):
        assess(_axes(nuclear=3))


@pytest.mark.parametrize("bad", [-1, 5, True, "banana"])
def test_invalid_axis_values_rejected(bad) -> None:
    with pytest.raises(ValueError):
        assess(_axes(confidentiality=bad))


# -- justification prompts ------------------------------------------------------


def test_prompts_only_for_nonzero_axes() -> None:
    none = assess(_axes())
    some = assess(_axes(reachability=2, availability=1))
    assert none["justification_prompts"] == []
    assert len(some["justification_prompts"]) == 2


# -- severity changes require rationale + are diff-visible -----------------------


def _finding() -> Finding:
    f = Finding.create(campaign_uuid=str(uuid.uuid4()), title="t")
    f.state = "impact_analysis"
    return f


def test_change_without_rationale_rejected() -> None:
    f = _finding()
    store = RecordStore()
    entry = record_severity(f, store, "agent-a", _axes(integrity=2), "initial triage")
    assert entry["previous_severity"] is None
    assert f.severity == "MEDIUM"
    with pytest.raises(SeverityError):
        record_severity(f, store, "agent-b", _axes(integrity=4), "")


def test_change_records_previous_severity_and_rationale() -> None:
    f = _finding()
    store = RecordStore()
    record_severity(f, store, "agent-a", _axes(integrity=2), "initial triage")
    second = record_severity(
        f, store, "agent-b", _axes(integrity=4, reachability=4), "found auth bypass"
    )
    assert second["previous_severity"] == "MEDIUM"
    assert second["severity"] == "CRITICAL"
    assert second["rationale"] == "found auth bypass"
    assert second["actor"] == "agent-b"
    assert f.severity == "CRITICAL"


# -- reviewer disagreement escalation --------------------------------------------


def test_escalation_gap_exceeded_escalates_not_averages() -> None:
    verdict = escalation_required(["low", "critical"])
    assert verdict["escalated"] is True
    assert verdict["spread"] >= ESCALATION_GAP
    assert "escalat" in verdict["reason"].lower()


def test_small_disagreement_resolves_to_midpoint() -> None:
    verdict = escalation_required(["medium", "high"])
    assert verdict["escalated"] is False
    assert verdict["resolution"] == "MEDIUM"


def test_unanimous_reviewers_never_escalate() -> None:
    verdict = escalation_required([Severity.CRITICAL] * 4)
    assert verdict["escalated"] is False
    assert verdict["spread"] == 0


def test_boundary_spread_equals_gap_escalates() -> None:
    assert escalation_required(["none", "medium"])["escalated"] is True
    assert escalation_required(["low", "medium"])["escalated"] is False


def test_single_severity_rejected() -> None:
    with pytest.raises(SeverityError):
        escalation_required(["high"])


# -- ambiguous-impact fixtures must resolve consistently --------------------------

AMBIGUOUS_FIXTURES = [
    # DoS-only with heavy preconditions: high availability damped to MEDIUM.
    (_axes(availability=3, preconditions=3), "MEDIUM"),
    # Unauthenticated read of public data only: impact NONE stays NONE
    # (clamped — reachability alone can never create severity).
    (_axes(reachability=4), "LOW"),
    # Authenticated full DB read: confidentiality critical, damp → HIGH.
    (_axes(confidentiality=4, reachability=2, preconditions=2), "CRITICAL"),
]


@pytest.mark.parametrize(("axes", "expected"), AMBIGUOUS_FIXTURES)
def test_ambiguous_fixtures_deterministic(axes: dict, expected: str) -> None:
    results = {assess(dict(axes))["severity"] for _ in range(5)}
    assert results == {expected}
