"""Tests for the deterministic severity rubric (issue #239, PLAN §10.3)."""

from __future__ import annotations

import pytest

from findings.severity import (
    DEFAULT_ESCALATION_THRESHOLD,
    Impact,
    ImpactAssessment,
    Reachability,
    RubricError,
    Severity,
    SeverityHistory,
    SeverityVote,
    dissenting_rationales,
    evaluate_disagreement,
    justification_prompts,
    score_severity,
)


def assess(**overrides) -> ImpactAssessment:
    """Canonical 'remote unauth RCE-ish' baseline with per-field overrides."""
    fields = dict(
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.HIGH,
        reachability=Reachability.REMOTE_NO_AUTH,
    )
    fields.update(overrides)
    return ImpactAssessment(**fields)


# ---------------------------------------------------------------------------
# Determinism: same inputs → same level, always
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "assessment,expected",
    [
        # Remote, no auth, full CIA compromise → CRITICAL.
        (assess(), Severity.CRITICAL),
        # Remote unauth but only availability impact (one HIGH axis).
        (assess(confidentiality=Impact.NONE, integrity=Impact.NONE), Severity.HIGH),
        # All axes none/low, remote unauth → LOW-ish floor from reachability.
        (
            assess(confidentiality=Impact.LOW, integrity=Impact.LOW, availability=Impact.LOW),
            Severity.HIGH,
        ),
        # Auth required pulls it down a notch from the remote_no_auth base.
        (assess(reachability=Reachability.REMOTE_AUTH), Severity.CRITICAL),
        # Local-only, single low axis → LOW.
        (
            assess(
                confidentiality=Impact.LOW,
                integrity=Impact.NONE,
                availability=Impact.NONE,
                reachability=Reachability.LOCAL,
            ),
            Severity.LOW,
        ),
        # Theoretical, nothing at all → NONE.
        (
            assess(
                confidentiality=Impact.NONE,
                integrity=Impact.NONE,
                availability=Impact.NONE,
                reachability=Reachability.THEORETICAL,
            ),
            Severity.NONE,
        ),
        # Privileged access drops the critical-looking case exactly one
        # notch (4 + 1 - 1 = 4): still CRITICAL, justification shows it.
        (assess(requires_privileged_access=True), Severity.CRITICAL),
    ],
)
def test_rubric_is_deterministic(assessment: ImpactAssessment, expected: Severity):
    level, justifications = score_severity(assessment)
    assert level == expected
    # Every rating carries an auditable justification trail.
    assert justifications
    assert all(isinstance(j, str) and j for j in justifications)
    # Same input twice → identical output including justification text.
    assert score_severity(assessment) == (level, justifications)


def test_fingerprint_dedupes_equivalent_assessments():
    assert assess().fingerprint() == assess().fingerprint()
    assert assess().fingerprint() != assess(reachability=Reachability.LOCAL).fingerprint()


# ---------------------------------------------------------------------------
# Ambiguous-impact fixtures: must resolve consistently despite vagueness
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture,expected",
    [
        # "Might leak some data over the network" — ambiguous wording but
        # structurally all-low CIA (capped at MEDIUM) + remote_auth.
        (
            assess(
                confidentiality=Impact.LOW,
                integrity=Impact.NONE,
                availability=Impact.NONE,
                reachability=Reachability.REMOTE_AUTH,
            ),
            Severity.LOW,
        ),
        # "DoS maybe" — only low availability, needs user interaction: 1-1=0.
        (
            assess(
                confidentiality=Impact.NONE,
                integrity=Impact.NONE,
                availability=Impact.LOW,
                requires_user_interaction=True,
            ),
            Severity.LOW,
        ),
        # "Full compromise but only behind admin panel with non-default
        # config" — high CIA (floor 4) minus two precondition penalties.
        (assess(requires_privileged_access=True, requires_unusual_config=True), Severity.HIGH),
    ],
)
def test_ambiguous_fixtures_resolve_consistently(fixture: ImpactAssessment, expected: Severity):
    for _ in range(3):  # repeat: rubric has no hidden state
        assert score_severity(fixture)[0] == expected


# ---------------------------------------------------------------------------
# Justification prompts
# ---------------------------------------------------------------------------


def test_prompts_cover_every_nonzero_axis():
    prompts = justification_prompts(
        assess(confidentiality=Impact.NONE, integrity=Impact.LOW, availability=Impact.NONE)
    )
    assert "integrity" in prompts and "confidentiality" not in prompts
    assert "reachability" in prompts  # always required


def test_invalid_input_rejected():
    with pytest.raises(RubricError):
        score_severity({"confidentiality": "high"})  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Transitions: rationale-required + diff-visible history
# ---------------------------------------------------------------------------


def test_transition_requires_rationale():
    history = SeverityHistory(initial=Severity.MEDIUM)
    with pytest.raises(RubricError):
        history.transition(Severity.HIGH, rationale="   ", stage="impact_analysis")


def test_history_diff_visible():
    history = SeverityHistory(initial=Severity.LOW)
    history.transition(Severity.MEDIUM, "confirmed auth bypass", stage="impact_analysis")
    history.transition(Severity.LOW, "mitigation ships by default", stage="poc_review")
    diffs = history.diff()
    assert len(diffs) == 2
    assert "low -> medium" in diffs[0] and "[impact_analysis]" in diffs[0]
    assert "medium -> low" in diffs[1] and "downgraded" in diffs[1]
    assert history.current == Severity.LOW


# ---------------------------------------------------------------------------
# Reviewer disagreement: escalate, never average
# ---------------------------------------------------------------------------


def _votes(*levels: Severity) -> list[SeverityVote]:
    return [SeverityVote(reviewer_id=f"r{i}", level=lvl) for i, lvl in enumerate(levels)]


def test_spread_below_threshold_advances_with_median():
    decision, consensus = evaluate_disagreement(
        _votes(Severity.LOW, Severity.MEDIUM, Severity.MEDIUM)
    )
    assert decision == "ADVANCE"
    assert consensus == Severity.MEDIUM


def test_spread_at_threshold_escalates():
    # LOW..HIGH is a spread of exactly the default threshold (2).
    decision, consensus = evaluate_disagreement(
        _votes(Severity.LOW, Severity.MEDIUM, Severity.HIGH)
    )
    assert decision == "ESCALATE"
    assert consensus is None


def test_wild_disagreement_never_averages():
    decision, consensus = evaluate_disagreement(
        _votes(Severity.NONE, Severity.NONE, Severity.CRITICAL, Severity.CRITICAL)
    )
    assert decision == "ESCALATE"
    assert consensus is None


def test_custom_threshold():
    tight = 1
    assert (
        evaluate_disagreement(_votes(Severity.LOW, Severity.MEDIUM), threshold=tight)[0]
        == "ESCALATE"
    )
    assert DEFAULT_ESCALATION_THRESHOLD == 2


def test_single_vote_rejected():
    with pytest.raises(RubricError):
        evaluate_disagreement(_votes(Severity.HIGH))


def test_dissent_kept_visible():
    votes = _votes(Severity.LOW, Severity.MEDIUM, Severity.MEDIUM)
    decision, consensus = evaluate_disagreement(votes)
    dissent = dissenting_rationales(votes, consensus)
    assert decision == "ADVANCE"
    assert len(dissent) == 1 and dissent[0].startswith("r0")
