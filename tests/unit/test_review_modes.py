"""Unit tests for policy/review_modes.py (issue #197, PLAN §10.2/§10.5)."""

import pytest

from policy.review_modes import (
    AdvanceDecision,
    QuorumPolicy,
    ReviewConfigError,
    ReviewerVerdict,
    ReviewMode,
    Verdict,
)


def v(verdict=Verdict.ACCEPT, blocking=False, reviewer="r"):
    return ReviewerVerdict(reviewer_id=reviewer, verdict=verdict, blocking_issue=blocking)


# -- config validation -------------------------------------------------------


def test_quorum_above_panel_size_rejected():
    with pytest.raises(ReviewConfigError):
        QuorumPolicy(panel_size=4, accept_quorum=5)


def test_invalid_panel_size_rejected():
    with pytest.raises(ReviewConfigError):
        QuorumPolicy(panel_size=0)


def test_defaults_match_plan_105():
    p = QuorumPolicy()
    assert p.mode is ReviewMode.INDEPENDENT_FIRST
    assert (p.panel_size, p.accept_quorum) == (4, 4)


# -- evaluation ---------------------------------------------------------------


def test_unanimous_accept_advances():
    out = QuorumPolicy().evaluate([v(reviewer=str(i)) for i in range(4)])
    assert out["decision"] is AdvanceDecision.ADVANCE
    assert "unanimous" in out["reason"]


def test_quorum_with_dissent_advances_and_attaches_dissents():
    verdicts = [v() for _ in range(3)] + [v(Verdict.REJECT, reviewer="dissent-1")]
    out = QuorumPolicy(panel_size=4, accept_quorum=3).evaluate(verdicts)
    assert out["decision"] is AdvanceDecision.ADVANCE
    assert len(out["dissents"]) == 1
    assert out["dissents"][0].reviewer_id == "dissent-1"


def test_below_quorum_fails():
    verdicts = [v() for _ in range(2)] + [v(Verdict.REJECT) for _ in range(2)]
    out = QuorumPolicy().evaluate(verdicts)
    assert out["decision"] is AdvanceDecision.QUORUM_FAILED


def test_blocking_issue_overrides_unanimous_accept():
    # Hard safety layer: even unanimous accept cannot waive a blocker.
    verdicts = [v(), v(), v(), v(blocking=True)]
    out = QuorumPolicy().evaluate(verdicts)
    assert out["decision"] is AdvanceDecision.QUORUM_FAILED
    assert "blocking" in out["reason"]


def test_all_reject_is_terminal_all_rejected():
    verdicts = [v(Verdict.REJECT, reviewer=str(i)) for i in range(4)]
    out = QuorumPolicy().evaluate(verdicts)
    assert out["decision"] is AdvanceDecision.ALL_REJECTED


def test_insufficient_reviews_keeps_collecting():
    out = QuorumPolicy().evaluate([v()])
    assert out["decision"] is AdvanceDecision.INSUFFICIENT_REVIEWS


def test_split_verdict_with_blocking_from_minority_blocks():
    verdicts = [v() for _ in range(3)] + [v(Verdict.REJECT, blocking=True)]
    out = QuorumPolicy(panel_size=4, accept_quorum=3).evaluate(verdicts)
    assert out["decision"] is AdvanceDecision.QUORUM_FAILED


# -- re-review caps ------------------------------------------------------------


def test_rereview_cap_enforced():
    p = QuorumPolicy(max_rounds=2)
    assert p.can_rereview(1)
    assert not p.can_rereview(2)


def test_both_modes_evaluate_identically_on_same_verdicts():
    verdicts = [v() for _ in range(4)]
    for mode in ReviewMode:
        out = QuorumPolicy(mode=mode).evaluate(list(verdicts))
        assert out["decision"] is AdvanceDecision.ADVANCE
