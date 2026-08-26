"""Table-driven tests for review-quorum edge semantics (issue #142)."""

import pytest

from findings.lifecycle import LifecycleError
from findings.quorum import (
    QuorumOutcome,
    QuorumPolicy,
    can_open_discussion,
    evaluate_quorum,
    record_late_dissent,
)


def rv(verdict, blocking=False, reviewer=None, field=None):
    return {
        "reviewer": reviewer or verdict + str(blocking) + str(field),
        "verdict": verdict,
        "blocking_safety_or_validity_objection": blocking,
        "objection_field": field,
    }


def panel(accepts, blocking=0):
    """Panel of 4 with `accepts` accepts and `blocking` blockers."""
    non_blocking_accepts = accepts
    if blocking > 4 - accepts:
        # Some blockers sit inside the accept count.
        non_blocking_accepts = accepts - blocking + (4 - accepts)
        blocking_in_accepts = blocking - (4 - accepts)
    else:
        blocking_in_accepts = 0
    reviews = [rv("accept") for _ in range(non_blocking_accepts)]
    reviews += [rv("accept", blocking=True, field="safety") for _ in range(blocking_in_accepts)]
    rejects = 4 - len(reviews) - (blocking - blocking_in_accepts)
    reviews += [rv("reject") for _ in range(rejects)]
    reviews += [
        rv("reject", blocking=True, field="safety") for _ in range(blocking - blocking_in_accepts)
    ]
    assert len(reviews) == 4
    return reviews


POL = QuorumPolicy()


# --- decision table: every cell ---------------------------------------------


def test_unanimous_accept_no_block_advances():
    out = evaluate_quorum(panel(4), POL)
    assert (out.decision, out.reason) == ("advance", "quorum_unanimous_accept")


def test_unanimous_accept_with_block_holds_by_default():
    reviews = [rv("accept"), rv("accept"), rv("accept"), rv("accept", True, field="safety")]
    out = evaluate_quorum(reviews, POL)
    assert out.decision == "hold"
    assert out.reason == "unanimous_accept_but_blocking_objection"


def test_unanimous_accept_over_block_when_configured():
    pol = QuorumPolicy(allow_unanimous_over_block=True)
    reviews = [rv("accept"), rv("accept"), rv("accept"), rv("accept", True, field="validity")]
    out = evaluate_quorum(reviews, pol)
    assert (out.decision, out.reason) == ("advance", "quorum_unanimous_accept_over_block")


def test_quorum_3_no_block_advances():
    out = evaluate_quorum([rv("accept")] * 3 + [rv("reject")], POL)
    assert (out.decision, out.reason) == ("advance", "quorum_majority_no_block")


def test_quorum_3_with_block_holds():
    reviews = [rv("accept"), rv("accept"), rv("accept", True, field="safety"), rv("reject")]
    out = evaluate_quorum(reviews, POL)
    assert (out.decision, out.reason) == ("hold", "quorum_met_but_blocking_objection")
    assert len(out.blocking_reviewers) == 1


def test_split_2_2_holds_pending_evidence():
    out = evaluate_quorum([rv("accept"), rv("accept"), rv("reject"), rv("reject")], POL)
    assert (out.decision, out.reason) == ("hold", "below_quorum_pending_evidence")


def test_all_reject_first_cycle_reverts():
    out = evaluate_quorum([rv("reject")] * 4, POL, re_review_cycles_used=0)
    assert out.decision == "hold"
    assert out.reason.startswith("all_reject_revert_cycle_1_of_")


def test_all_reject_at_cap_forces_quarantine():
    out = evaluate_quorum([rv("reject")] * 4, POL, re_review_cycles_used=2)
    assert (out.decision, out.reason) == (
        "force_quarantine",
        "all_reject_re_review_cap_exhausted",
    )


def test_all_reject_cap_zero_immediate_quarantine():
    pol = QuorumPolicy(max_re_review_cycles=0)
    out = evaluate_quorum([rv("reject")] * 4, pol, re_review_cycles_used=0)
    assert out.decision == "force_quarantine"


def test_custom_quorum_2_respected():
    pol = QuorumPolicy(quorum_accepts=2)
    out = evaluate_quorum([rv("accept"), rv("accept"), rv("reject"), rv("reject")], pol)
    assert out.decision == "advance"


# --- blocking-field semantics -------------------------------------------------


def test_severity_conflict_never_blocks():
    reviews = [
        rv("accept"),
        rv("accept"),
        rv("accept"),
        rv("reject", True, field="severity"),  # non-blocking field cited
    ]
    out = evaluate_quorum(reviews, POL)
    assert out.decision == "advance" and not out.blocking_reviewers


def test_flag_without_field_blocks_conservatively():
    reviews = [rv("accept"), rv("accept"), rv("accept"), rv("reject", True)]
    out = evaluate_quorum(reviews, POL)
    assert out.decision == "hold"


def test_non_blocking_field_list_configurable():
    pol = QuorumPolicy(blocking_fields=("safety",))
    reviews = [
        rv("accept"),
        rv("accept"),
        rv("accept"),
        rv("reject", True, field="validity"),
    ]
    assert evaluate_quorum(reviews, pol).decision == "advance"


# --- mode / discussion gating ---------------------------------------------------


def test_independent_first_requires_full_blind_panel():
    pol = QuorumPolicy(mode="independent_first", blind_review_count=4)
    assert can_open_discussion(pol, 3) is False
    assert can_open_discussion(pol, 4) is True


def test_discussion_first_always_allows_discussion():
    pol = QuorumPolicy(mode="discussion_first")
    assert can_open_discussion(pol, 1) is True


def test_unknown_mode_rejected():
    with pytest.raises(LifecycleError):
        QuorumPolicy(mode="chaos")


def test_invalid_policy_values_rejected():
    with pytest.raises(LifecycleError):
        QuorumPolicy(quorum_accepts=0)
    with pytest.raises(LifecycleError):
        QuorumPolicy(max_re_review_cycles=-1)
    with pytest.raises(LifecycleError):
        QuorumPolicy(blind_review_count=0)


# --- incomplete panels / determinism --------------------------------------------


def test_incomplete_panel_raises():
    with pytest.raises(LifecycleError):
        evaluate_quorum([rv("accept")], POL)


def test_order_independent():
    a = [rv("accept"), rv("accept", True, field="safety"), rv("accept"), rv("reject")]
    b = list(reversed(a))
    oa, ob = evaluate_quorum(a, POL), evaluate_quorum(b, POL)
    assert (oa.decision, oa.reason) == (ob.decision, ob.reason)


def test_outcome_dataclass_shape():
    out = evaluate_quorum(panel(3), POL)
    assert isinstance(out, QuorumOutcome)
    assert out.accepts == 3 and out.rejects == 1 and out.blocking_reviewers == []


# --- late dissent -----------------------------------------------------------------


def test_late_dissent_appends_without_mutating_original():
    reviews = [{"reviewer": "r1", "verdict": "accept"}, {"reviewer": "r2", "verdict": "accept"}]
    original = dict(reviews[0])
    amend = record_late_dissent(reviews, "r1", "reject", note="changed my mind")
    assert amend["kind"] == "amendment"
    assert amend["previous_verdict"] == "accept"
    assert amend["verdict"] == "reject"
    assert reviews[0] == original  # untouched
    reviews.append(amend)  # append-only growth is the only mutation


def test_amendment_from_unknown_reviewer_rejected():
    with pytest.raises(LifecycleError):
        record_late_dissent([{"reviewer": "r1", "verdict": "accept"}], "ghost", "reject")
