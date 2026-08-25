"""Unit tests for the finding lifecycle state machine (PLAN §10)."""

import pytest

from findings.lifecycle import (
    FindingLifecycle,
    LifecycleError,
    RecordStore,
    State,
)


@pytest.fixture()
def lc():
    return FindingLifecycle(RecordStore())


AGENT = "11111111-1111-1111-1111-111111111111"
REVIEWER = "22222222-2222-2222-2222-222222222222"
DISPUTER = "33333333-3333-3333-3333-333333333333"
CAMPAIGN = "44444444-4444-4444-4444-444444444444"


def make_finding(lc):
    res = lc.submit_finding(CAMPAIGN, AGENT, {"title": "SQLi in login", "category": "injection"})
    return res.finding


def claim(lc, finding):
    lc.claim_for_review(finding.finding_uuid, REVIEWER, "2099-01-01T00:00:00+00:00")


def test_submit_creates_in_initial_findings(lc):
    f = make_finding(lc)
    # Record is created in initial_findings then immediately queued into
    # review_cycle_1 (both steps appear in the append-only history).
    hist = lc.store.history(f.finding_uuid)
    assert hist[0].to_state == "initial_findings"
    assert hist[1].to_state == "review_cycle_1"
    assert f.state == State.REVIEW_CYCLE_1


def test_happy_path_through_linear_pipeline(lc):
    f = make_finding(lc)
    claim(lc, f)
    lc.record_first_review(f.finding_uuid, REVIEWER, "confirmed")
    # Advance through impact_analysis .. final_review -> vulnerabilities.
    for _ in range(6):
        lc.advance(f.finding_uuid, REVIEWER)
    f = lc.store.load(f.finding_uuid)
    assert f.state == State.VULNERABILITIES
    lc.finalize_report(f.finding_uuid, REVIEWER)


def test_lease_required_and_single_claim(lc):
    f = make_finding(lc)
    with pytest.raises(LifecycleError):
        lc.record_first_review(f.finding_uuid, REVIEWER, "confirmed")
    claim(lc, f)
    with pytest.raises(LifecycleError):
        lc.claim_for_review(f.finding_uuid, DISPUTER, "2099-01-01T00:00:00+00:00")


def test_illegal_transition_blocked(lc):
    f = make_finding(lc)
    with pytest.raises(LifecycleError):
        lc.advance(f.finding_uuid, AGENT)  # initial_findings cannot advance


def test_dual_confirmation_deletion_keeps_tombstone_history(lc):
    f = make_finding(lc)
    claim(lc, f)
    lc.record_first_review(f.finding_uuid, REVIEWER, "incorrect")
    # Still in review_cycle_1 pending dispute — not deleted.
    assert lc.store.load(f.finding_uuid).state == State.REVIEW_CYCLE_1
    res = lc.resolve_dispute(f.finding_uuid, DISPUTER, supports_finding=False)
    assert res.finding.state == State.DELETED
    # Append-only history preserved (tombstone, not silent removal).
    hist = lc.store.history(f.finding_uuid)
    assert any(t.reason == "dual_confirmation_deletion" for t in hist)
    assert len(hist) >= 3


def test_dispute_overruled_advances_with_dissent_attached(lc):
    f = make_finding(lc)
    claim(lc, f)
    lc.record_first_review(f.finding_uuid, REVIEWER, "incorrect", notes="looks fine")
    res = lc.resolve_dispute(f.finding_uuid, DISPUTER, supports_finding=True)
    assert res.finding.state == State.VALIDATED_OR_DISPUTED
    kinds = [r.get("kind") for r in res.finding.reviews]
    assert "independent_dispute" in kinds
    assert any(r["conclusion"] == "incorrect" for r in res.finding.reviews)


def test_resolve_dispute_without_incorrect_conclusion_rejected(lc):
    f = make_finding(lc)
    claim(lc, f)
    lc.record_first_review(f.finding_uuid, REVIEWER, "confirmed")
    with pytest.raises(LifecycleError):
        lc.resolve_dispute(f.finding_uuid, DISPUTER, supports_finding=False)


def record_four_poc_reviews(lc, uuid_, verdicts):
    for i, v in enumerate(verdicts):
        lc.record_poc_review(uuid_, f"agent-{i}", v)


def test_poc_quorum_all_accept_advances(lc):
    f = make_finding(lc)
    claim(lc, f)
    lc.record_first_review(f.finding_uuid, REVIEWER, "confirmed")
    lc.advance(f.finding_uuid, REVIEWER)  # -> poc path start? no: impact_analysis
    # drive to poc_review
    while lc.store.load(f.finding_uuid).state != State.POC_REVIEW:
        lc.advance(f.finding_uuid, REVIEWER)
    record_four_poc_reviews(lc, f.finding_uuid, ["accept"] * 4)
    res = lc.evaluate_poc_quorum(f.finding_uuid, REVIEWER)
    assert res.finding.state == State.POLISHED_REPORT


def test_poc_quorum_majority_with_no_blocking_objection(lc):
    f = make_finding(lc)
    claim(lc, f)
    lc.record_first_review(f.finding_uuid, REVIEWER, "confirmed")
    while lc.store.load(f.finding_uuid).state != State.POC_REVIEW:
        lc.advance(f.finding_uuid, REVIEWER)
    record_four_poc_reviews(lc, f.finding_uuid, ["accept", "accept", "accept", "reject"])
    res = lc.evaluate_poc_quorum(f.finding_uuid, REVIEWER)
    assert res.finding.state == State.POLISHED_REPORT


def test_poc_majority_blocked_by_safety_objection(lc):
    f = make_finding(lc)
    claim(lc, f)
    lc.record_first_review(f.finding_uuid, REVIEWER, "confirmed")
    while lc.store.load(f.finding_uuid).state != State.POC_REVIEW:
        lc.advance(f.finding_uuid, REVIEWER)
    record_four_poc_reviews(lc, f.finding_uuid, ["accept", "accept", "accept", "reject"])
    # Attach a blocking objection to the rejecting reviewer.
    f_cur = lc.store.load(f.finding_uuid)
    f_cur.poc_reviews[-1]["blocking_safety_or_validity_objection"] = True
    assert lc.evaluate_poc_quorum(f.finding_uuid, REVIEWER) is None


def test_poc_all_reject_quarantines(lc):
    f = make_finding(lc)
    claim(lc, f)
    lc.record_first_review(f.finding_uuid, REVIEWER, "confirmed")
    while lc.store.load(f.finding_uuid).state != State.POC_REVIEW:
        lc.advance(f.finding_uuid, REVIEWER)
    record_four_poc_reviews(lc, f.finding_uuid, ["reject"] * 4)
    res = lc.evaluate_poc_quorum(f.finding_uuid, REVIEWER)
    assert res.finding.state == State.QUARANTINED
    # Quarantine can be released back to post-first-review with new evidence.
    rel = lc.release_quarantine(f.finding_uuid, REVIEWER)
    assert rel.finding.state == State.VALIDATED_OR_DISPUTED


def test_poc_all_reject_can_revert_instead_of_quarantine(lc):
    f = make_finding(lc)
    claim(lc, f)
    lc.record_first_review(f.finding_uuid, REVIEWER, "confirmed")
    while lc.store.load(f.finding_uuid).state != State.POC_REVIEW:
        lc.advance(f.finding_uuid, REVIEWER)
    record_four_poc_reviews(lc, f.finding_uuid, ["reject"] * 4)
    res = lc.revert_from_poc_review(f.finding_uuid, REVIEWER, "needs more evidence")
    assert res.finding.state == State.VALIDATED_OR_DISPUTED


def test_final_report_requires_final_review_passed(lc):
    f = make_finding(lc)
    claim(lc, f)
    lc.record_first_review(f.finding_uuid, REVIEWER, "confirmed")
    with pytest.raises(LifecycleError):
        lc.finalize_report(f.finding_uuid, REVIEWER)


def test_history_is_append_only(lc):
    f = make_finding(lc)
    claim(lc, f)
    lc.record_first_review(f.finding_uuid, REVIEWER, "confirmed")
    before = [t.seq for t in lc.store.history(f.finding_uuid)]
    assert before == sorted(before)
    n = len(before)
    lc.advance(f.finding_uuid, REVIEWER)
    after = lc.store.history(f.finding_uuid)
    assert len(after) == n + 1
    # Earlier entries untouched.
    assert [t.seq for t in after[:n]] == before


def test_content_hash_detects_tampering():
    a = {"x": 1}
    b = {"x": 2}
    from findings.lifecycle import content_hash

    assert content_hash(a) != content_hash(b)
    assert content_hash(a) == content_hash({"x": 1})
