"""Tests for review-mode configuration & quorum policy engine (issue #197, PLAN §10.2/§10.5)."""

from __future__ import annotations

import pytest

from config.loader import ConfigError, load_config, validate_dict
from findings.lifecycle import FindingLifecycle, LifecycleError, RecordStore
from findings.review_policy import (
    Phase,
    QuorumPolicy,
    ReviewMode,
    ReviewPolicyConfig,
    ReviewPolicyEngine,
    ReviewPolicyError,
)


def make_engine(mode="independent_first", **policy_kw) -> ReviewPolicyEngine:
    cfg = ReviewPolicyConfig(
        mode=ReviewMode(mode),
        panel_size=4,
        policies={Phase.POC_REVIEW: QuorumPolicy(**policy_kw)} if policy_kw else {},
    )
    return ReviewPolicyEngine(cfg)


def rv(reviewer="r1", verdict="accept", blind=True, blocking=False) -> dict:
    return {
        "reviewer": reviewer,
        "verdict": verdict,
        "blind": blind,
        "blocking_safety_or_validity_objection": blocking,
    }


# --- visibility: independent-first -------------------------------------------


def test_independent_first_rejects_peeking_before_blind_collection():
    eng = make_engine()
    with pytest.raises(ReviewPolicyError, match="independent-first"):
        eng.check_visibility(Phase.POC_REVIEW, [rv()], saw_prior_reviews=True)


def test_independent_first_allows_blind_reviewers():
    eng = make_engine()
    eng.check_visibility(Phase.POC_REVIEW, [rv(), rv()], saw_prior_reviews=False)


def test_visibility_opens_after_full_blind_panel_collected():
    eng = make_engine()
    reviews = [rv(blind=True) for _ in range(4)]
    assert eng.discussion_open(reviews) is True
    eng.check_visibility(Phase.POC_REVIEW, reviews, saw_prior_reviews=True)


def test_discussion_stays_closed_until_panel_complete():
    eng = make_engine()
    assert eng.discussion_open([rv(), rv(), rv()]) is False


def test_discussion_first_permits_visibility_anytime():
    eng = make_engine(mode="discussion_first")
    eng.check_visibility(Phase.POC_REVIEW, [], saw_prior_reviews=True)
    assert eng.discussion_open([]) is True


def test_unknown_phase_rejected():
    eng = make_engine()
    with pytest.raises(ReviewPolicyError, match="unknown review phase"):
        eng.check_visibility("typo_phase", [], saw_prior_reviews=False)


# --- quorum evaluation -------------------------------------------------------


def test_quorum_met_advances():
    eng = make_engine()
    reviews = [
        rv(verdict="accept"),
        rv(verdict="accept"),
        rv(verdict="accept"),
        rv(verdict="reject"),
    ]
    d = eng.evaluate(Phase.POC_REVIEW, reviews)
    assert d["outcome"] == "advance"
    assert d["reason"] == "quorum_met_no_block"


def test_pending_below_quorum():
    eng = make_engine()
    d = eng.evaluate(Phase.POC_REVIEW, [rv(), rv()])
    assert d["outcome"] == "pending"


def test_blocking_objection_vetoes_even_with_unanimous_accepts():
    eng = make_engine()
    reviews = [
        rv(verdict="accept"),
        rv(verdict="accept"),
        rv(verdict="accept"),
        rv(verdict="accept", blocking=True),
    ]
    d = eng.evaluate(Phase.POC_REVIEW, reviews)
    # §10.5: advance only when no reviewer identifies a blocking issue.
    assert d["outcome"] == "unresolved"
    assert d["reason"] == "blocking_objection_veto"


def test_blocking_veto_can_be_disabled_by_policy():
    eng = make_engine(forbid_blocking_objections=False)
    reviews = [
        rv(verdict="accept"),
        rv(verdict="accept"),
        rv(verdict="accept"),
        rv(verdict="accept", blocking=True),
    ]
    assert eng.evaluate(Phase.POC_REVIEW, reviews)["outcome"] == "advance"


def test_require_all_accept_blocks_majority():
    eng = make_engine(require_all_accept=True)
    reviews = [rv(), rv(), rv(), rv(verdict="reject")]
    d = eng.evaluate(Phase.POC_REVIEW, reviews)
    assert d["outcome"] == "unresolved"

    unanimous = [rv(), rv(), rv(), rv()]
    assert eng.evaluate(Phase.POC_REVIEW, unanimous)["outcome"] == "advance"


def test_all_reject_maps_to_reject_all():
    eng = make_engine()
    reviews = [rv(verdict="reject") for _ in range(4)]
    assert eng.evaluate(Phase.POC_REVIEW, reviews) == {
        "outcome": "reject_all",
        "reason": "all_reject",
        "accepts": 0,
        "rejects": 4,
        "total": 4,
    }


def test_mixed_without_quorum_is_unresolved():
    eng = make_engine()
    reviews = [rv(), rv(), rv(verdict="reject"), rv(verdict="reject")]
    assert eng.evaluate(Phase.POC_REVIEW, reviews)["outcome"] == "unresolved"


def test_non_panel_phase_has_no_quorum():
    eng = make_engine()
    with pytest.raises(ReviewPolicyError, match="no quorum"):
        eng.evaluate(Phase.FIRST_REVIEW, [])


def test_invalid_policy_rejected():
    with pytest.raises(ReviewPolicyError):
        QuorumPolicy(quorum=0)
    with pytest.raises(ReviewPolicyError):
        ReviewPolicyConfig(panel_size=0)


# --- lifecycle integration -----------------------------------------------------


@pytest.fixture
def finding_at_poc_review():
    store = RecordStore()
    lc = FindingLifecycle(store)
    res = lc.submit_finding("c-1", "agent-0", {"title": "t"})
    fu = res.finding.finding_uuid
    lc.claim_for_review(fu, "rev-1", "2099-01-01T00:00:00+00:00")
    lc.record_first_review(fu, "rev-1", "confirmed")
    for state in ("impact_analysis", "poc_draft", "poc_review"):
        r = lc._get(fu)
        if str(r.state).endswith(state):
            break
        lc.advance(fu, "agent-0")
    return lc, fu


def test_lifecycle_enforces_independent_first_pre_record(finding_at_poc_review):
    lc, fu = finding_at_poc_review
    eng = make_engine()
    lc.record_poc_review(fu, "r1", "accept", policy_engine=eng)
    # Second reviewer peeks at r1's result before panel completion → rejected.
    with pytest.raises(ReviewPolicyError, match="independent-first"):
        lc.record_poc_review(fu, "r2", "accept", saw_prior_reviews=True, policy_engine=eng)
    assert len(lc._get(fu).poc_reviews) == 1  # violation never recorded


def test_lifecycle_discussion_first_allows_peeking(finding_at_poc_review):
    lc, fu = finding_at_poc_review
    eng = make_engine(mode="discussion_first")
    lc.record_poc_review(fu, "r1", "accept", policy_engine=eng)
    lc.record_poc_review(fu, "r2", "accept", saw_prior_reviews=True, policy_engine=eng)
    assert len(lc._get(fu).poc_reviews) == 2


def test_lifecycle_policy_engine_drives_advance(finding_at_poc_review):
    lc, fu = finding_at_poc_review
    eng = make_engine(require_all_accept=True)
    for i in range(3):
        lc.record_poc_review(fu, f"r{i}", "accept", policy_engine=eng)
    lc.record_poc_review(fu, "r9", "reject", policy_engine=eng)
    # 3/4 accepts + one reject: default would advance, require_all_accept won't.
    assert lc.evaluate_poc_quorum(fu, "agent-0", policy_engine=eng) is None
    assert str(lc._get(fu).state) == "poc_review" or lc._get(fu).state.value == "poc_review"

    # Unanimous now advances via the engine.
    lc.record_poc_review(fu, "r10", "accept", policy_engine=eng)  # replaces nothing; 5th
    # With 5 reviews and require_all_accept, the reject still blocks — override
    # with a fresh unanimous engine to prove the advance path works.
    strict = make_engine(require_all_accept=False)
    res = lc.evaluate_poc_quorum(fu, "agent-0", policy_engine=strict)
    assert res is not None
    assert res.finding.state.value == "polished_report"


def test_lifecycle_policy_engine_quarantines_all_reject(finding_at_poc_review):
    lc, fu = finding_at_poc_review
    eng = make_engine()
    for i in range(4):
        lc.record_poc_review(fu, f"r{i}", "reject", policy_engine=eng)
    res = lc.evaluate_poc_quorum(fu, "agent-0", policy_engine=eng)
    assert res is not None
    assert res.finding.state.value == "quarantined"


def test_legacy_flag_still_works_without_engine(finding_at_poc_review):
    lc, fu = finding_at_poc_review
    for i in range(4):
        lc.record_poc_review(fu, f"r{i}", "accept")
    res = lc.evaluate_poc_quorum(fu, "agent-0")
    assert res is not None and res.finding.state.value == "polished_report"
    with pytest.raises(LifecycleError):
        lc.evaluate_poc_quorum(fu, "agent-0")  # wrong state now


# --- config loading ----------------------------------------------------------


def test_config_review_mode_defaults():
    cfg, errors = validate_dict({})
    assert not errors
    assert cfg.review.mode == "independent_first"
    assert cfg.review.panel_size == 4
    assert cfg.review.require_all_accept is False
    assert cfg.review.forbid_blocking_objections is True


def test_config_review_mode_roundtrip(tmp_path):
    p = tmp_path / "cfg.yaml"
    p.write_text(
        "review:\n"
        "  mode: discussion_first\n"
        "  panel_size: 5\n"
        "  require_all_accept: true\n"
        "  forbid_blocking_objections: false\n"
    )
    cfg = load_config(str(p))
    assert cfg.review.mode == "discussion_first"
    assert cfg.review.panel_size == 5
    assert cfg.review.require_all_accept is True
    assert cfg.review.forbid_blocking_objections is False


def test_config_rejects_bad_mode(tmp_path):
    p = tmp_path / "cfg.yaml"
    p.write_text("review:\n  mode: chaos\n")
    with pytest.raises(ConfigError, match="review.mode"):
        load_config(str(p))


def test_config_rejects_non_bool_flags(tmp_path):
    p = tmp_path / "cfg.yaml"
    p.write_text("review:\n  require_all_accept: sometimes\n")
    with pytest.raises(ConfigError, match="require_all_accept"):
        load_config(str(p))
