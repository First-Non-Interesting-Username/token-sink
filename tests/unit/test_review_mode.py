"""Tests for policy/review_mode.py (issue #197, PLAN §10.2/§10.5)."""

import pytest

from policy.review_mode import (
    QuorumDecision,
    ReviewModeConfig,
    ReviewPolicyError,
    can_start_reReview,
    evaluate_quorum,
    re_reviews_used,
)


def review(verdict="accept", blocking=False, uuid="a-1", family=None):
    r = {
        "verdict": verdict,
        "blocking_safety_or_validity_objection": blocking,
        "reviewer_agent_uuid": uuid,
    }
    if family:
        r["model_family"] = family
    return r


# -- config validation -------------------------------------------------------


def test_default_config_is_independent_first():
    cfg = ReviewModeConfig()
    assert cfg.mode == "independent_first"
    assert not cfg.can_see_prior_reviews()


def test_discussion_first_allows_visibility():
    cfg = ReviewModeConfig(mode="discussion_first")
    assert cfg.can_see_prior_reviews()


def test_unknown_mode_rejected():
    with pytest.raises(ReviewPolicyError):
        ReviewModeConfig(mode="chaos")


def test_bad_quorum_rejected():
    with pytest.raises(ReviewPolicyError):
        ReviewModeConfig(quorum=0)
    with pytest.raises(ReviewPolicyError):
        ReviewModeConfig(max_reReviews=-1)


# -- quorum evaluation -------------------------------------------------------


def test_unanimous_accept_advances():
    cfg = ReviewModeConfig(require_all_accept=True)
    reviews = [review(uuid=f"a{i}") for i in range(4)]
    d = evaluate_quorum(reviews, cfg, panel_size=4)
    assert isinstance(d, QuorumDecision)
    assert d.outcome == "advance"
    assert d.reason == "unanimous_accept"


def test_quorum_majority_no_block_advances():
    cfg = ReviewModeConfig(quorum=3)
    reviews = [
        review("accept", uuid="a"),
        review("accept", uuid="b"),
        review("accept", uuid="c"),
        review("reject", uuid="d"),
    ]
    d = evaluate_quorum(reviews, cfg, 4)
    assert d.outcome == "advance"
    assert d.reason == "quorum_no_block"


def test_blocking_objection_prevents_majority_advance():
    cfg = ReviewModeConfig(quorum=2)
    reviews = [
        review("accept", uuid="a"),
        review("accept", uuid="b"),
        review("reject", blocking=True, uuid="c"),
        review("abstain", uuid="d"),
    ]
    d = evaluate_quorum(reviews, cfg, 4)
    assert d.outcome == "unresolved"
    assert d.reason == "blocked_by_objection"


def test_insufficient_accepts_unresolved():
    cfg = ReviewModeConfig(quorum=4)
    reviews = [
        review("accept", uuid="a"),
        review("accept", uuid="b"),
        review("abstain", uuid="c"),
        review("reject", uuid="d"),
    ]
    d = evaluate_quorum(reviews, cfg, 4)
    assert d.outcome == "unresolved"


def test_all_reject_quarantines():
    cfg = ReviewModeConfig()
    reviews = [review("reject", uuid=f"r{i}") for i in range(4)]
    d = evaluate_quorum(reviews, cfg, 4)
    assert d.outcome == "quarantine"


def test_require_all_accept_forbids_majority_path():
    cfg = ReviewModeConfig(require_all_accept=True, quorum=1)
    reviews = [review("accept", uuid="a"), review("abstain", uuid="b")]
    d = evaluate_quorum(reviews, cfg, 2)
    assert d.outcome == "unresolved"
    assert d.reason == "require_all_accept_not_met"


def test_wrong_panel_size_rejected():
    cfg = ReviewModeConfig()
    with pytest.raises(ReviewPolicyError):
        evaluate_quorum([review()], cfg, panel_size=4)


def test_duplicate_reviewers_rejected():
    cfg = ReviewModeConfig()
    reviews = [review(uuid="same") for _ in range(4)]
    with pytest.raises(ReviewPolicyError):
        evaluate_quorum(reviews, cfg, 4)


# -- model-family diversity --------------------------------------------------


def test_diversity_required_but_missing_families():
    cfg = ReviewModeConfig(require_model_family_diversity=True)
    reviews = [review(uuid=f"a{i}") for i in range(4)]
    with pytest.raises(ReviewPolicyError):
        evaluate_quorum(reviews, cfg, 4)


def test_diversity_single_family_rejected():
    cfg = ReviewModeConfig(require_model_family_diversity=True)
    reviews = [review(uuid=f"a{i}", family="claude") for i in range(4)]
    with pytest.raises(ReviewPolicyError):
        evaluate_quorum(reviews, cfg, 4)


def test_diversity_satisfied():
    cfg = ReviewModeConfig(require_model_family_diversity=True)
    families = ["claude", "gpt", "gemini", "llama"]
    reviews = [review(uuid=f"a{i}", family=f) for i, f in enumerate(families)]
    d = evaluate_quorum(reviews, cfg, 4)
    assert d.diversity_ok
    assert d.outcome == "advance"


def test_no_diversity_requirement_skips_check():
    cfg = ReviewModeConfig()
    reviews = [review(uuid=f"a{i}", family="claude") for i in range(4)]
    d = evaluate_quorum(reviews, cfg, 4)
    assert d.diversity_ok


# -- re-review caps ----------------------------------------------------------


def test_initial_round_is_free():
    cfg = ReviewModeConfig(max_reReviews=1)
    mixed = [
        review("accept", uuid="x"),
        review("reject", uuid="y"),
        review("abstain", uuid="z"),
        review("accept", uuid="w"),
    ]
    rounds = [mixed]
    assert re_reviews_used(rounds) == 0
    assert can_start_reReview(rounds, cfg)


def test_cap_exhausted():
    cfg = ReviewModeConfig(max_reReviews=1)
    rounds = [
        [review("reject", uuid=f"a{i}") for i in range(4)],
        [review("abstain", uuid=f"b{i}") for i in range(4)],
    ]
    assert re_reviews_used(rounds) == 1
    assert not can_start_reReview(rounds, cfg)


def test_terminal_round_blocks_more_reviews():
    cfg = ReviewModeConfig(max_reReviews=5)
    rounds = [[review("accept", uuid=f"a{i}") for i in range(4)]]
    # unanimous accept is terminal — no further rounds even under the cap.
    assert not can_start_reReview(rounds, cfg)


def test_mixed_round_allows_rereview_under_cap():
    cfg = ReviewModeConfig(max_reReviews=2)
    mixed = [
        review("accept", uuid="x"),
        review("reject", uuid="y"),
        review("abstain", uuid="z"),
        review("accept", uuid="w"),
    ]
    rounds = [mixed]
    assert can_start_reReview(rounds, cfg)
