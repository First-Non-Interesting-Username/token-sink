"""Tests for the score computation engine (PLAN §8.3–§8.4, issue #76).

Regression coverage demanded by the issue:
- tiny-sample overconfidence (1-for-1 must not score ~100%)
- monotonicity: more consistent samples → narrower interval, stabler score
- recency decay behavior (half-life)
- deterministic replay from recorded observations
"""

from __future__ import annotations

from evaluation.scores import (
    Observation,
    ScoreStore,
    combine_signals,
    rank_candidates_ucb,
    seed_prior_from_benchmarks,
)

T0 = 1_000_000.0


def _store(**kw) -> ScoreStore:
    return ScoreStore(**kw)


# -- overconfidence regression ---------------------------------------------


def test_single_success_does_not_score_100():
    store = _store()
    entry = store.record(Observation("p", "m", "reasoning", success=True, recorded_at=T0), now=T0)
    # Uninformative prior Beta(1,1): posterior mean = 2/3 at best.
    assert entry.score < 0.7
    lo, hi = entry.wilson_interval
    assert hi - lo > 0.5  # essentially no weighted evidence yet -> very wide


def test_benchmark_seeded_prior_shrinks_tiny_sample():
    alpha, beta = seed_prior_from_benchmarks(benchmark_version=1, successes=8, failures=2)
    assert abs(alpha / (alpha + beta) - 0.8) < 1e-9
    store = _store()
    store.set_prior("p", "m", "coding", alpha, beta, benchmark_version=1)
    entry = store.record(Observation("p", "m", "coding", success=True, recorded_at=T0), now=T0)
    # One lucky call cannot lift a strength-4 prior of 80% anywhere near 100%.
    assert entry.score < 0.9
    assert entry.benchmark_version == 1


def test_neutral_prior_when_no_benchmarks():
    alpha, beta = seed_prior_from_benchmarks(1, 0, 0)
    assert alpha == beta


# -- monotonicity with sample size ------------------------------------------


def test_more_samples_narrow_interval_and_stable_score():
    store = _store()
    for i in range(5):
        store.record(
            Observation("p", "m", "tool_use", success=(i % 4 != 0), recorded_at=T0 + i),
            now=T0,
        )
    early_entry = store.get("p", "m", "tool_use")
    early_unc, early_score = early_entry.uncertainty, early_entry.score
    for i in range(5, 200):
        store.record(
            Observation("p", "m", "tool_use", success=(i % 4 != 0), recorded_at=T0 + i),
            now=T0,
        )
    late = store.get("p", "m", "tool_use")
    assert late.uncertainty < early_unc
    # Both hover near the true 75% rate but the later estimate is closer.
    assert abs(late.score - 0.75) <= abs(early_score - 0.75)


# -- recency decay ------------------------------------------------------------


def test_recent_success_outweighs_old_failure():
    # Same evidence, different ages: a recent success should yield a higher
    # score than an identical success recorded many half-lives ago.
    fresh = ScoreStore(half_life_s=1000)
    old_store = ScoreStore(half_life_s=1000)
    e_new = fresh.record(Observation("p", "m", "latency", success=True, recorded_at=T0), now=T0)
    e_old = old_store.record(
        Observation("p", "m", "latency", success=True, recorded_at=T0 - 10_000),
        now=T0,
    )
    assert e_new.score > e_old.score


def test_half_life_configurable():
    s_short = ScoreStore(half_life_s=10)
    s_long = ScoreStore(half_life_s=1e9)
    o = Observation("p", "m", "c", success=True, recorded_at=T0 - 1000)
    e_short = s_short.record(o, now=T0)
    e_long = s_long.record(o, now=T0)
    assert e_long.score > e_short.score


# -- deterministic replay ------------------------------------------------------


def test_replay_from_recorded_observations_is_deterministic():
    store = _store(half_life_s=3600)
    obs = [
        Observation("a", "m1", "reasoning", success=True, recorded_at=T0 + i * 60)
        for i in range(20)
    ] + [
        Observation("a", "m2", "reasoning", success=False, recorded_at=T0 + i * 90)
        for i in range(15)
    ]
    for o in obs:
        store.record(o, now=o.recorded_at)
    before = {k: (e.alpha, e.beta, e.score) for k, e in store._entries.items()}
    recomputed = store.recompute(now=T0 + 3000)
    after = {k: (e.alpha, e.beta, e.score) for k, e in recomputed.items()}
    assert set(before) == set(after)
    for k in before:
        assert before[k][0] > 0  # sanity: mass accumulated
        assert abs(before[k][2] - after[k][2]) < 1e-12


# -- multi-signal combination ---------------------------------------------------


def test_combine_signals_weights_and_redistribution():
    full = combine_signals(
        0.8, latency_norm=0.6, error_rate=0.1, reviewer_agreement=0.9, completion_quality=0.7
    )
    expected = 0.5 * 0.8 + 0.2 * 0.6 + 0.15 * 0.9 + 0.1 * 0.9 + 0.05 * 0.7
    assert abs(full - expected) < 1e-9
    # Missing signals redistribute weight; result stays within [min, max] of
    # present signals and never crashes on None-heavy input.
    sparse = combine_signals(0.5)
    assert 0.0 <= sparse <= 1.0
    assert sparse == 0.5  # only signal present -> it is the whole score


def test_error_rate_is_inverted():
    good = combine_signals(0.5, error_rate=0.0)
    bad = combine_signals(0.5, error_rate=1.0)
    assert good > bad


# -- UCB router integration -------------------------------------------------------


def test_ucb_prefers_wide_intervals_for_exploration():
    store = _store()
    # Candidate A: one success (wide interval). Candidate B: 50/75-ish
    # successes with similar mean but tight interval.
    store.record(Observation("a", "ma", "c", success=True, recorded_at=T0), now=T0)
    for i in range(50):
        store.record(Observation("b", "mb", "c", success=(i % 4 != 0), recorded_at=T0 + i), now=T0)
    ranked = rank_candidates_ucb([("a", "ma", store), ("b", "mb", store)], "c", exploration=1.0)
    # Wide-interval candidate ranks first under exploration...
    assert ranked[0][:2] == ("a", "ma")
    # ...but not when exploration is switched off.
    ranked_greedy = rank_candidates_ucb(
        [("a", "ma", store), ("b", "mb", store)], "c", exploration=0.0
    )
    assert ranked_greedy[0][:2] == ("b", "mb")


def test_unscored_candidate_sorts_last():
    store = _store()
    store.record(Observation("x", "mx", "c", success=True, recorded_at=T0), now=T0)
    ranked = rank_candidates_ucb([("none", "nada", store), ("x", "mx", store)], "c")
    assert ranked[-1][:2] == ("none", "nada")
