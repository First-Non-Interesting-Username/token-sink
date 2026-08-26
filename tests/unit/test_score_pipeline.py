"""Score update pipeline tests (issue #235, PLAN §8.3–§8.4)."""

from __future__ import annotations

import pytest

from evaluation.score_pipeline import ScorePipeline, benchmark_prior

NOW = 1_800_000_000.0
PROV, MODEL, CAT = "gw", "m1", "coding"
CANDS = [("gw", "m1"), ("gw", "m2")]


class TestBenchmarkPrior:
    def test_perfect_and_zero_runs(self):
        a, b = benchmark_prior(10, 10)
        assert a > b  # strong success prior
        a, b = benchmark_prior(0, 10)
        assert b > a

    def test_empty_run_neutral(self):
        assert benchmark_prior(0, 0) == (1.0, 1.0)

    def test_strength_controls_confidence(self):
        weak = benchmark_prior(5, 10, strength=2.0)
        strong = benchmark_prior(5, 10, strength=20.0)
        # Both centered near 0.5; stronger run has bigger pseudo-counts.
        assert sum(strong) > sum(weak)


class TestBenchmarkIngestion:
    def test_benchmark_seeds_prior_before_any_observation(self):
        pipe = ScorePipeline()
        pipe.apply_benchmark_run(
            PROV,
            MODEL,
            CAT,
            passed_items=["t1", "t2", "t3"],
            failed_items=["t4"],
            suite_version=3,
            run_id="run-1",
            now=NOW,
        )
        entry = pipe.store.get(PROV, MODEL, CAT)
        assert (
            entry is not None
            and (entry.alpha, entry.beta) == (7.0, 3.0)  # strength 8 prior on 3/4 pass rate
            and entry.benchmark_version == 3
        )
        upd = pipe.audit_log()[-1]
        assert upd.source == "benchmark" and upd.inputs["suite_version"] == 3

    def test_benchmark_without_items_rejected(self):
        pipe = ScorePipeline()
        with pytest.raises(ValueError):
            pipe.apply_benchmark_run(PROV, MODEL, CAT, [], [], suite_version=1)


class TestObservedOutcomes:
    def test_observed_updates_feed_rolling_score(self):
        pipe = ScorePipeline()
        pipe.apply_benchmark_run(
            PROV, MODEL, CAT, ["t1"], ["t2", "t3", "t4"], suite_version=1, now=NOW
        )
        entry0 = pipe.store.get(PROV, MODEL, CAT)
        assert entry0 is not None
        before = entry0.score
        for i in range(20):
            pipe.record_outcome(PROV, MODEL, CAT, success=True, now=NOW + i + 1)
        entry1 = pipe.store.get(PROV, MODEL, CAT)
        assert entry1 is not None
        after = entry1.score
        assert after > before  # observed successes pull the score up

    def test_source_tagged_audit(self):
        pipe = ScorePipeline()
        pipe.apply_benchmark_run(PROV, MODEL, CAT, ["t1"], [], suite_version=2, now=NOW)
        pipe.record_outcome(PROV, MODEL, CAT, True, now=NOW + 1)
        sources = [u.source for u in pipe.trace(PROV, MODEL, CAT)]
        assert sources == ["benchmark", "observed"]


class TestRouterConsumption:
    def test_rank_prefers_higher_scored_model(self):
        pipe = ScorePipeline()
        # m1: benchmark + observed all success; m2: no data (sorts last).
        pipe.apply_benchmark_run("gw", "m1", CAT, ["a", "b"], [], suite_version=1, now=NOW)
        pipe.apply_benchmark_run("gw", "m2", CAT, [], ["a", "b"], suite_version=1, now=NOW)
        ranked = pipe.rank(CANDS, CAT, exploration=0.0)
        assert ranked[0][1] == "m1"

    def test_exploration_can_promote_uncertain_model(self):
        pipe = ScorePipeline()
        pipe.apply_benchmark_run("gw", "m1", CAT, ["a", "b"], ["c", "d"], suite_version=1, now=NOW)
        pipe.record_outcome("gw", "m1", CAT, True, now=NOW + 1)
        pipe.record_outcome("gw", "m1", CAT, True, now=NOW + 2)
        pipe.record_outcome("gw", "m1", CAT, True, now=NOW + 3)
        # m2: one observation only → wide interval.
        pipe.record_outcome("gw", "m2", CAT, True, now=NOW + 4)
        exploit = {p: r for _, p, r in pipe.rank(CANDS, CAT, exploration=0.0)}
        explore = {p: r for _, p, r in pipe.rank(CANDS, CAT, exploration=5.0)}
        assert explore["m2"] > exploit["m2"]

    def test_best_returns_candidate(self):
        pipe = ScorePipeline()
        assert pipe.best(CANDS, CAT) is None or pipe.best(CANDS, CAT) in CANDS


class TestAuditTraceability:
    def test_every_change_traceable_to_inputs(self):
        pipe = ScorePipeline()
        pipe.apply_benchmark_run(
            PROV, MODEL, CAT, ["x"], ["y"], suite_version=7, run_id="r9", now=NOW
        )
        pipe.record_outcome(PROV, MODEL, CAT, False, reviewer_agreement=0.4, now=NOW + 1)
        log = pipe.export_audit()
        assert len(log) == 2
        bench = next(u for u in log if u["source"] == "benchmark")
        assert bench["inputs"]["suite_version"] == 7
        assert sorted(bench["inputs"]["passed"]) == ["x"]
        obs = next(u for u in log if u["source"] == "observed")
        assert obs["inputs"] == {"success": False}

    def test_trace_isolated_per_key(self):
        pipe = ScorePipeline()
        pipe.record_outcome("gw", "m1", CAT, True, now=NOW)
        pipe.record_outcome("gw", "m2", CAT, False, now=NOW)
        assert len(pipe.trace("gw", "m1", CAT)) == 1
