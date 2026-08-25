"""Unit tests for the router decision log (issue #55, PLAN §7.2)."""

from __future__ import annotations

import pytest

from routers.decision_log import (
    CandidatePlan,
    DecisionLog,
    MergePolicyError,
    RedactionError,
)


def _plans():
    return [
        CandidatePlan(
            router_id="r1",
            provider="prov-a",
            model="model-x",
            rationale="best capability score",
            confidence=0.9,
            expected_cost=0.01,
            fallbacks=[{"provider": "prov-b", "model": "model-y"}],
        ),
        CandidatePlan(
            router_id="r2",
            provider="prov-b",
            model="model-y",
            rationale="cheapest",
            confidence=0.7,
            expected_cost=0.002,
        ),
        CandidatePlan(
            router_id="r3",
            provider="prov-c",
            model="model-z",
            rationale="low latency",
            confidence=0.8,
            expected_cost=0.005,
        ),
    ]


def _log(redactor=None, enforce=False):
    kwargs = {}
    if redactor is not None:
        kwargs["redactor"] = redactor
    return DecisionLog(enforce_redaction=enforce, **kwargs)


def test_record_is_complete_and_json_round_trips():
    log = _log()
    rec = log.record(
        task_snapshot={"task": "scan example", "scope": ["example.com"]},
        task_ref="tasks/abc123",
        model_catalog_version="catalog-2026-08-25",
        input_signals={"load": 0.2, "quota_remaining": 100, "budget_left": 5.0},
        candidate_plans=_plans(),
        merge_policy="consensus",
        final_selection={"router_id": "r1", "provider": "prov-a", "model": "model-x"},
    )
    assert rec["task_snapshot_hash"]
    assert rec["decision_id"]
    assert rec["merge_policy"] == "consensus"
    assert len(rec["candidates"]) == 3
    # JSON round-trip must preserve everything (storage-agnostic record).
    import json

    restored = json.loads(json.dumps(rec))
    report = log.replay(restored)
    assert report["drift"] is False


def test_replay_is_deterministic_and_matches_recorded_selection():
    log = _log()
    rec = log.record(
        task_snapshot="do a review",
        task_ref="tasks/r1",
        model_catalog_version="v1",
        input_signals={},
        candidate_plans=_plans(),
        merge_policy="best_score",
        final_selection={"router_id": "r1", "provider": "prov-a", "model": "model-x"},
        merge_options={
            "budget": 0.01,
            "scores": {"prov-a/model-x": 0.9, "prov-b/model-y": 0.6, "prov-c/model-z": 0.85},
        },
    )
    reports = [log.replay(dict(rec)) for _ in range(5)]
    # Identical replay from a fixed record every time.
    assert all(r == reports[0] for r in reports)
    assert reports[0]["drift"] is False
    assert reports[0]["recomputed_selection"]["model"] == "model-x"


def test_replay_flags_drift_when_recorded_selection_differs():
    log = _log()
    rec = log.record(
        task_snapshot="t",
        task_ref="tasks/x",
        model_catalog_version="v1",
        input_signals={},
        candidate_plans=_plans(),
        merge_policy="fastest",
        # Recorded selection is NOT what fastest would pick given latencies.
        final_selection={"router_id": "r1", "provider": "prov-a", "model": "model-x"},
        merge_options={"expected_latency": {"prov-b/model-y": 120, "prov-c/model-z": 300}},
    )
    report = log.replay(rec)
    assert report["drift"] is True
    assert report["recomputed_selection"]["model"] == "model-y"


def test_failed_router_mid_pool_leaves_complete_valid_record():
    plans = [
        CandidatePlan(
            router_id="r-doomed",
            provider="prov-dead",
            model="model-q",
            rationale="",
            confidence=0.0,
            expected_cost=0.0,
            failed=True,
            error="connection reset mid-pool",
        ),
        *_plans(),
    ]
    log = _log()
    rec = log.record(
        task_snapshot="t",
        task_ref="tasks/y",
        model_catalog_version="v1",
        input_signals={},
        candidate_plans=plans,
        merge_policy="consensus",
        final_selection={"router_id": "r1", "provider": "prov-a", "model": "model-x"},
    )
    # The failed router is recorded, never silently dropped.
    failed = [c for c in rec["candidates"] if c["failed"]]
    assert len(failed) == 1 and failed[0]["error"] == "connection reset mid-pool"
    # Replay succeeds and excludes the failed partial from merging.
    report = log.replay(rec)
    assert report["drift"] is False
    assert report["merge_details"]["distinct_candidates"] == 3


def test_redaction_applied_before_persistence():
    def redact(payload):
        payload["input_signals"]["target_host"] = "[REDACTED]"
        return payload

    log = _log(redactor=redact)
    rec = log.record(
        task_snapshot="t",
        task_ref="tasks/z",
        model_catalog_version="v1",
        input_signals={"target_host": "internal.example.com"},
        candidate_plans=_plans(),
        merge_policy="consensus",
        final_selection={"router_id": "r1", "provider": "prov-a", "model": "model-x"},
    )
    assert rec["input_signals"]["target_host"] == "[REDACTED]"
    assert rec["redacted"] is True


def test_enforced_redaction_fails_closed_when_no_change():
    log = _log(redactor=lambda p: p, enforce=True)
    with pytest.raises(RedactionError):
        log.record(
            task_snapshot="t",
            task_ref="tasks/e",
            model_catalog_version="v1",
            input_signals={},
            candidate_plans=_plans(),
            merge_policy="consensus",
            final_selection={},
        )


def test_unknown_policy_and_empty_pool_raise():
    log = _log()
    rec = log.record(
        task_snapshot="t",
        task_ref="tasks/u",
        model_catalog_version="v1",
        input_signals={},
        candidate_plans=_plans(),
        merge_policy="coin_flip",
        final_selection={"router_id": "r1", "provider": "p", "model": "m"},
    )
    bad = dict(rec)
    bad["merge_policy"] = "coin_flip"
    with pytest.raises(MergePolicyError):
        log.replay(bad)

    empty = dict(rec)
    empty["candidates"] = []
    with pytest.raises(MergePolicyError):
        log.replay(empty)


def test_diversity_policy_spreads_model_families():
    log = _log()
    rec = log.record(
        task_snapshot="independent review",
        task_ref="tasks/d",
        model_catalog_version="v1",
        input_signals={},
        candidate_plans=[
            CandidatePlan("ra", "famA", "a-big", "top", 0.95, 0.01),
            CandidatePlan("rb", "famA", "a-small", "same family", 0.9, 0.005),
            CandidatePlan("rc", "famB", "b-mid", "other family", 0.85, 0.004),
        ],
        merge_policy="diversity",
        final_selection={"router_id": "ra", "provider": "famA", "model": "a-big"},
        merge_options={"families": {"famA/a-big": "alpha", "famA/a-small": "alpha"}},
    )
    report = log.replay(rec)
    assert report["drift"] is False
    assert report["merge_details"]["distinct_families"] == 2
