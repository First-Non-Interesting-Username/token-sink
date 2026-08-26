"""Unit tests for the router-decision replay harness (issue #159, §7.2)."""

from __future__ import annotations

import pytest

from routers.decision_log import CandidatePlan, DecisionLog
from routers.replay import (
    CatalogMismatch,
    ReplayHarness,
    write_record_fixture,
)


def _plans():
    return [
        CandidatePlan(
            router_id="r1",
            provider="prov-a",
            model="model-x",
            rationale="capable",
            confidence=0.9,
            expected_cost=0.01,
        ),
        CandidatePlan(
            router_id="r2",
            provider="prov-b",
            model="model-y",
            rationale="cheap",
            confidence=0.7,
            expected_cost=0.002,
        ),
    ]


def _record(catalog: str = "cat-v1", merge_policy: str = "consensus"):
    log = DecisionLog()
    return log.record(
        task_snapshot={"url": "example.com", "goal": "xss"},
        task_ref="task-1",
        model_catalog_version=catalog,
        input_signals={"load": 0.2},
        candidate_plans=_plans(),
        merge_policy=merge_policy,
        final_selection={"router_id": "r1", "provider": "prov-a", "model": "model-x"},
        merge_options={"expected_latency": {}},
    )


def test_identical_inputs_reproduce_byte_identical():
    h = ReplayHarness("cat-v1")
    res = h.replay(_record())
    assert res.ok and not res.drift and res.byte_identical
    assert res.report["recomputed_selection"]["model"] == "model-x"


def test_tie_break_change_caught_by_byte_check():
    """A policy tweak that changes merge details must fail byte-identical
    even if the winning (provider, model) key is unchanged."""
    h = ReplayHarness("cat-v1")
    rec = _record()
    # Simulate stored merge_details differing from what current code computes.
    rec["final_selection"]["merge_details"] = {"policy": "consensus", "agreement": 9}
    res = h.replay(rec)
    assert not res.byte_identical


def test_catalog_mismatch_rejected_loudly():
    h = ReplayHarness("cat-v2")  # catalog moved on since the record
    with pytest.raises(CatalogMismatch, match="cat-v1.*cat-v2|created under"):
        h.replay(_record(catalog="cat-v1"))
    # strict=False opts out (e.g. for historical audit views)
    assert h.replay(_record(catalog="cat-v1"), strict=False).ok


def test_explain_trace_shape():
    h = ReplayHarness("cat-v1")
    trace = h.explain(_record())
    order = list(trace.keys())
    assert (
        order.index("input_signals")
        < order.index("candidates")
        < order.index("merge_policy")
        < order.index("outcome")
    )
    assert len(trace["candidates"]) == 2
    assert trace["candidates"][0]["failed"] is False
    assert trace["merge_policy"] == "consensus"
    assert trace["outcome"]["provider"] == "prov-a"
    assert trace["input_snapshot_hash"].startswith("")


def test_explain_includes_failed_partials():
    plans = _plans()
    plans.append(
        CandidatePlan(
            router_id="r3",
            provider="prov-c",
            model="m-z",
            rationale="x",
            confidence=0.5,
            expected_cost=0.0,
            failed=True,
            error="timeout",
        )
    )
    log = DecisionLog()
    rec = log.record(
        task_snapshot={},
        task_ref="t2",
        model_catalog_version="cat-v1",
        input_signals={},
        candidate_plans=plans,
        merge_policy="best_score",
        final_selection={"router_id": "r1", "provider": "prov-a", "model": "model-x"},
        merge_options={"capability_scores": {"r1": 0.9}},
    )
    trace = ReplayHarness("cat-v1").explain(rec)
    failed = [c for c in trace["candidates"] if c["failed"]]
    assert len(failed) == 1 and failed[0]["error"] == "timeout"


def test_regression_directory(tmp_path):
    h = ReplayHarness("cat-v1")
    write_record_fixture(_record(), tmp_path)  # passes
    write_record_fixture(_record(catalog="cat-old"), tmp_path)  # mismatch → fail
    bad = tmp_path / "zz-broken.json"
    bad.write_text("{not json")
    summary = h.regression(tmp_path)
    assert summary["total"] == 3
    assert summary["passed"] == 1 and summary["failed"] == 2
    kinds = {f.get("error", "")[:20] for f in summary["failures"]}
    assert any("invalid JSON" in k for k in kinds)


def test_regression_detects_drift(tmp_path):
    h = ReplayHarness("cat-v1")
    rec = _record(merge_policy="fastest")
    # Recorded outcome lies about what 'fastest' would pick.
    rec["final_selection"] = {
        "router_id": "r2",
        "provider": "prov-b",
        "model": "model-y",
        "options": {"expected_latency": {"prov-a/model-x": 1.0}},
    }
    p = write_record_fixture(rec, tmp_path)
    assert p.exists()
    summary = h.regression(tmp_path)
    assert summary["failed"] == 1
    assert summary["failures"][0]["drift"] is True
