"""Tests for parallel-router disagreement recording (issue #281, PLAN §7.2)."""

from __future__ import annotations

import pytest

from routers.decision_log import MERGE_POLICIES, CandidatePlan
from routers.disagreement import DisagreementIndex, detect, resolve


def _plan(rid, provider="prov-a", model="m-1", conf=0.8):
    return CandidatePlan(
        router_id=rid,
        provider=provider,
        model=model,
        rationale="r",
        confidence=conf,
        expected_cost=0.1,
    )


def test_detect_true_only_when_live_plans_differ():
    assert not detect([_plan("a"), _plan("b")])
    assert detect([_plan("a"), _plan("b", provider="prov-b")])
    # failed plans never count as a dissenting opinion
    failed = _plan("c", provider="prov-c")
    failed.failed = True
    assert not detect([_plan("a"), failed])


def test_resolution_records_groups_and_explicit_rationale():
    res = resolve(
        [_plan("a"), _plan("b"), _plan("c", provider="prov-b")],
        MERGE_POLICIES["consensus"],
        decision_id="d-1",
    )
    assert res.disagreed is True
    assert len(res.groups) == 2
    assert res.rationale.strip()
    d = res.to_dict()
    assert d["resolved_by"] == "coordinator"
    assert any(g["provider"] == "prov-b" for g in d["groups"])


def test_coordinator_note_overrides_generated_rationale():
    res = resolve(
        [_plan("a"), _plan("b", provider="other")],
        MERGE_POLICIES["consensus"],
        decision_id="d-2",
        coordinator_note="human operator pinned prov-a for compliance",
        resolved_by="operator-7",
    )
    assert res.rationale == "human operator pinned prov-a for compliance"
    assert res.resolved_by == "operator-7"


def test_no_disagreement_still_records_rationale():
    res = resolve([_plan("a"), _plan("b")], MERGE_POLICIES["consensus"], decision_id="d-3")
    assert res.disagreed is False
    assert "no disagreement" in res.rationale


def test_empty_rationale_rejected():
    with pytest.raises(ValueError):
        resolve(
            [_plan("a"), _plan("b", provider="x")],
            MERGE_POLICIES["consensus"],
            decision_id="d-4",
            coordinator_note="   ",
            resolved_by="coordinator",
        )


def test_index_queryable_by_task_and_agent():
    idx = DisagreementIndex()
    rec = {
        "decision_id": "d-9",
        "candidates": [
            {"router_id": "router-alpha"},
            {"router_id": "router-beta"},
        ],
    }
    idx.add("task-1", rec)
    idx.add("task-1", {**rec, "decision_id": "d-10"})
    idx.add("task-2", rec)
    assert len(idx.by_task("task-1")) == 2
    assert len(idx.by_agent("router-alpha")) == 3  # 2x task-1 + 1x task-2
    assert idx.by_agent("router-gamma") == []
