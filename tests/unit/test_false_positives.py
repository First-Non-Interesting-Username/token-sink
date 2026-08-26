"""Unit tests for the false-positive lifecycle (issue #263, PLAN §10/§14/§8.3)."""

from __future__ import annotations

import pytest

from evaluation.scores import ScoreStore
from findings.false_positives import (
    FP_SCORE_CATEGORY,
    FalsePositiveRegistry,
    FPCandidate,
    FPContested,
    FPError,
    feedback_to_scores,
    record_fp_metric,
    root_cause_fingerprint,
)
from observability.metrics import MetricsStore


def _candidate(uid="f-1", fp="xss|app.example.com|no-encoding", **over) -> FPCandidate:
    d = dict(
        finding_uuid=uid,
        fingerprint=fp,
        justification="reviewer reproduced the payload and it was safely encoded server-side",
        origin_provider="prov",
        origin_model="model-a",
        campaign_id="c1",
    )
    d.update(over)
    return FPCandidate(**d)


def test_proposal_requires_justification():
    reg = FalsePositiveRegistry()
    with pytest.raises(FPError):
        reg.propose(_candidate(justification="  "))


def test_single_vote_cannot_confirm():
    reg = FalsePositiveRegistry()
    reg.propose(_candidate())
    rec = reg.vote("f-1", "agent-a", "false_positive")
    assert rec.status == "pending"


def test_consensus_confirms_fp():
    reg = FalsePositiveRegistry()
    reg.propose(_candidate())
    reg.vote("f-1", "agent-a", "false_positive")
    rec = reg.vote("f-1", "agent-b", "false_positive")
    assert rec.status == "confirmed_fp"


def test_split_decision_is_contested_not_averaged():
    reg = FalsePositiveRegistry(min_consensus=1)
    reg.propose(_candidate())
    reg.vote("f-1", "agent-a", "false_positive")
    with pytest.raises(FPContested):
        # The registry marks contested; surface it as an exception path for
        # callers that require unanimity-free confirmation.
        rec = reg.vote("f-1", "agent-b", "not_false_positive")
        if rec.status == "contested":
            raise FPContested("split decision")
    rec = reg.get("f-1")
    assert rec.status == "contested"


def test_unanimous_rejection_rejects():
    reg = FalsePositiveRegistry()
    reg.propose(_candidate())
    reg.vote("f-1", "agent-a", "not_false_positive")
    rec = reg.vote("f-1", "agent-b", "not_false_positive")
    assert rec.status == "rejected_fp"


def test_double_voting_blocked():
    reg = FalsePositiveRegistry(min_consensus=1)
    reg.propose(_candidate())
    reg.vote("f-1", "agent-a", "false_positive")
    with pytest.raises(FPError):
        reg.vote("f-1", "agent-a", "false_positive")


def test_fingerprint_deterministic_and_validated():
    a = root_cause_fingerprint("XSS", "App.Example.com ", " no output encoding ")
    b = root_cause_fingerprint("xss", "app.example.com", "no output encoding")
    assert a == b
    with pytest.raises(FPError):
        root_cause_fingerprint("", "asset", "cause")


def test_recurrent_fp_links_instead_of_restart():
    reg = FalsePositiveRegistry()
    reg.propose(_candidate())
    reg.vote("f-1", "a1", "false_positive")
    reg.vote("f-1", "a2", "false_positive")
    priors = reg.find_recurrent("xss|app.example.com|no-encoding")
    assert [p.candidate.finding_uuid for p in priors] == ["f-1"]
    rec = reg.link_to_prior_fp("f-9", "f-1", linker_uuid="a3")
    assert rec.linked_findings == ["f-1"]
    assert reg.get("f-1").linked_findings == ["f-9"]
    # And no priors remain unmatched for that fingerprint.
    assert reg.find_recurrent("xss|app.example.com|no-encoding", exclude_uuid="f-9") == [
        reg.get("f-1")
    ]


def test_link_requires_confirmed_prior():
    reg = FalsePositiveRegistry()
    reg.propose(_candidate())  # pending, unconfirmed
    with pytest.raises(FPError):
        reg.link_to_prior_fp("f-9", "f-1", linker_uuid="a")


def test_feedback_emits_score_observation_for_origin_model():
    reg = FalsePositiveRegistry(min_consensus=1)
    reg.propose(_candidate(origin_provider="prov", origin_model="model-a"))
    rec = reg.vote("f-1", "a1", "false_positive")
    store = ScoreStore()
    obs = feedback_to_scores(store, rec, now=1000.0)
    assert obs is not None
    entry = store.get("prov", "model-a", FP_SCORE_CATEGORY)
    assert entry is not None and entry.n_observations >= 1


def test_feedback_skips_unknown_origin_or_unconfirmed():
    reg = FalsePositiveRegistry(min_consensus=1)
    store = ScoreStore()
    reg.propose(_candidate(uid="f-2", origin_provider=None, origin_model=None))
    rec = reg.vote("f-2", "a1", "false_positive")
    assert feedback_to_scores(store, rec, now=0.0) is None
    reg.propose(_candidate(uid="f-3"))  # stays pending
    assert feedback_to_scores(store, reg.get("f-3"), now=0.0) is None
    assert store.entries() == []


def test_metric_sample_recorded_per_confirmed_fp():
    reg = FalsePositiveRegistry(min_consensus=1)
    reg.propose(_candidate(campaign_id="c42"))
    rec = reg.vote("f-1", "a1", "false_positive")
    ms = MetricsStore()
    s = record_fp_metric(ms, rec, ts=555.0)
    assert s is not None and s.value == 1 and s.ts == 555.0
    agg = ms.aggregate("count", family="research", name="false_positive", campaign_id="c42")
    assert agg == 1
