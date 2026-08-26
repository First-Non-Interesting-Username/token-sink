"""False-positive lifecycle tests (issue #263, PLAN §10/§8.3/§14)."""

from __future__ import annotations

import time

import pytest

from findings.dedup import root_cause_fingerprint
from findings.false_positive import (
    FP_SCORE_CATEGORY,
    find_recurrent_fp,
    record_fp_metrics,
    record_fp_score_feedback,
)
from findings.lifecycle import FindingLifecycle, LifecycleError, RecordStore, State

AGENT = "11111111-1111-1111-1111-111111111111"
REVIEWER = "22222222-2222-2222-2222-222222222222"
CONFIRMER = "33333333-3333-3333-3333-333333333333"
CAMPAIGN = "44444444-4444-4444-4444-444444444444"


@pytest.fixture()
def lc():
    return FindingLifecycle(RecordStore())


def make_incorrect_finding(lc):
    """A finding with one 'incorrect' first review on record."""
    res = lc.submit_finding(
        CAMPAIGN,
        AGENT,
        {
            "title": "Reflected XSS in search",
            "category": "xss-reflected",
            "affected_asset": "https://app.example.com/search",
            "location": "/search?q=",
            "hypothesis": "unescaped query echo",
        },
    )
    f = res.finding
    lc.claim_for_review(f.finding_uuid, REVIEWER, "2099-01-01T00:00:00+00:00")
    lc.record_first_review(f.finding_uuid, REVIEWER, "incorrect", notes="output is encoded")
    return f


def test_false_positive_requires_justification(lc):
    f = make_incorrect_finding(lc)
    with pytest.raises(LifecycleError):
        lc.classify_false_positive(f.finding_uuid, CONFIRMER, justification="   ")
    # Whitespace-only must not have mutated the record.
    assert lc.store.load(f.finding_uuid).state == State.REVIEW_CYCLE_1


def test_false_positive_requires_incorrect_review(lc):
    res = lc.submit_finding(CAMPAIGN, AGENT, {"title": "clean finding", "category": "x"})
    f = res.finding
    lc.claim_for_review(f.finding_uuid, REVIEWER, "2099-01-01T00:00:00+00:00")
    lc.record_first_review(f.finding_uuid, REVIEWER, "confirmed")
    with pytest.raises(LifecycleError):
        lc.classify_false_positive(f.finding_uuid, CONFIRMER, justification="nope")


def test_false_positive_dual_confirmation_and_justification(lc):
    f = make_incorrect_finding(lc)
    res = lc.classify_false_positive(
        f.finding_uuid,
        CONFIRMER,
        justification="Output is HTML-encoded at the template layer; PoC was a false alarm.",
    )
    assert res.finding.state == State.FALSE_POSITIVE
    assert res.finding.fp_confirmed_by == CONFIRMER
    assert "HTML-encoded" in res.finding.false_positive_justification
    # Justification persisted in the audit payload too.
    last = res.transitions[-1]
    assert last.payload["justification"].startswith("Output is HTML-encoded")


def test_false_positive_single_reviewer_cannot_self_confirm(lc):
    f = make_incorrect_finding(lc)
    with pytest.raises(LifecycleError):
        # Same agent that said 'incorrect' tries to double-confirm.
        lc.classify_false_positive(f.finding_uuid, REVIEWER, justification="me again")


def test_contest_false_positive_reopens(lc):
    f = make_incorrect_finding(lc)
    lc.classify_false_positive(f.finding_uuid, CONFIRMER, justification="encoded output")
    with pytest.raises(LifecycleError):
        lc.contest_false_positive(f.finding_uuid, AGENT, "   ")
    res = lc.contest_false_positive(f.finding_uuid, AGENT, "new bypass evidence found")
    assert res.finding.state == State.VALIDATED_OR_DISPUTED
    assert any(t.reason.startswith("false_positive_contested") for t in res.transitions)


def test_find_recurrent_fp_links_same_root_cause():
    fp = {
        "finding_uuid": "fp-uuid",
        "affected_asset": "https://app.example.com/search",
        "category": "xss-reflected",
        "location": "/search?q=123",
        "root_cause": "unescaped query echo",
    }
    candidate = dict(fp, finding_uuid="new-uuid", location="/search?q=456")
    link = find_recurrent_fp(candidate, [fp])
    assert link is not None
    assert link.adjudicated_fp_uuid == "fp-uuid"

    # Different root cause → no linkage (conservative).
    other = dict(fp, root_cause="stored via admin panel", finding_uuid="fp-2")
    assert find_recurrent_fp(candidate, [other]) is None


def test_find_recurrent_fp_matches_dedup_fingerprint_semantics():
    fp = {
        "finding_uuid": "a",
        "affected_asset": "https://h.example.com/x",
        "category": "c",
        "location": "/p?id=1",
        "root_cause": "rc",
    }
    cand = dict(fp, finding_uuid="b")
    assert find_recurrent_fp(cand, [fp]) is not None
    # Sanity: linkage agrees with the dedup fingerprint directly.
    assert root_cause_fingerprint(fp) == root_cause_fingerprint(cand)


class _FakeScoreStore:
    def __init__(self):
        self.obs = []

    def record(self, observation, now=None):
        self.obs.append(observation)
        return observation


def test_record_fp_score_feedback_attributes_failure():
    store = _FakeScoreStore()
    record_fp_score_feedback(
        store,
        provider="prov",
        model="model-a",
        discovering_model_metadata={"provider": "ignored", "model_id": "ignored"},
        recorded_at=time.time(),
    )
    assert len(store.obs) == 1
    o = store.obs[0]
    assert o.category == FP_SCORE_CATEGORY and o.success is False
    assert (o.provider, o.model) == ("prov", "model-a")


def test_record_fp_score_feedback_requires_attribution():
    with pytest.raises(LifecycleError):
        record_fp_score_feedback(
            _FakeScoreStore(),
            provider="",
            model="",
            discovering_model_metadata={},
            recorded_at=time.time(),
        )


class _FakeMetrics:
    def __init__(self):
        self.samples = []

    def record(self, **kw):
        self.samples.append(kw)


def test_record_fp_metrics_emits_research_samples():
    m = _FakeMetrics()
    record_fp_metrics(m, campaign_id=CAMPAIGN, outcome="confirmed_false_positive", ts=100.0)
    assert len(m.samples) == 1
    s = m.samples[0]
    assert s["family"] == "research" and s["value"] == 1.0
    assert s["tags"]["kind"] == "false_positive" and s["campaign_id"] == CAMPAIGN


def test_record_fp_metrics_rejects_unknown_outcome():
    with pytest.raises(LifecycleError):
        record_fp_metrics(_FakeMetrics(), None, outcome="banana", ts=1.0)


def test_end_to_end_fp_then_recurrence_suppressed_path(lc):
    """Full loop: adjudicate FP -> new same-root-cause finding links back."""
    f = make_incorrect_finding(lc)
    lc.classify_false_positive(f.finding_uuid, CONFIRMER, justification="template-layer encoding")
    adjudicated = lc.store.load(f.finding_uuid).to_dict()
    recurrent = dict(adjudicated, finding_uuid="recurrent-1")
    link = find_recurrent_fp(recurrent, [adjudicated])
    assert link is not None and link.adjudicated_fp_uuid == f.finding_uuid
