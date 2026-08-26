"""Tests for the evidence-gap workflow on reverted findings (issue #158)."""

from __future__ import annotations

import pytest

from findings.evidence_gaps import (
    DEFAULT_MAX_CYCLES,
    EvidenceGapError,
    GapWorkflowState,
    extract_gaps,
    gap_key,
    generate_tasks,
)
from findings.lifecycle import Finding
from policy.scope import ScopePolicy, TargetSpec


def _finding(**over) -> Finding:
    kw = {"observation": "xss in search", "location": "https://app.example.com/search"}
    kw.update(over)
    return Finding.create(campaign_uuid="camp-1", title="Reflected XSS", **kw)


def _review(reviewer: str, missing: str, verdict: str = "reject") -> dict:
    return {
        "reviewer_uuid": reviewer,
        "verdict": verdict,
        "missing_evidence": missing,
        "blocking_safety_or_validity_objection": False,
    }


# --- gap extraction ------------------------------------------------------------


def test_gaps_aggregated_from_multiple_reviewers():
    f = _finding(
        poc_reviews=[
            _review("r1", "Add reproduction steps for a second injection context"),
            _review("r2", "add reproduction steps for a second injection context"),
            _review("r3", "Show impact evidence"),
            _review("r4", ""),
        ]
    )
    gaps = extract_gaps(f)
    assert len(gaps) == 2  # paraphrases collapse; blank skipped
    assert gaps[0].sources == ["r1", "r2"]
    assert gaps[1].sources == ["r3"]


def test_gap_keys_stable_across_punctuation_and_case():
    assert gap_key("Add PoC for XSS!") == gap_key("add poc for xss")
    assert gap_key("a") != gap_key("b")


def test_no_reviews_means_no_gaps():
    assert extract_gaps(_finding()) == []


# --- task generation + scope enforcement -----------------------------------------


def _scope(includes: str) -> ScopePolicy:
    return ScopePolicy(
        campaign_uuid="camp-1",
        in_scope=[TargetSpec(value=includes)],
        active_testing_enabled=True,
    )


def test_one_task_per_unresolved_gap():
    f = _finding(poc_reviews=[_review("r1", "gap one"), _review("r2", "gap two")])
    tasks, rejected = generate_tasks(f, extract_gaps(f), scope=_scope("app.example.com"))
    assert len(tasks) == 2
    assert rejected == []
    assert {t.gap_key for t in tasks} == {g.key for g in extract_gaps(f)}
    assert all(t.status == "pending" for t in tasks)


def test_out_of_scope_target_rejected_not_silently_trimmed():
    # Location points outside the campaign scope.
    f = _finding(location="https://evil.example.net/x")
    f.poc_reviews = [_review("r1", "need repro")]
    tasks, rejected = generate_tasks(f, extract_gaps(f), scope=_scope("app.example.com"))
    assert tasks == []
    assert len(rejected) == 1
    assert rejected[0].status == "rejected_out_of_scope"
    assert "human approval" in rejected[0].rejection_reason


def test_in_scope_task_allowed():
    tasks, rejected = generate_tasks(
        _finding(),
        [extract_gaps(_finding(poc_reviews=[_review("r1", "g")]))[0]],
        scope=_scope("app.example.com"),
    )
    assert len(tasks) == 1 and rejected == []


def test_resolved_gaps_do_not_generate_tasks():
    g = extract_gaps(_finding(poc_reviews=[_review("r1", "g")]))[0]
    g.addressed_by.append("ev-1")
    tasks, _rej = generate_tasks(_finding(), [g])
    assert tasks == []


def test_scope_expansion_requires_human_approval():
    """A task can never widen scope: targets outside policy are hard-rejected."""
    f = _finding(location="https://unlisted.example.org/")
    f.poc_reviews = [_review("r1", "evidence")]
    scope = _scope("app.example.com")  # does NOT include unlisted.example.org
    tasks, rejected = generate_tasks(f, extract_gaps(f), scope=scope)
    assert not any(t.target_url and "unlisted.example.org" in t.target_url for t in tasks)
    assert len(rejected) == 1


# --- cycle cap → force quarantine --------------------------------------------------


def test_revert_allowed_within_cap():
    st = GapWorkflowState()
    assert st.record_revert(_finding(poc_reviews=[_review("r1", "more evidence")]))
    assert st.cycles_used == 1
    assert st.force_quarantine_reason == ""


def test_cycle_cap_forces_quarantine():
    st = GapWorkflowState(max_cycles=2)
    reviews = [_review("r1", "evidence A"), _review("r2", "evidence B")]
    assert st.record_revert(_finding(poc_reviews=reviews))
    assert st.record_revert(_finding(poc_reviews=reviews))
    # Third revert attempt exceeds cap → must quarantine instead.
    allowed = st.record_revert(_finding(poc_reviews=reviews))
    assert not allowed
    assert st.force_quarantine_reason == "unresolvable-evidence-gaps"


def test_default_cap_is_two():
    assert DEFAULT_MAX_CYCLES == 2


def test_custom_cap_zero_means_immediate_quarantine():
    st = GapWorkflowState()
    assert not st.record_revert(_finding(), max_cycles=0)
    assert st.force_quarantine_reason == "unresolvable-evidence-gaps"


def test_gaps_collected_per_revert():
    st = GapWorkflowState()
    st.record_revert(_finding(poc_reviews=[_review("r1", "gap one")]))
    st.record_revert(_finding(poc_reviews=[_review("r2", "gap two")]))
    assert len(st.gaps) == 2


# --- addressing evidence + reviewer context ----------------------------------------


def _state_with_gap() -> tuple[GapWorkflowState, str]:
    st = GapWorkflowState()
    st.record_revert(_finding(poc_reviews=[_review("r1", "need second context PoC")]))
    key = next(iter(st.gaps))
    return st, key


def test_attach_evidence_resolves_gap():
    st, key = _state_with_gap()
    st.attach_evidence(key, "ev-42")
    assert st.gaps[key].addressed_by == ["ev-42"]
    assert st.open_gaps == []
    assert st.can_advance_to_review()


def test_open_gaps_block_rereview():
    st, _key = _state_with_gap()
    assert not st.can_advance_to_review()


def test_unknown_gap_key_raises():
    st, _key = _state_with_gap()
    with pytest.raises(EvidenceGapError):
        st.attach_evidence("nope", "ev-1")


def test_duplicate_evidence_attachment_is_idempotent():
    st, key = _state_with_gap()
    st.attach_evidence(key, "ev-1")
    st.attach_evidence(key, "ev-1")
    assert st.gaps[key].addressed_by == ["ev-1"]


def test_reviewer_context_maps_description_to_evidence():
    st, key = _state_with_gap()
    st.attach_evidence(key, "ev-7")
    ctx = st.reviewer_context()
    assert list(ctx.values()) == [["ev-7"]]
    desc = next(iter(ctx))
    assert "second context PoC".lower() in desc.lower()


def test_state_serializes_roundtrip_safe_json():
    st, key = _state_with_gap()
    st.attach_evidence(key, "ev-1")
    d = st.to_dict()
    import json

    json.dumps(d)  # must be JSON-safe for timeline persistence (#22)
    assert d["cycles_used"] == 1
    assert d["gaps"][0]["addressed_by"] == ["ev-1"]
