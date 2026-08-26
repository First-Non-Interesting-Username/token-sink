"""Unit tests for cross-agent duplicate adjudication (issue #246).

Fixtures per the issue: exact duplicates across agents, same root cause on
different endpoints (must NOT auto-merge), and look-alikes that must not be
linked at all.
"""

from __future__ import annotations

import pytest

from findings.cross_agent_dedup import (
    AdjudicationError,
    DuplicateCase,
    adjudicate_merge,
    open_cases,
)


def _finding(agent: str, uuid: str, **overrides) -> dict:
    base = {
        "finding_uuid": uuid,
        "discovered_by": agent,
        "title": "Reflected XSS in search results",
        "category": "xss-reflected",
        "affected_asset": "https://app.example.com/search",
        "location": "/search parameter q",
        "observation": "The q query parameter is echoed into the page body unencoded.",
        "root_cause": "missing output encoding of the q parameter",
        "evidence_uuids": [f"ev-{uuid[:4]}"],
        "review_uuids": [],
    }
    base.update(overrides)
    return base


A1 = _finding("agent-one", "aaaa1111-0000-0000-0000-000000000001")
A2 = _finding("agent-two", "bbbb2222-0000-0000-0000-000000000002")


# -- case opening ----------------------------------------------------------------


def test_exact_cross_agent_duplicate_opens_case_with_both_agents() -> None:
    cases = open_cases(A2, [A1])
    assert len(cases) == 1
    case = cases[0]
    assert set(case.discovering_agents.values()) == {"agent-one", "agent-two"}
    assert case.status == "proposed"
    assert case.score == 1.0


def test_same_root_cause_different_endpoint_is_candidate_not_auto_merge() -> None:
    other = _finding(
        "agent-two",
        A2["finding_uuid"],
        affected_asset="https://app.example.com/profile",
        location="/profile parameter bio",
        observation="The bio field is echoed into the page body unencoded.",
    )
    cases = open_cases(other, [A1])
    # Different asset+location ⇒ different fingerprint; only heuristic link.
    for case in cases:
        assert case.score < 1.0


def test_lookalike_below_threshold_not_linked() -> None:
    unrelated = _finding(
        "agent-two",
        A2["finding_uuid"],
        title="SQL injection in login form",
        category="sqli",
        location="/login parameter user",
        observation="Username field is concatenated into a SQL statement.",
        root_cause="string-concatenated SQL query construction",
    )
    assert open_cases(unrelated, [A1]) == []


def test_same_agent_resubmission_still_visible_as_case() -> None:
    resub = _finding("agent-one", A2["finding_uuid"])  # same agent, new record id
    cases = open_cases(resub, [A1])
    assert len(cases) == 1
    assert len(set(cases[0].discovering_agents.values())) == 1


# -- adjudication independence ------------------------------------------------------


def _case(status: str = "proposed") -> DuplicateCase:
    c = open_cases(A2, [A1])[0]
    c.status = status
    return c


@pytest.mark.parametrize("actor", ["agent-one", "agent-two"])
def test_discovering_agent_cannot_adjudicate_own_pair(actor: str) -> None:
    with pytest.raises(AdjudicationError):
        _case().confirm(actor)


def test_independent_adjudicator_can_confirm_then_reconfirm_fails() -> None:
    case = _case()
    case.confirm("adjudicator-9")
    assert case.status == "confirmed"
    assert case.decisions[-1]["action"] == "confirmed"
    with pytest.raises(AdjudicationError):
        case.confirm("adjudicator-9")


def test_reject_closes_case_and_logs_decision() -> None:
    case = _case()
    case.reject("adjudicator-9", notes="different root causes on inspection")
    assert case.status == "rejected"
    with pytest.raises(AdjudicationError):
        case.confirm("adjudicator-8")


# -- merge with provenance ------------------------------------------------------------


def test_adjudicate_merge_preserves_provenance_from_both_agents() -> None:
    canonical = dict(A1)
    duplicate = dict(A2)
    case = _case()
    result = adjudicate_merge(case, canonical, duplicate, "adjudicator-9")
    # Evidence union from BOTH agents survives the merge.
    assert f"ev-{A1['finding_uuid'][:4]}" in canonical["evidence_uuids"]
    assert f"ev-{A2['finding_uuid'][:4]}" in canonical["evidence_uuids"]
    assert result.absorbed_uuids == [A2["finding_uuid"]]
    # Append-only history on both sides + cross-agent attribution stamp.
    assert canonical["merge_history"][-1]["action"] == "merge"
    assert duplicate["merge_history"][-1]["action"] == "superseded_by_merge"
    attr = canonical["cross_agent_attribution"][-1]
    assert attr["absorbed_from"] == "agent-two"
    assert attr["canonical_by"] == "agent-one"


def test_merge_requires_confirmation_flow_and_marks_merged() -> None:
    case = _case()
    adjudicate_merge(case, dict(A1), dict(A2), "adjudicator-9")
    assert case.status == "merged"
    with pytest.raises(AdjudicationError):
        adjudicate_merge(case, dict(A1), dict(A2), "adjudicator-9")


def test_mismatched_pair_refused() -> None:
    other = _finding("agent-three", "cccc3333-0000-0000-0000-000000000003")
    with pytest.raises(AdjudicationError):
        adjudicate_merge(_case(), dict(A1), other, "adjudicator-9")


def test_decision_log_is_append_only_shape() -> None:
    case = _case()
    case.confirm("adjudicator-9")
    before = list(case.decisions)
    case.status = "merged"  # simulate downstream transition writing next entry
    case._record("merged", "adjudicator-9", "")
    assert case.decisions[: len(before)] == before
    assert len(case.decisions) == len(before) + 1
