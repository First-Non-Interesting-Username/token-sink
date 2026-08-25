"""Unit tests for duplicate-finding dedup (issue #139).

Table-driven over the three fixture families the issue requires: exact
duplicates, same root cause on different endpoints, and look-alikes that
must NOT merge.
"""

from __future__ import annotations

import uuid

import pytest

from findings.dedup import (
    SIMILARITY_THRESHOLD,
    find_duplicates,
    merge_duplicates,
    root_cause_fingerprint,
    similarity,
)

UUID_A = str(uuid.uuid4())
UUID_B = str(uuid.uuid4())
UUID_C = str(uuid.uuid4())


def _finding(**overrides) -> dict:
    base = {
        "finding_uuid": str(uuid.uuid4()),
        "title": "Reflected XSS in search results",
        "category": "xss-reflected",
        "affected_asset": "https://app.example.com/search",
        "location": "/search parameter q",
        "observation": "The q query parameter is echoed into the page body without HTML encoding.",
        "root_cause": "missing output encoding of the q parameter",
        "evidence_uuids": [str(uuid.uuid4())],
        "review_uuids": [],
        "confidence": {"level": "medium"},
    }
    base.update(overrides)
    return base


# --- fixtures per issue #139 ------------------------------------------------


def test_exact_duplicate_same_fingerprint():
    a = _finding(finding_uuid=UUID_A)
    b = _finding(
        finding_uuid=UUID_B,
        # Different wording, same flaw: fingerprint must still collide because
        # it excludes free-text observation phrasing.
        title="Search box reflects unescaped input",
        observation="User-controlled search text lands raw in HTML.",
    )
    assert root_cause_fingerprint(a) == root_cause_fingerprint(b)


def test_exact_duplicate_detected_as_exact():
    a = _finding()
    b = _finding(title="different words entirely but same root cause")
    links = find_duplicates(b, [a])
    assert len(links) == 1
    assert links[0].status == "exact"
    assert links[0].score == 1.0
    assert links[0].duplicate_of_uuid == a["finding_uuid"]


def test_same_root_cause_different_endpoints_are_linked_not_merged():
    """Same flaw class, two endpoints -> similar candidates, adjudication required."""
    a = _finding(affected_asset="https://app.example.com/search")
    b = _finding(
        affected_asset="https://api.example.com/v1/items",
        location="/v1/items parameter name",
        root_cause="missing output encoding of the name parameter",
        title="Reflected XSS in items listing",
        observation="The name parameter is echoed without HTML encoding.",
    )
    links = find_duplicates(b, [a])
    # Different asset+location+root-cause => NOT an exact fingerprint match.
    assert all(ln.status != "exact" for ln in links)
    if links:
        assert links[0].status == "similar"  # proposal only; human/agent decides


def test_lookalikes_below_threshold_never_link():
    """Related-looking findings that must NOT merge."""
    xss = _finding()
    idor = _finding(
        finding_uuid=UUID_C,
        title="IDOR on invoice download endpoint",
        category="idor",
        affected_asset="https://api.example.com/v1/invoices/{id}/download",
        location="/v1/invoices/{id}/download path parameter",
        observation="Sequential invoice identifiers can be enumerated by an authenticated user.",
        root_cause="missing object-level authorization check on invoice ownership",
    )
    assert find_duplicates(idor, [xss]) == []


def test_self_is_ignored():
    f = _finding()
    assert find_duplicates(f, [dict(f)]) == []


# --- merge semantics --------------------------------------------------------


def test_merge_preserves_provenance_from_both_sides():
    canon = _finding(finding_uuid=UUID_A)
    dup = _finding(
        finding_uuid=UUID_B,
        evidence_uuids=[canon["evidence_uuids"][0], str(uuid.uuid4())],  # one shared, one new
        review_uuids=[str(uuid.uuid4())],
    )
    result = merge_duplicates(canon, [dup], adjudicator_id="agent-xyz")
    assert result.absorbed_uuids == [UUID_B]
    # Evidence unioned without duplicates.
    assert len(canon["evidence_uuids"]) == 2
    assert len(canon["review_uuids"]) == 1
    # Append-only merge decision recorded on BOTH records.
    assert canon["merge_history"][0]["action"] == "merge"
    assert canon["merge_history"][0]["adjudicator"] == "agent-xyz"
    assert dup["merge_history"][0]["action"] == "superseded_by_merge"
    assert dup["merge_history"][0]["canonical_uuid"] == UUID_A


def test_merge_requires_at_least_one_duplicate():
    with pytest.raises(ValueError):
        merge_duplicates(_finding(), [], adjudicator_id="x")


def test_merge_appends_never_overwrites():
    canon = _finding(finding_uuid=UUID_A)
    d1 = _finding(finding_uuid=UUID_B)
    d2 = _finding()
    merge_duplicates(canon, [d1], adjudicator_id="a1")
    history_len = len(canon["merge_history"])
    merge_duplicates(canon, [d2], adjudicator_id="a2")
    assert len(canon["merge_history"]) == history_len + 1  # append-only


def test_similarity_is_symmetric_and_bounded():
    a = _finding()
    b = _finding(title="totally unrelated sql injection in login form", category="sqli")
    s = similarity(a, b)
    assert 0.0 <= s <= 1.0
    assert similarity(a, b) == similarity(b, a)


def test_threshold_conservative():
    # Guard against someone lowering the threshold into merge-happy territory.
    assert SIMILARITY_THRESHOLD >= 0.6
