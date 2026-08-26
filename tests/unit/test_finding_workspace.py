"""Tests for the finding workspace read-model (issue #162, PLAN §13 view 3)."""

from __future__ import annotations

import pytest

from api.finding_workspace import (
    FindingWorkspace,
    UnknownFindingError,
    UnknownVersionError,
)
from findings.lifecycle import FindingLifecycle, RecordStore


@pytest.fixture()
def seeded():
    store = RecordStore()
    lc = FindingLifecycle(store)
    result = lc.submit_finding(
        "camp-1",
        "agent-a",
        {
            "title": "SQLi in login form",
            "category": "web",
            "affected_asset": "example.com",
            "location": "/login",
            "observation": "error-based injection works",
            "hypothesis": "unsanitized input",
            "evidence_refs": ["ev-1", "ev-2"],
            "repro_outline": ["send payload", "observe error"],
        },
    )
    return store, lc, result


def test_timeline_ordered_by_seq_with_out_of_order_arrival(seeded):
    store, _, result = seeded
    fid = result.finding.finding_uuid
    # Simulate a store that received events out of order.
    history = store.history(fid)
    history.reverse()
    store._history[fid] = history
    ws = FindingWorkspace(store)
    tl = ws.timeline(fid)
    seqs = [e["seq"] for e in tl["events"]]
    assert seqs == sorted(seqs) == [0, 1]
    assert tl["current_state"] == "review_cycle_1"


def test_timeline_unknown_finding_raises():
    ws = FindingWorkspace(RecordStore())
    with pytest.raises(UnknownFindingError):
        ws.timeline("nope")


def _advance_to_second_version(lc, result):
    """Push one more transition so a second version snapshot exists.

    The in-memory RecordStore keeps references, so a genuinely distinct
    version snapshot must be an independent Finding object (real persistent
    stores guarantee this; here we mirror it explicitly).
    """
    finding = result.finding
    from findings.lifecycle import State, Transition

    evolved = finding.from_dict(finding.to_dict())
    evolved.evidence_refs = finding.evidence_refs + ["ev-3"]
    lc.store.save(
        evolved,
        Transition(
            seq=2,
            finding_uuid=finding.finding_uuid,
            from_state=State.REVIEW_CYCLE_1.value,
            to_state=State.REVIEW_CYCLE_1.value,
            reason="evidence added",
            actor_uuid="agent-b",
            timestamp="2026-01-01T00:00:02+00:00",
        ),
    )


def test_structured_diff_fields_lists_and_nested(seeded):
    store, lc, result = seeded
    fid = result.finding.finding_uuid
    _advance_to_second_version(lc, result)
    # Also mutate a scalar + nested dict on v3 (independent snapshot).
    v3 = store.load(fid)
    evolved = v3.from_dict(v3.to_dict())
    evolved.title = "SQLi in login form (updated)"
    evolved.tool_provenance = {"scanner": "x", "depth": 2}
    from findings.lifecycle import State, Transition

    store.save(
        evolved,
        Transition(
            seq=3,
            finding_uuid=fid,
            from_state=State.REVIEW_CYCLE_1.value,
            to_state=State.REVIEW_CYCLE_1.value,
            reason="edit",
            actor_uuid="agent-b",
            timestamp="2026-01-01T00:00:03+00:00",
        ),
    )

    ws = FindingWorkspace(store)
    # submit_finding writes TWO versions (discover + queue-for-review), so
    # the edited snapshot is version 4.
    diff = ws.diff_versions(fid, 1, 4)
    assert diff["changed"]["title"] == {
        "kind": "scalar",
        "old": "SQLi in login form",
        "new": "SQLi in login form (updated)",
    }
    list_change = diff["changed"]["evidence_refs"]
    assert list_change["added"] == ["ev-3"] and list_change["removed"] == []
    assert diff["added"]["tool_provenance.depth"] == 2
    assert diff["added"]["tool_provenance.scanner"] == "x"


def test_diff_identical_versions_is_empty(seeded):
    store, lc, result = seeded
    fid = result.finding.finding_uuid
    _advance_to_second_version(lc, result)
    diff = FindingWorkspace(store).diff_versions(fid, 1, 1)
    assert not diff["changed"] and not diff["added"] and not diff["removed"]


def test_diff_unknown_version_rejected(seeded):
    store, _, result = seeded
    with pytest.raises(UnknownVersionError):
        FindingWorkspace(store).diff_versions(result.finding.finding_uuid, 1, 99)


def test_reviews_assembly_includes_poc_and_dissent(seeded):
    store, lc, result = seeded
    fid = result.finding.finding_uuid
    current = store.load(fid)
    current.reviews = [{"reviewer": "r1", "verdict": "valid"}]
    current.poc_reviews = [
        {
            "reviewer": "r2",
            "verdict": "accept",
            "dissent": False,
            "mode": "independent_first",
            "comment": "reproduced",
        },
        {
            "agent_uuid": "r3",
            "verdict": "reject",
            "dissent": True,
            "mode": "discussion_first",
            "comment": "could not reproduce",
        },
    ]
    store.save(
        current,
        type(store.history(fid)[-1])(
            seq=9,
            finding_uuid=fid,
            from_state="review_cycle_1",
            to_state="review_cycle_1",
            reason="reviews recorded",
            actor_uuid="r1",
            timestamp="2026-01-01T00:00:04+00:00",
        ),
    )
    out = FindingWorkspace(store).reviews(fid)
    assert out["reviews"][0]["verdict"] == "valid"
    poc = {p["reviewer"]: p for p in out["poc_reviews"]}
    assert poc["r2"]["verdict"] == "accept" and not poc["r2"]["dissent"]
    assert poc["r3"]["verdict"] == "reject" and poc["r3"]["dissent"]
    assert poc["r3"]["mode"] == "discussion_first"


def test_responses_are_redacted(seeded):
    store, _, result = seeded
    fid = result.finding.finding_uuid
    current = store.load(fid)
    # Plant a secret-shaped string into an event payload and review comment.
    last = store.history(fid)[-1]
    last.payload["note"] = "key was sk-example-abc123def456ghi789"
    current.poc_reviews = [
        {
            "reviewer": "r",
            "verdict": "accept",
            "comment": "token ghp_example0000AAAAplaceholderTOKENvalue12345 (example)",
        }
    ]
    store.save(current, last)

    ws = FindingWorkspace(store)
    tl = ws.timeline(fid)
    assert "sk-example-" not in str(tl)
    revs = ws.reviews(fid)
    assert "ghp_" not in str(revs)


def test_read_only_surface_no_mutation_methods():
    public = {n for n in dir(FindingWorkspace) if not n.startswith("_")}
    assert public == {"timeline", "diff_versions", "reviews"}
