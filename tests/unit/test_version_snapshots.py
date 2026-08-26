"""Unit tests for the finding version snapshot/diff service (issue #291).

Issue #291 asks for what #119's diff functions alone don't provide:

- Version-numbered snapshots addressable as ``v1..vN`` with actor +
  timestamp + transition reason preserved, so a reviewer can answer
  "what changed since the first review cycle and who changed it".
- Diff between any two version numbers through the store.
- Semantic highlight summary: severity changes, claim changes, evidence-link
  changes — surfaced separately from prose diffs.
- Conflicting concurrent edits surfaced per §18 via the ConcurrencyControl
  rejection audit.

Note on numbering: submit_finding records two history entries (discovered +
queued for review) and claim_for_review one more (lease_acquired, a
history-only entry), so a freshly claimed finding sits at v3. Tests derive
versions dynamically from ``current_version`` rather than hardcoding.
"""

from __future__ import annotations

import pytest

from findings.concurrency import ConcurrencyControl
from findings.lifecycle import FindingLifecycle, RecordStore
from findings.version_snapshots import (
    VersionNotFoundError,
    VersionSnapshotStore,
    render_side_by_side,
)

LEASE = "2099-01-01T00:00:00+00:00"


@pytest.fixture()
def setup():
    store = RecordStore()
    life = FindingLifecycle(store)
    cc = ConcurrencyControl(store)
    snap = VersionSnapshotStore(store, concurrency=cc)
    f = life.submit_finding(
        campaign_uuid="11111111-1111-1111-1111-111111111111",
        discovering_agent_uuid="agent-a",
        fields={
            "title": "Reflected XSS in search",
            "category": "xss",
            "affected_asset": "app.example.com",
            "location": "/search?q=",
            "observation": "Payload echoed unencoded.",
            "hypothesis": "No output encoding on q.",
            "evidence_refs": ["ev-1"],
        },
    )
    fid = f.finding.finding_uuid
    # REVIEW_CYCLE_1 is a leased state; take a lease so guarded writes are legal.
    life.claim_for_review(fid, "b", LEASE)
    return store, life, cc, snap, fid


def test_versions_are_numbered_with_actor_and_reason(setup):
    store, _, _, snap, fid = setup
    v = snap.versions(fid)
    assert len(v) == 3  # discovered + queued + lease_acquired
    assert v[0]["actor_uuid"] == "agent-a"
    assert all(x["reason"] and x["timestamp"] for x in v)
    assert [x["version"] for x in v] == list(range(1, len(v) + 1))


def test_guarded_edits_append_addressable_versions(setup):
    store, _, cc, snap, fid = setup
    head = cc.current_version(fid)
    cc.update(
        fid,
        "b",
        expected_version=head,
        mutate=lambda w: setattr(w, "observation", "Echoed AND stored."),
        reason="review edit",
    )
    versions = snap.versions(fid)
    assert len(versions) == head + 1
    assert versions[-1]["actor_uuid"] == "b"
    assert "review edit" in versions[-1]["reason"]
    # Snapshot content actually differs per version.
    assert snap.snapshot(fid, head + 1).observation == "Echoed AND stored."
    assert snap.snapshot(fid, head).observation == "Payload echoed unencoded."


def test_diff_between_any_two_versions(setup):
    store, _, cc, snap, fid = setup
    head = cc.current_version(fid)

    def mutate(w):
        w.observation = "Stored XSS confirmed."
        w.evidence_refs.append("ev-2")

    cc.update(fid, "b", head, mutate=mutate, reason="escalate")
    d = snap.diff(fid, head, head + 1)
    assert {c["field"] for c in d["changed"]} == {"observation"}
    assert d["evidence_added"] == ["ev-2"]
    assert d["from_version"] == head and d["to_version"] == head + 1
    assert d["changed_by"] == "b"


def test_semantic_highlights_severity_and_claims(setup):
    store, _, cc, snap, fid = setup

    def mutate(w):
        w.suspected_impact = "Critical — session takeover."
        w.title = "Stored XSS in search"

    base = cc.current_version(fid)
    cc.update(fid, "b", base, mutate=mutate)
    d = snap.diff(fid, base, base + 1)
    kinds = {(h["kind"], h["field"]) for h in d["highlights"]}
    assert ("severity_change", "suspected_impact") in kinds
    assert ("claim_change", "title") in kinds
    # Evidence unchanged here → no evidence highlights.
    assert not any(h["kind"].startswith("evidence") for h in d["highlights"])


def test_evidence_link_changes_highlighted(setup):
    store, _, cc, snap, fid = setup
    head = cc.current_version(fid)

    def mutate(w):
        w.evidence_refs.remove("ev-1")
        w.evidence_refs.append("ev-9")

    cc.update(fid, "b", head, mutate=mutate)
    d = snap.diff(fid, head, head + 1)
    kinds = {(h["kind"], h.get("ref")) for h in d["highlights"]}
    assert ("evidence_added", "ev-9") in kinds
    assert ("evidence_removed", "ev-1") in kinds


def test_unknown_version_raises(setup):
    _, _, _, snap, fid = setup
    with pytest.raises(VersionNotFoundError):
        snap.snapshot(fid, 999)


def test_conflicting_edit_rejected_and_visible(setup):
    """§18: concurrent conflicting edits detected and surfaceable."""
    _, _, cc, snap, fid = setup
    head = cc.current_version(fid)
    cc.update(fid, "b", head, mutate=lambda w: setattr(w, "observation", "edit A"))
    try:
        # Stale expected_version: another writer already landed edit A.
        cc.update(
            fid,
            "b",
            head,
            mutate=lambda w: setattr(w, "observation", "conflicting edit B"),
        )
        raised = False
    except Exception:
        raised = True
    assert raised
    rejections = cc.rejected_writes(fid)
    assert len(rejections) == 1
    conflicts = snap.conflicts(fid)
    assert conflicts and conflicts[0]["actor_uuid"] == "b"
    # Rejected writes don't advance the timeline: only one real edit landed.
    assert len(snap.versions(fid)) == head + 1


def test_what_changed_since_first_review_answerable_from_api(setup):
    """Acceptance: 'what changed since v(N) and who changed it' from one call."""
    _, _, cc, snap, fid = setup
    base = cc.current_version(fid)
    cc.update(
        fid,
        "b",
        base,
        mutate=lambda w: setattr(w, "location", "/s?q=&x=1"),
        reason="edit b",
    )
    # same lease holder performs both edits
    cc.update(
        fid,
        "b",
        cc.current_version(fid),
        mutate=lambda w: setattr(w, "hypothesis", "H2"),
        reason="edit 2",
    )
    summary = snap.changes_since(fid, base)
    assert summary["actors"] == ["b"]  # single lease holder made both edits
    fields = {c["field"] for c in summary["diff"]["changed"]}
    assert fields == {"location", "hypothesis"}


def test_render_side_by_side_marks_actor_and_fields(setup):
    _, _, cc, snap, fid = setup
    head = cc.current_version(fid)
    cc.update(fid, "b", head, mutate=lambda w: setattr(w, "observation", "New obs"))
    text = render_side_by_side(snap.diff(fid, head, head + 1))
    assert "b" in text
    assert "observation" in text
    assert f"v{head}" in text and f"v{head + 1}" in text
