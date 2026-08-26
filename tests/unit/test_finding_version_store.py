"""Tests for the finding version store + inspect CLI (issue #291, PLAN §13 view 3)."""

from __future__ import annotations

import json

import pytest

from cli import finding_inspect
from findings.concurrency import ConcurrencyControl, ConflictError
from findings.lifecycle import Finding, FindingLifecycle, RecordStore, State, Transition
from findings.version_store import (
    UnknownVersionError,
    VersionStore,
    format_diff_report,
    render_unified_diff,
)


@pytest.fixture()
def env():
    store = RecordStore()
    lc = FindingLifecycle(store)
    result = lc.submit_finding(
        "camp-1",
        "agent-a",
        {
            "title": "XSS in search",
            "category": "web",
            "affected_asset": "example.com",
            "location": "/search",
            "observation": "reflected XSS works",
            "hypothesis": "no output encoding",
            "evidence_refs": ["ev-1"],
            "repro_outline": ["submit payload", "observe alert"],
        },
    )
    return store, lc, result


def _save(store, finding, seq, actor, reason):
    store.save(
        finding,
        Transition(
            seq=seq,
            finding_uuid=finding.finding_uuid,
            from_state="review_cycle_1",
            to_state="review_cycle_1",
            reason=reason,
            actor_uuid=actor,
            timestamp=f"2026-01-01T00:00:{seq:02d}+00:00",
        ),
    )


def test_versions_lists_author_and_reason_per_version(env):
    store, lc, result = env
    fid = result.finding.finding_uuid
    evolved = Finding.from_dict(result.finding.to_dict())
    evolved.observation = "reflected XSS works in IE too"
    _save(store, evolved, 2, "agent-b", "impact edit")

    rows = VersionStore(store).versions(fid)
    assert len(rows) == 3  # submit writes two transitions + this one
    assert rows[0]["author"] == "agent-a"
    assert rows[0]["reason"] == "discovered"
    assert rows[2]["author"] == "agent-b"
    assert rows[2]["reason"] == "impact edit"


def test_semantic_diff_between_versions(env):
    store, lc, result = env
    fid = result.finding.finding_uuid
    evolved = Finding.from_dict(result.finding.to_dict())
    evolved.evidence_refs = ["ev-1", "ev-2"]
    evolved.observation = "updated observation"
    _save(store, evolved, 5, "agent-b", "evidence + observation update")

    vs = VersionStore(store)
    # submit_finding stored 2 versions; the edit is version 3.
    d = vs.diff(fid, 1, 3)
    assert d["changed_by"] == {"from_author": "agent-a", "to_author": "agent-b"}
    assert d["evidence_added"] == ["ev-2"]
    obs = next(c for c in d["changed"] if c["field"] == "observation")
    assert obs["new"] == "updated observation"
    assert not d["has_unlinked_drift"]  # evidence backs the change


def test_unlinked_claim_drift_flagged(env):
    store, _, result = env
    fid = result.finding.finding_uuid
    stripped = Finding.from_dict(result.finding.to_dict())
    stripped.evidence_refs = []
    stripped.observation = "rewritten with no evidence"
    _save(store, stripped, 7, "agent-c", "rewrite")
    d = VersionStore(store).diff(fid, 1, 3)
    assert d["has_unlinked_drift"]
    assert any(u["field"] == "observation" for u in d["unlinked_claims"])


def test_unknown_version_raises(env):
    store, _, result = env
    with pytest.raises(UnknownVersionError):
        VersionStore(store).diff(result.finding.finding_uuid, 1, 99)


def test_conflicts_surfaced_from_concurrency_control(env):
    store, _, result = env
    fid = result.finding.finding_uuid
    cc = ConcurrencyControl(store)

    def mutate(f: Finding) -> None:
        f.observation = "concurrent edit"

    # The finding sits in a LEASED state, so the lease guard fires before
    # the version check; move it to an unleased state (vulnerabilities) so
    # the optimistic-concurrency rejection is what gets exercised.

    stored = store.load(fid)
    if isinstance(stored.state, str):
        stored.state = State(stored.state)
    stored.state = State.VULNERABILITIES
    with pytest.raises(ConflictError):
        cc.update(fid, "agent-z", expected_version=99, mutate=mutate, reason="stale edit")

    conflicts = VersionStore(store, concurrency=cc).conflicts(fid)
    assert len(conflicts) == 1
    assert conflicts[0]["agent_uuid"] == "agent-z"
    assert conflicts[0]["expected_version"] == 99
    assert conflicts[0]["reason"] == "stale edit"


def test_render_unified_diff_shows_changes():
    text = render_unified_diff("line one\nline two\n", "line one\nline TWO changed\n", "v1", "v3")
    assert "--- v1" in text and "+++ v3" in text
    assert "-line two" in text and "+line TWO changed" in text


def test_cli_lists_versions_human_readable(env):
    store, _, result = env
    fid = result.finding.finding_uuid
    captured: list[str] = []
    rc = finding_inspect.run_cli(["--uuid", fid, "--versions"], store, out=captured.append)
    text = "\n".join(captured)
    assert rc == 0
    assert "agent-a" in text and "discovered" in text


def test_cli_diff_json_output(env):
    store, _, result = env
    fid = result.finding.finding_uuid
    captured: list[str] = []
    rc = finding_inspect.run_cli(
        ["--uuid", fid, "--diff", "1", "1", "--json"], store, out=captured.append
    )
    parsed = json.loads("\n".join(captured))
    assert rc == 0
    assert parsed["finding_uuid"] == fid
    assert parsed["from_version"] == 1 and parsed["to_version"] == 1


def test_format_diff_report_renders_sections(env):
    store, _, result = env
    fid = result.finding.finding_uuid
    evolved = Finding.from_dict(result.finding.to_dict())
    evolved.evidence_refs = ["ev-1", "ev-2"]
    _save(store, evolved, 4, "agent-b", "add evidence")
    report = format_diff_report(VersionStore(store).diff(fid, 1, 3))
    assert f"finding {fid}" in report
    assert "+ evidence: ev-2" in report
