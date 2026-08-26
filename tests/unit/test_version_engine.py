"""Unit tests for the finding version diff engine (issue #291)."""

from __future__ import annotations

import dataclasses

import pytest

from findings.lifecycle import Finding
from findings.severity import Severity, SeverityHistory
from findings.version_engine import (
    VersionError,
    detect_conflict,
    load_versions,
    render_unified,
    workspace_diff,
)


def _finding(**over) -> Finding:
    d = dict(
        campaign_uuid="c-1",
        title="Reflected XSS in search",
        category="xss",
        affected_asset="app.example.com",
        location="/search?q=",
        observation="Payload echoed unencoded.",
        hypothesis="No output encoding on q.",
        evidence_refs=["ev-1"],
    )
    d.update(over)
    return Finding.create(**d)


class _Entry:
    def __init__(self, finding: Finding) -> None:
        self.finding = finding


def test_load_versions_orders_snapshots():
    a, b = _finding(), _finding()
    b.finding_uuid = a.finding_uuid
    b.observation = "updated"
    versions = load_versions([_Entry(a), _Entry(b)])
    assert len(versions) == 2 and versions[0].observation == "Payload echoed unencoded."


def test_load_versions_rejects_empty_history():
    with pytest.raises(VersionError):
        load_versions([])


def test_workspace_diff_flags_claim_changes_semantically():
    v1 = _finding()
    v2 = _finding(title="Reflected XSS in search box", evidence_refs=["ev-1", "ev-2"])
    d = workspace_diff(v1, v2)
    assert [c["field"] for c in d["claim_changes"]] == ["title"]
    assert d["evidence_added"] == ["ev-2"]
    assert d["summary"]["claims_changed"] == 1


def test_workspace_diff_includes_severity_history():
    v1 = _finding()
    v2 = _finding()
    v2.finding_uuid = v1.finding_uuid
    v2.severity_history = SeverityHistory(initial=Severity.LOW)
    v2.severity_history.transition(
        Severity.HIGH, rationale="bulk exposure confirmed", stage="poc_review"
    )
    d = workspace_diff(v1, v2)
    assert d["severity_changes"][0]["to_severity"] == "high"
    rendered = render_unified(d)
    assert "! severity: low -> high" in rendered


def test_render_unified_marks_claim_vs_metadata_lines():
    v1 = _finding(redaction_status="unredacted")
    v2 = _finding(
        redaction_status="redacted",
        title="New title",
        evidence_refs=["ev-1", "ev-9"],
    )
    v2.finding_uuid = v1.finding_uuid
    out = render_unified(workspace_diff(v1, v2))
    lines = out.splitlines()
    claim_line = next(line for line in lines if "title" in line)
    meta_line = next(line for line in lines if "redaction_status" in line)
    assert claim_line.startswith("!")
    assert meta_line.startswith(".")
    assert "+ evidence ev-9" in lines


def test_render_unified_empty_diff():
    f = _finding()
    out = render_unified(workspace_diff(f, dataclasses.replace(f)))
    assert out == "(no changes)"


def test_conflicting_concurrent_edits_detected():
    base = _finding(observation="original observation")
    ours = _finding(observation="agent A's observation")
    theirs = _finding(observation="agent B's observation")
    rep = detect_conflict(base, ours, theirs)
    assert rep["has_conflict"] and rep["conflicts"] == ["observation"]
    assert rep["detail"][0]["ours"] == "agent A's observation"


def test_disjoint_edits_merge_cleanly():
    base = _finding()
    ours = _finding(title="A's title")
    theirs = _finding(hypothesis="B's hypothesis")
    rep = detect_conflict(base, ours, theirs)
    assert not rep["has_conflict"] and rep["cleanly_mergeable"]


def test_identical_branches_no_conflict():
    base = _finding()
    rep = detect_conflict(base, base, base)
    assert rep["cleanly_mergeable"]
