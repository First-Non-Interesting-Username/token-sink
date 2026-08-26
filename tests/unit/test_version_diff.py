"""Unit tests for finding version diffing (issue #119)."""

from __future__ import annotations

from findings.lifecycle import Finding
from findings.version_diff import CLAIM_FIELDS, diff_findings, render_markdown


def _finding(**over) -> Finding:
    d = dict(
        campaign_uuid="11111111-1111-1111-1111-111111111111",
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


def test_identical_versions_produce_empty_diff():
    a = _finding()
    b = _finding()
    b.finding_uuid = a.finding_uuid
    d = diff_findings(a, b)
    assert d["changed"] == []
    assert d["evidence_added"] == [] and d["evidence_removed"] == []
    assert not d["has_unlinked_drift"]


def test_scalar_change_detected_with_old_new():
    a = _finding()
    b = _finding(observation="Payload echoed AND stored.")
    d = diff_findings(a, b)
    changed = {c["field"]: c for c in d["changed"]}
    assert set(changed) == {"observation"}
    assert changed["observation"]["old"] == "Payload echoed unencoded."
    assert changed["observation"]["new"] == "Payload echoed AND stored."


def test_evidence_add_remove():
    a = _finding(evidence_refs=["ev-1", "ev-2"])
    b = _finding(evidence_refs=["ev-2", "ev-3"])
    d = diff_findings(a, b)
    assert d["evidence_added"] == ["ev-3"]
    assert d["evidence_removed"] == ["ev-1"]


def test_claim_change_without_any_evidence_is_flagged():
    a = _finding()
    b = _finding(title="Completely different claim", evidence_refs=[])
    d = diff_findings(a, b)
    assert d["has_unlinked_drift"]
    assert [u["field"] for u in d["unlinked_claims"]] == ["title"]


def test_claim_change_with_existing_evidence_not_flagged():
    # evidence_refs unchanged but non-empty ⇒ change is considered backed.
    a = _finding()
    b = _finding(observation="Updated after re-test.")
    d = diff_findings(a, b)
    assert not d["has_unlinked_drift"]


def test_metadata_changes_are_diffed_but_never_claim_drift():
    from findings.lifecycle import State

    a = _finding()
    b = _finding()
    b.state = State.POC_REVIEW
    d = diff_findings(a, b)
    fields = [c["field"] for c in d["changed"]]
    assert "state" not in fields  # metadata tracked separately from claims
    assert not d["has_unlinked_drift"]


def test_confidence_change_is_a_claim_field():
    a = _finding(confidence=0.4)
    b = _finding(confidence=0.9)
    d = diff_findings(a, b)
    assert any(c["field"] == "confidence" for c in d["changed"])


def test_all_claim_fields_covered_by_constant():
    # guard: the drift rule tracks the full technical-claim surface
    assert "observation" in CLAIM_FIELDS and "repro_outline" in CLAIM_FIELDS


def test_markdown_render_includes_tables_and_warning():
    a = _finding()
    b = _finding(title="Renamed claim", evidence_refs=[])  # no backing evidence ⇒ drift
    d = diff_findings(a, b)
    md = render_markdown(d)
    assert "| title" in md
    assert "Claim drift warning" in md
    assert d["evidence_added"] == []


def test_redacted_rendering_masks_values_but_keeps_structure():
    a = _finding()
    b = _finding(observation="secret payload xyz")
    d = diff_findings(a, b)
    md = render_markdown(d, redacted=True)
    assert "secret payload xyz" not in md
    assert "[redacted]" in md
    assert "| observation" in md


def test_render_clean_diff_when_nothing_changed():
    a = _finding()
    b = _finding()
    b.finding_uuid = a.finding_uuid
    md = render_markdown(diff_findings(a, b))
    assert "No scalar fields changed." in md
