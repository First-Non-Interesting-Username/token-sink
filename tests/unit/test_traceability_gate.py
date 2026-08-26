"""Unit tests for the claim-to-evidence traceability gate (issue #282)."""

from __future__ import annotations

import uuid

import pytest

from findings.evidence import EvidenceItem, EvidenceStore
from findings.lifecycle import Finding
from findings.traceability import (
    TRACEABLE_CLAIM_FIXTURES,
    UNTRACEABLE_CLAIM_FIXTURES,
    TraceabilityError,
    TraceabilityGate,
    extract_claims,
    render_traceability,
    validate_claim_shape,
)


def uid() -> str:
    return str(uuid.uuid4())


def make_item(**overrides) -> EvidenceItem:
    defaults = dict(
        evidence_uuid=uid(),
        campaign_uuid=uid(),
        kind="http_exchange",
        claim_type="source_fact",
        artifact_ref="artifacts/abc123",
        raw_digest="a" * 64,
        provenance_agent_uuid=uid(),
    )
    defaults.update(overrides)
    return EvidenceItem(**defaults)


def _finding_with_claims(claims: list[dict]) -> Finding:
    f = Finding.create(campaign_uuid="c-1", title="Reflected XSS in search")
    f.claims = claims
    return f


@pytest.fixture()
def store() -> EvidenceStore:
    s = EvidenceStore()
    s.add(make_item())  # one arbitrary item
    # Pin one known uuid for fixtures to cite.
    s.add(make_item(evidence_uuid="ev-1"))
    return s


def test_claim_shape_requires_text():
    with pytest.raises(TraceabilityError):
        validate_claim_shape({"claim": "   ", "evidence_uuids": ["x"]})


def test_claim_shape_requires_backing_or_label():
    for fx in UNTRACEABLE_CLAIM_FIXTURES:
        with pytest.raises(TraceabilityError):
            validate_claim_shape(fx)


def test_well_formed_claims_pass_shape_check():
    for fx in TRACEABLE_CLAIM_FIXTURES:
        validate_claim_shape(fx)


def test_gate_catches_untraceable_claims(store):
    gate = TraceabilityGate(store)
    f = _finding_with_claims(list(UNTRACEABLE_CLAIM_FIXTURES))
    with pytest.raises(TraceabilityError) as ei:
        gate.check(f)
    assert "untraceable claim" in str(ei.value)
    assert len(ei.value.args[0].split("\n- ")) >= 3


def test_gate_passes_traceable_claims(store):
    gate = TraceabilityGate(store)
    f = _finding_with_claims(
        [
            {"claim": "Payload echoed unencoded.", "evidence_uuids": ["ev-1"]},
            {"claim": "Likely affects only versions below 2.4.", "label": "analysis"},
        ]
    )
    report = gate.check(f)
    assert len(report.traceable) == 1
    assert len(report.labeled_analysis) == 1
    assert report.violations == ()


def test_gate_fails_on_unknown_evidence_ids(store):
    gate = TraceabilityGate(store)
    f = _finding_with_claims([{"claim": "Server is vulnerable.", "evidence_uuids": ["nope"]}])
    with pytest.raises(TraceabilityError):
        gate.check(f)


def test_finding_without_claims_passes_gate(store):
    gate = TraceabilityGate(store)
    f = Finding.create(campaign_uuid="c", title="t")
    assert extract_claims(f) == []
    report = gate.check(f)
    assert report.violations == ()


def test_render_traceability_shows_chain(store):
    f = _finding_with_claims(
        [
            {"claim": "Payload echoed unencoded.", "evidence_uuids": ["ev-1"]},
            {"claim": "Likely v2.x only.", "label": "analysis"},
        ]
    )
    out = render_traceability(f, store)
    lines = out.splitlines()
    assert lines[0].startswith("[evidence]")
    assert "ev-1(artifacts/abc123)" in lines[0]
    assert lines[1] == "[analysis] Likely v2.x only."
