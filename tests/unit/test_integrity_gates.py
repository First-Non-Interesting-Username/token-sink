"""Unit tests for evidence integrity gates (issue #303).

Covers: manifest construction, verify-at-gate success, tampered bytes
detected at the gate, missing artifacts blocking advancement, append-only
failure ledger, and bundle round-trip with embedded manifest.
"""

from __future__ import annotations

import pytest

from findings.evidence import EvidenceItem
from findings.integrity import (
    IntegrityError,
    build_manifest,
    verify_at_gate,
)
from storage.artifacts import ArtifactStore
from storage.bundle import export_campaign, import_campaign


def _evidence(uuid_suffix: str) -> EvidenceItem:
    return EvidenceItem(
        evidence_uuid=f"ev-{uuid_suffix}",
        campaign_uuid="c-1",
        kind="observation",
        claim_type="source_fact",
        artifact_ref="artifacts/x",
        raw_digest="0" * 64,
        provenance_agent_uuid="agent-1",
    )


@pytest.fixture()
def store(tmp_path):
    s = ArtifactStore(tmp_path / "artifacts")
    digest = s.put_bytes(b"raw observation bytes").digest
    # EvidenceItem is immutable post-freeze: build with the real digest.
    item = EvidenceItem(
        evidence_uuid="ev-1",
        campaign_uuid="c-1",
        kind="observation",
        claim_type="source_fact",
        artifact_ref="artifacts/x",
        raw_digest=digest,
        provenance_agent_uuid="agent-1",
    )
    return s, item


# --- manifest ------------------------------------------------------------------


def test_manifest_covers_all_artifacts_and_is_stable(store):
    _, item = store
    m1 = build_manifest("f-1", [item])
    m2 = build_manifest("f-1", [item])
    assert m1.content_hash() == m2.content_hash()
    assert item.raw_digest in m1.entries


def test_manifest_changes_when_evidence_set_changes(store):
    s, item = store
    other = s.put_bytes(b"different bytes").digest
    m1 = build_manifest("f-1", [item])
    m2_item = EvidenceItem(
        evidence_uuid="ev-2",
        campaign_uuid="c-1",
        kind="log_excerpt",
        claim_type="source_fact",
        artifact_ref="a",
        raw_digest=other,
        provenance_agent_uuid="agent-1",
    )
    m2 = build_manifest("f-1", [item, m2_item])
    assert m1.content_hash() != m2.content_hash()


# --- gate verification -----------------------------------------------------------


def test_gate_passes_on_intact_evidence(store):
    s, item = store
    rec = verify_at_gate("f-1", [item], s)
    assert rec.ok and rec.checked == 1


def test_tampered_bytes_block_the_gate(store, tmp_path):
    s, item = store
    # Corrupt the stored artifact behind the store's back (path layout:
    # root/"ab"/digest[:2]/digest — see storage.artifacts._digest_path).
    path = tmp_path / "artifacts" / "ab" / item.raw_digest[:2] / item.raw_digest
    path.write_bytes(b"TAMPERED")
    ledger: list = []
    with pytest.raises(IntegrityError):
        verify_at_gate("f-1", [item], s, ledger=ledger)
    assert ledger and not ledger[0].ok  # failure recorded, never dropped


def test_missing_artifact_blocks_the_gate(store):
    s, item = store
    ghost = EvidenceItem(
        evidence_uuid="ev-ghost",
        campaign_uuid="c-1",
        kind="observation",
        claim_type="source_fact",
        artifact_ref="a",
        raw_digest="1" * 64,
        provenance_agent_uuid="agent-1",
    )
    with pytest.raises(IntegrityError):
        verify_at_gate("f-1", [ghost], s)


def test_ledger_is_append_only_across_checks(store):
    s, item = store
    ledger: list = []
    verify_at_gate("f-1", [item], s, ledger=ledger)
    verify_at_gate("f-1", [item], s, ledger=ledger)
    assert len(ledger) == 2 and all(r.ok for r in ledger)


# --- bundle round-trip --------------------------------------------------------------


def test_bundle_round_trip_with_embedded_manifest(tmp_path):
    src = ArtifactStore(tmp_path / "src")
    dst = ArtifactStore(tmp_path / "dst")
    digest = src.put_bytes(b"evidence payload").digest
    item = EvidenceItem(
        evidence_uuid="ev-b",
        campaign_uuid="c-1",
        kind="observation",
        claim_type="source_fact",
        artifact_ref="a",
        raw_digest=digest,
        provenance_agent_uuid="agent-1",
    )
    manifest = build_manifest("f-9", [item])
    bundle = export_campaign(
        src,
        [digest],
        tmp_path / "b.tar",
        metadata={"finding_manifest": manifest.content_hash()},
    )
    imported = import_campaign(bundle, dst)
    assert imported == [digest]
    # Gate re-verification passes against the destination store.
    rec = verify_at_gate("f-9", [item], dst)
    assert rec.ok
