"""Tests for the immutable evidence store + traceability API (issue #84)."""

import dataclasses
import uuid as uuid_mod

import pytest

from findings.evidence import (
    ANALYSIS_LABELS,
    EvidenceExistsError,
    EvidenceItem,
    EvidenceNotFoundError,
    EvidenceStore,
)


def uid() -> str:
    return str(uuid_mod.uuid4())


def make_item(**overrides) -> EvidenceItem:
    defaults = dict(
        evidence_uuid=uid(),
        campaign_uuid=uid(),
        kind="http_exchange",
        claim_type="source_fact",
        artifact_ref="artifacts/abc123",
        raw_digest="a" * 64,
        provenance_agent_uuid=uid(),
        source_url="https://example.com/in-scope",
        source_tool="curl",
        extraction_method="raw_response",
        retrieved_at="2026-08-25T12:00:00+00:00",
    )
    defaults.update(overrides)
    return EvidenceItem(**defaults)


class TestWriteOnce:
    def test_add_then_refuse_duplicate(self):
        store = EvidenceStore()
        item = make_item()
        store.add(item)
        with pytest.raises(EvidenceExistsError):
            store.add(make_item(evidence_uuid=item.evidence_uuid))

    def test_no_update_or_delete_api(self):
        # The immutability guarantee is partly structural: the store simply
        # exposes no mutation path.
        assert not hasattr(EvidenceStore, "update")
        assert not hasattr(EvidenceStore, "delete")
        assert not hasattr(EvidenceStore, "remove")

    def test_get_unknown_raises(self):
        with pytest.raises(EvidenceNotFoundError):
            EvidenceStore().get(uid())


class TestProvenance:
    def test_records_full_provenance(self):
        agent, task = uid(), uid()
        item = make_item(provenance_agent_uuid=agent, task_uuid=task)
        assert item.provenance_agent_uuid == agent
        assert item.task_uuid == task
        assert item.source_url and item.source_tool and item.retrieved_at
        d = item.to_dict()
        assert d["provenance"]["agent_uuid"] == agent
        assert d["provenance"]["task_uuid"] == task

    def test_claim_types_enforced(self):
        with pytest.raises(ValueError, match="claim_type"):
            make_item(claim_type="definitely_true")

    def test_raw_digest_must_be_sha256(self):
        with pytest.raises(ValueError, match="sha256"):
            make_item(raw_digest="short")

    def test_agent_uuid_required(self):
        with pytest.raises(ValueError, match="provenance"):
            make_item(provenance_agent_uuid="")


class TestInterpretationSeparation:
    """§2.3: raw observations separate from interpretation."""

    def test_interpretation_lives_outside_raw_identity(self):
        # The raw bytes are identified by digest only; the interpretation is
        # a distinct field that never alters raw_digest.
        i1 = make_item(interpretation="looks like SQLi")
        i2 = make_item(
            evidence_uuid=i1.evidence_uuid,
            interpretation="totally different reading",
        )
        assert i1.raw_digest == i2.raw_digest  # same raw bytes
        assert i1.interpretation != i2.interpretation

    def test_content_hash_detects_mutation(self):
        original = make_item()
        store = EvidenceStore()
        store.add(original)

        # Simulate post-creation tampering: fields mutated in place while the
        # recorded creation-time hash stays stale (what a persisted-record
        # edit looks like). The frozen-hash design must catch it.
        tampered = dataclasses.replace(original, interpretation="changed")
        object.__setattr__(tampered, "recorded_hash", original.recorded_hash)
        store._items[original.evidence_uuid] = tampered
        assert store.verify_integrity() == [original.evidence_uuid]

    def test_untampered_store_verifies_clean(self):
        store = EvidenceStore()
        store.add(make_item())
        store.add(make_item())
        assert store.verify_integrity() == []


class TestTraceability:
    def test_traceable_claim(self):
        store = EvidenceStore()
        e1, e2 = make_item(), make_item()
        store.add(e1)
        store.add(e2)
        report = store.check_traceability(
            [
                {
                    "claim": "endpoint returns stack traces",
                    "evidence_uuids": [e1.evidence_uuid, e2.evidence_uuid],
                }
            ]
        )
        assert report.traceable == ("endpoint returns stack traces",)
        assert not report.violations

    def test_unbacked_unlabeled_claim_violates(self):
        store = EvidenceStore()
        report = store.check_traceability([{"claim": "the server is vulnerable"}])
        assert len(report.violations) == 1
        assert "not labeled" in report.violations[0]

    @pytest.mark.parametrize("label", ANALYSIS_LABELS)
    def test_explicit_analysis_labels_pass(self, label):
        store = EvidenceStore()
        report = store.check_traceability([{"claim": "this likely chains to RCE", "label": label}])
        assert report.labeled_analysis == ("this likely chains to RCE",)
        assert not report.violations

    def test_unknown_evidence_citation_violates(self):
        store = EvidenceStore()
        ghost = uid()
        report = store.check_traceability([{"claim": "x", "evidence_uuids": [ghost]}])
        assert report.violations and ghost in report.violations[0]

    def test_mixed_claims_all_classified(self):
        store = EvidenceStore()
        e = make_item()
        store.add(e)
        claims = [
            {"claim": "observed fact", "evidence_uuids": [e.evidence_uuid]},
            {"claim": "my guess", "label": "inference"},
            {"claim": "wild assertion"},
        ]
        report = store.check_traceability(claims)
        assert len(report.traceable) == 1
        assert len(report.labeled_analysis) == 1
        assert len(report.violations) == 1


class TestResolveChain:
    def test_resolve_claim_returns_chain_in_order(self):
        store = EvidenceStore()
        items = [make_item() for _ in range(3)]
        for i in items:
            store.add(i)
        chain = store.resolve_claim([i.evidence_uuid for i in items])
        assert [c.evidence_uuid for c in chain] == [i.evidence_uuid for i in items]

    def test_resolve_reports_all_missing_not_first(self):
        store = EvidenceStore()
        good = make_item()
        store.add(good)
        missing_a, missing_b = uid(), uid()
        with pytest.raises(EvidenceNotFoundError) as exc:
            # unknown IDs interleaved — all must be reported at once
            store.resolve_claim([missing_a, good.evidence_uuid, missing_b])
        assert missing_a in str(exc.value) and missing_b in str(exc.value)


class TestTombstoneSafety:
    def test_audit_pinned_evidence_survives_finding_deletion(self):
        store = EvidenceStore()
        pinned, unpinned = make_item(), make_item()
        store.add(pinned)
        store.add(unpinned)
        store.retain_for_audit([pinned.evidence_uuid])
        deletable = store.deletable_after_tombstone([pinned.evidence_uuid, unpinned.evidence_uuid])
        assert deletable == {unpinned.evidence_uuid}

    def test_pin_unknown_id_fails_loudly(self):
        with pytest.raises(EvidenceNotFoundError):
            EvidenceStore().retain_for_audit([uid()])
