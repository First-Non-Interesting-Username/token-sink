"""Tests for the content-addressed evidence & provenance store (issue #165)."""

import pytest

from findings.evidence_store import (
    EvidenceStore,
    EvidenceStoreError,
    RawCapture,
    RedirectHop,
)


def test_put_raw_is_content_addressed_and_dedupes():
    s = EvidenceStore()
    d1 = s.put_raw(b"raw observation bytes", campaign_uuid="c1", source_url="http://x")
    d2 = s.put_raw(b"raw observation bytes")
    assert d1 == d2
    assert len(s) == 1
    cap = s.get_capture(d1)
    assert cap.source_url == "http://x"  # first writer's metadata kept


def test_digest_mismatch_rejected():
    s = EvidenceStore()
    with pytest.raises(EvidenceStoreError):
        s.put_capture(RawCapture(digest="0" * 64, raw_bytes=b"other bytes"))


def test_link_claim_requires_known_digest():
    s = EvidenceStore()
    d = s.put_raw(b"bytes", campaign_uuid="c1")
    with pytest.raises(EvidenceStoreError):
        s.link_claim("claim-1", ["f" * 64])
    s.link_claim("claim-1", [d])
    chain = s.trace_claim("claim-1")
    assert len(chain) == 1
    assert chain[0]["source_url"] is None or "record_type" in chain[0]
    assert chain[0]["digest"] == d


def test_trace_claim_includes_source_metadata():
    s = EvidenceStore()
    d = s.put_capture(
        RawCapture(
            raw_bytes=b"<html>proof</html>",
            campaign_uuid="c1",
            agent_uuid="a-9",
            source_url="http://target/page",
            source_tool="curl",
            extraction_method="regex",
            redirect_hops=[RedirectHop(url="http://t/1", status=302)],
        )
    )
    s.link_claim("claim-x", [d])
    rec = s.trace_claim("claim-x")[0]
    assert rec["agent_uuid"] == "a-9"
    assert rec["retrieved_at"] > 0
    assert rec["redirect_hops"] == [{"url": "http://t/1", "status": 302}]


def test_reverse_index_and_verify_all():
    s = EvidenceStore()
    d = s.put_raw(b"evidence", campaign_uuid="c1")
    s.link_claim("c-a", [d])
    s.link_claim("c-b", [d])
    assert s.claims_for_digest(d) == ["c-a", "c-b"]
    assert s.verify_all() == []
    # simulate tampering of stored bytes
    s.get_capture(d).raw_bytes = b"TAMPERED"
    assert s.verify_all() == [d]


def test_claim_dedup_keeps_order():
    s = EvidenceStore()
    d1 = s.put_raw(b"a")
    d2 = s.put_raw(b"b")
    s.link_claim("k", [d1, d2])
    s.link_claim("k", [d1, d2])
    assert s.trace_claim("k") and len(s.trace_claim("k")) == 2
