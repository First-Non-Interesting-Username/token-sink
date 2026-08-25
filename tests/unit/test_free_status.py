"""Tests for the free-status verification workflow (issue #87, PLAN §8.2)."""

from __future__ import annotations

import pytest

from providers.free_status import (
    Evidence,
    FreeStatus,
    ModelFreeStatus,
    VerificationError,
    VerificationStore,
)


def test_unknown_by_default_and_excluded_from_routing():
    store = VerificationStore()
    assert store.get("opencode-zen", "some-model").status is FreeStatus.UNKNOWN
    # unknown ⇒ never eligible for free-only routing (§8.2 hard rule)
    assert store.effective_status("opencode-zen", "some-model") is FreeStatus.UNKNOWN
    assert ("opencode-zen", "some-model") not in store.routable_free()


def test_submit_does_not_change_status_without_human_approval():
    store = VerificationStore()
    req = store.submit(
        "kilo",
        "m1",
        FreeStatus.FREE,
        submitted_by="agent-task-42",
        evidence=[Evidence(kind="pricing_page", reference="https://example.com/pricing")],
        now=100.0,
    )
    # Status must still be UNKNOWN — model/agent submission alone never promotes.
    assert store.get("kilo", "m1").status is FreeStatus.UNKNOWN
    assert len(store.pending_requests()) == 1

    entry = store.approve(req.request_id, approved_by="operator-alice", now=200.0)
    assert entry.status is FreeStatus.FREE
    assert entry.source == f"verification:{req.request_id}"
    assert entry.verified_at == 200.0
    assert store.routable_free(now=201.0) == [("kilo", "m1")]
    assert store.pending_requests() == []


def test_submit_unknown_proposal_rejected():
    store = VerificationStore()
    with pytest.raises(VerificationError):
        store.submit("p", "m", FreeStatus.UNKNOWN, submitted_by="x", evidence=[])


def test_approve_unknown_request_rejected():
    store = VerificationStore()
    with pytest.raises(VerificationError):
        store.approve("vfq_nope", approved_by="alice")


def test_deny_keeps_status_unknown():
    store = VerificationStore()
    req = store.submit("p", "m", FreeStatus.PAID, submitted_by="op", evidence=[], now=1.0)
    store.deny(req.request_id, denied_by="alice", reason="no evidence")
    assert store.get("p", "m").status is FreeStatus.UNKNOWN


def test_expiry_reverts_to_unknown():
    store = VerificationStore()
    req = store.submit("p", "m", FreeStatus.FREE, submitted_by="op", evidence=[], now=0.0)
    store.approve(req.request_id, approved_by="a", ttl_seconds=10.0, now=0.0)
    assert store.effective_status("p", "m", now=5.0) is FreeStatus.FREE
    # After the TTL the verified status reverts to unknown.
    assert store.effective_status("p", "m", now=11.0) is FreeStatus.UNKNOWN
    reverted = store.expire_stale(now=11.0)
    assert len(reverted) == 1 and reverted[0].status is FreeStatus.UNKNOWN
    assert ("p", "m") not in store.routable_free(now=12.0)


def test_pricing_hash_drift_invalidates_verification():
    store = VerificationStore()
    store.set_pricing_hash("p", "m", "<html>free tier v1</html>")
    req = store.submit("p", "m", FreeStatus.FREE, submitted_by="op", evidence=[], now=0.0)
    store.approve(req.request_id, approved_by="a", now=1.0)
    assert store.effective_status("p", "m", now=2.0) is FreeStatus.FREE

    # Upstream pricing page changes → stale-verified, revert to unknown.
    store.set_pricing_hash("p", "m", "<html>now paid</html>")
    invalidated = store.refresh_pricing_hashes(now=3.0)
    assert len(invalidated) == 1
    assert store.effective_status("p", "m", now=4.0) is FreeStatus.UNKNOWN
    assert ("p", "m") not in store.routable_free(now=4.0)


def test_audit_trail_is_chained_and_tamper_evident():
    store = VerificationStore()
    r1 = store.submit("p", "m", FreeStatus.FREE, submitted_by="op", evidence=[], now=0.0)
    store.approve(r1.request_id, approved_by="a", now=1.0)
    r2 = store.submit("q", "n", FreeStatus.PAID, submitted_by="op", evidence=[], now=2.0)
    store.deny(r2.request_id, denied_by="a")

    trail = store.audit_trail()
    actions = [e.action for e in trail]
    assert actions == ["submit", "approve", "submit", "deny"]
    assert store.verify_audit_chain()

    # Tamper with a detail field → chain check fails.
    tampered = trail[1]
    object.__setattr__(tampered, "actor", "mallory")
    assert not store.verify_audit_chain()


def test_catalog_entry_roundtrip_serialization():
    entry = ModelFreeStatus(
        provider="gw",
        model_id="fast",
        status=FreeStatus.FREE,
        source="verification:x",
        verified_at=5.0,
        pricing_page_hash="abc",
        expires_at=None,
    )
    assert ModelFreeStatus.from_dict(entry.to_dict()) == entry
