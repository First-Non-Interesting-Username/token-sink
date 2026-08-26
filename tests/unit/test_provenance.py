"""Table-driven tests for provenance records (issue #150)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from findings.provenance import (
    ACQUISITION_METHODS,
    ProvenanceRecord,
    RedirectHop,
    capture_redirect_chain,
    findings_with_stale_only_provenance,
    findings_without_provenance,
)

NOW = datetime(2026, 8, 25, 12, 0, 0, tzinfo=UTC)


def _record(**overrides) -> ProvenanceRecord:
    base = dict(
        acquisition_method="direct_fetch",
        fetched_at="2026-08-25T11:00:00Z",
        content_hash=ProvenanceRecord.hash_bytes(b"raw bytes"),
        campaign_uuid="00000000-0000-4000-8000-00000000c0de",
        agent_uuid="00000000-0000-4000-8000-00000000a9e7",
        source_url="https://app.example.com/search",
        http_status=200,
    )
    base.update(overrides)
    return ProvenanceRecord(**base)


# --- construction / taxonomy -------------------------------------------------


def test_unknown_acquisition_method_rejected():
    with pytest.raises(ValueError):
        _record(acquisition_method="telepathy")


def test_all_methods_constructible():
    for m in ACQUISITION_METHODS:
        kwargs = (
            {"source_url": "https://app.example.com", "http_status": 200}
            if m != "local_fixture"
            else {}
        )
        assert _record(acquisition_method=m, **kwargs).acquisition_method == m


def test_network_sourced_requires_url_and_status():
    with pytest.raises(ValueError):
        _record(source_url=None, http_status=None)
    # local_fixture needs neither
    _record(acquisition_method="local_fixture", source_url=None, http_status=None)


def test_bad_content_hash_rejected():
    with pytest.raises(ValueError):
        _record(content_hash="not-a-hash")


# --- integrity ---------------------------------------------------------------


def test_hash_mismatch_detected():
    rec = _record()
    ok, reason = rec.is_trusted(raw_bytes=b"tampered bytes", now=NOW)
    assert not ok
    assert reason == "content-hash-mismatch"


def test_hash_matches_original_bytes():
    rec = _record()
    ok, _ = rec.is_trusted(raw_bytes=b"raw bytes", now=NOW)
    assert ok


def test_redaction_preserves_verifiability():
    """Redaction applies to display copies only; the recorded hash covers
    pre-redaction bytes, so verification must still pass afterwards."""
    raw = b"user=jane secret=sk-example-123 payload"
    rec = _record(content_hash=ProvenanceRecord.hash_bytes(raw))
    display_copy = b"user=<REDACTED> secret=<REDACTED> payload"
    # Display copy differs from raw — that is fine; verification uses the
    # original bytes the store retains.
    assert display_copy != raw
    assert rec.verify_content_hash(raw)


# --- redirect chain ------------------------------------------------------------


def test_redirect_chain_capture():
    chain = capture_redirect_chain(
        [
            ("http://app.example.com/a", 301),
            ("https://app.example.com/b", 302),
            ("https://app.example.com/final", 200),
        ]
    )
    rec = _record(redirect_chain=chain, final_url=chain[-1].url)
    d = rec.to_dict()
    assert len(d["redirect_chain"]) == 3
    assert d["redirect_chain"][0] == {"url": "http://app.example.com/a", "status": 301}
    assert d["final_url"] == "https://app.example.com/final"
    # Round-trip through from_dict preserves the chain.
    rec2 = ProvenanceRecord.from_dict(d)
    assert rec2.redirect_chain == [
        RedirectHop(url=u, status=s)
        for u, s in [
            ("http://app.example.com/a", 301),
            ("https://app.example.com/b", 302),
            ("https://app.example.com/final", 200),
        ]
    ]


# --- trust decay -----------------------------------------------------------------


def test_freshness_classes():
    fresh = _record(fetched_at=(NOW - timedelta(hours=1)).isoformat().replace("+00:00", "Z"))
    aging = _record(fetched_at=(NOW - timedelta(days=5)).isoformat().replace("+00:00", "Z"))
    stale = _record(fetched_at=(NOW - timedelta(days=30)).isoformat().replace("+00:00", "Z"))
    assert fresh.freshness_class(NOW) == "fresh"
    assert aging.freshness_class(NOW) == "aging"
    assert stale.freshness_class(NOW) == "stale"


def test_stale_is_untrusted_but_aging_is_not():
    aging = _record(fetched_at=(NOW - timedelta(days=5)).isoformat().replace("+00:00", "Z"))
    stale = _record(fetched_at=(NOW - timedelta(days=30)).isoformat().replace("+00:00", "Z"))
    ok_a, why_a = aging.is_trusted(raw_bytes=b"raw bytes", now=NOW)
    ok_s, why_s = stale.is_trusted(raw_bytes=b"raw bytes", now=NOW)
    assert ok_a and "aging" in why_a
    assert not ok_s and "stale" in why_s


def test_require_fresh_flag():
    aging = _record(fetched_at=(NOW - timedelta(days=5)).isoformat().replace("+00:00", "Z"))
    ok, why = aging.is_trusted(raw_bytes=b"raw bytes", now=NOW, require_fresh=True)
    assert not ok and "not-fresh" in why


# --- audit views (#97) ------------------------------------------------------------


def test_findings_without_provenance_listed():
    findings = [
        {
            "finding_uuid": "f1",
            "evidence_uuids": ["e1"],
            "provenance_records": [_record().to_dict()],
        },
        {"finding_uuid": "f2", "evidence_uuids": ["e2"]},  # evidence, no provenance
        {"finding_uuid": "f3"},  # no evidence at all — not flagged
    ]
    assert findings_without_provenance(findings) == ["f2"]


def test_stale_only_provenance_listed():
    stale = _record(fetched_at=(NOW - timedelta(days=30)).isoformat().replace("+00:00", "Z"))
    fresh = _record()
    findings = [
        {
            "finding_uuid": "all-stale",
            "evidence_uuids": ["e"],
            "provenance_records": [stale.to_dict()],
        },
        {
            "finding_uuid": "has-fresh",
            "evidence_uuids": ["e"],
            "provenance_records": [stale.to_dict(), fresh.to_dict()],
        },
    ]
    assert findings_with_stale_only_provenance(findings, now=NOW) == ["all-stale"]
