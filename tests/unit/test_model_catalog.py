"""Tests for the model catalog service (issue #118, PLAN §8.1)."""

from __future__ import annotations

import threading

import pytest

from providers.free_status import FreeStatus
from providers.model_catalog import (
    Capability,
    CatalogEntry,
    ModelCatalog,
    TrustLevel,
)


def make_entry(provider="gw", model="m1", **kw) -> CatalogEntry:
    return CatalogEntry(provider=provider, model_id=model, **kw)


def test_upsert_and_get_roundtrip():
    cat = ModelCatalog()
    e = make_entry(
        capabilities={Capability.CODING, Capability.REASONING},
        context_window=128000,
        max_output_tokens=8192,
        supports_streaming=True,
        supports_structured_output=True,
        request_rate_limit=60,
        token_rate_limit=100_000,
        trust_level=TrustLevel.GATEWAY,
        free_status=FreeStatus.FREE,
    )
    cat.upsert(e, now=100.0)
    got = cat.get("gw", "m1")
    assert got is not None and got.context_window == 128000
    assert Capability.REASONING in got.capabilities
    assert not cat.is_stale(got, now=101.0)
    # Serialization roundtrip
    assert CatalogEntry.from_dict(got.to_dict()) == got


def test_discovery_deprecates_missing_models_instead_of_dropping():
    cat = ModelCatalog()
    cat.apply_discovery("gw", [{"model_id": "a"}, {"model_id": "b"}], now=1.0)
    assert cat.get("gw", "b") is not None

    # Second refresh no longer reports "b" → deprecated, still resolvable.
    updated, deprecated = cat.apply_discovery("gw", [{"model_id": "a"}], now=2.0)
    assert [e.model_id for e in updated] == ["a"]
    assert [e.model_id for e in deprecated] == ["b"]
    gone = cat.get("gw", "b")
    assert gone is not None and gone.deprecated  # NOT removed — campaign safety
    # Deprecated entries excluded from candidates but retrievable directly.
    assert all(e.key != "gw/b" for e, _ in cat.candidates())

    # Rediscovered → un-deprecated automatically.
    cat.apply_discovery("gw", [{"model_id": "a"}, {"model_id": "b"}], now=3.0)
    assert cat.get("gw", "b").deprecated is False


def test_staleness_flag_is_conservative_not_excluding():
    cat = ModelCatalog(stale_after_seconds=10.0)
    cat.upsert(make_entry(model="fresh"), now=100.0)
    cat.upsert(make_entry(model="old"), now=50.0)
    result = dict((e.key, stale) for e, stale in cat.candidates(now=105.0))
    # Stale entries stay visible but flagged so routers lower confidence.
    assert result["gw/fresh"] is False
    assert result["gw/old"] is True


def test_candidates_filter_by_capability_and_structured_output():
    cat = ModelCatalog()
    cat.upsert(
        make_entry(
            model="coder", capabilities={Capability.CODING}, supports_structured_output=True
        ),
        now=1.0,
    )
    cat.upsert(make_entry(model="writer", capabilities={Capability.REPORT_WRITING}), now=1.0)
    hits = [e.key for e, _ in cat.candidates(capability=Capability.CODING)]
    assert hits == ["gw/coder"]
    hits = [e.key for e, _ in cat.candidates(require_structured_output=True)]
    assert hits == ["gw/coder"]


def test_snapshot_freezes_state_for_decision_replay():
    cat = ModelCatalog()
    cat.upsert(make_entry(model="m"), now=1.0)
    snap = cat.snapshot()
    # Mutate after snapshot: raise context window + add a model.
    cat.get("gw", "m").context_window = 999999
    cat.upsert(make_entry(model="new"), now=2.0)

    restored = cat.restore(snap.snapshot_id)
    assert set(restored) == {"gw/m"}  # later addition absent
    assert restored["gw/m"].context_window == 0  # later edit leaked nowhere
    # Live catalog DID change.
    assert cat.get("gw", "m").context_window == 999999
    with pytest.raises(KeyError):
        cat.restore("cat_nope")


def test_concurrent_refresh_during_routing_decisions():
    """Unit test required by the issue: refresh racing candidate queries."""
    cat = ModelCatalog()
    for i in range(50):
        cat.upsert(make_entry(model=f"m{i}"), now=1.0)
    errors: list[Exception] = []
    stop = threading.Event()

    def refresher():
        n = 51
        while not stop.is_set():
            try:
                # Refresh replaces the whole provider listing each tick.
                cat.apply_discovery(
                    "gw", [{"model_id": f"m{i % 50}"} for i in range(n)], now=float(n)
                )
            except Exception as exc:  # pragma: no cover - collected below
                errors.append(exc)
            n += 1

    t = threading.Thread(target=refresher, daemon=True)
    t.start()
    try:
        for _ in range(200):
            pairs = cat.candidates(now=5.0)
            # Invariants that must hold even mid-refresh:
            assert len(pairs) > 0
            for e, stale in pairs:
                assert isinstance(stale, bool)
                assert not e.deprecated
            snap = cat.snapshot()
            restored = cat.restore(snap.snapshot_id)
            assert set(restored) == {e.key for e, _ in pairs}
    finally:
        stop.set()
        t.join(timeout=5)
    assert errors == []
