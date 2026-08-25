"""Unit tests for the append-only, tamper-evident event store (issue #42)."""

from __future__ import annotations

import pytest

from observability.event_store import GENESIS_HASH, EventStore


def test_ids_are_monotonic_and_gap_free() -> None:
    store = EventStore()
    for i in range(1, 6):
        ev = store.append("tick", {"i": i}, campaign_id="c1", ts=i)
        assert ev.seq == i
    assert store.latest_id(campaign_id="c1") == 5
    assert store.latest_id(campaign_id="c2") == 0


def test_campaigns_have_independent_chains() -> None:
    store = EventStore()
    a = store.append("a", {}, campaign_id="c1")
    b = store.append("b", {}, campaign_id="c2")
    assert a.seq == 1 and b.seq == 1
    # Both chains start from the same genesis but are independent.
    assert a.prev_hash == b.prev_hash == GENESIS_HASH
    assert a.hash != b.hash


def test_global_log_uses_none_campaign() -> None:
    store = EventStore()
    g = store.append("orchestrator.started", {})
    assert g.campaign_id is None
    assert store.latest_id() == 1


def test_replay_after_returns_tail_in_order() -> None:
    store = EventStore()
    for i in range(1, 8):
        store.append("e", {"i": i}, campaign_id="c1")
    result = store.replay_after(4, campaign_id="c1")
    assert not result.reset
    assert [e.seq for e in result.events] == [5, 6, 7]
    assert result.last_event_id == 7


def test_replay_from_zero_replays_everything() -> None:
    store = EventStore()
    for i in range(1, 4):
        store.append("e", {"i": i}, campaign_id="c1")
    result = store.replay_after(0, campaign_id="c1")
    assert not result.reset
    assert len(result.events) == 3


def test_replay_with_future_id_signals_reset() -> None:
    store = EventStore()
    store.append("e", {}, campaign_id="c1")
    result = store.replay_after(99, campaign_id="c1")
    assert result.reset


def test_prune_causes_stale_client_reset() -> None:
    """A client arbitrarily far behind must get a reset, never a silent gap."""
    store = EventStore()
    for i in range(1, 11):
        store.append("e", {"i": i}, campaign_id="c1")
    pruned = store.prune(keep=3, campaign_id="c1")
    assert pruned == 7

    # Fresh client: fine.
    fresh = store.replay_after(store.latest_id(campaign_id="c1"), campaign_id="c1")
    assert not fresh.reset and fresh.events == ()

    # Recent-enough client (id >= retained window start - 1): continuous tail.
    ok = store.replay_after(7, campaign_id="c1")
    assert not ok.reset
    assert [e.seq for e in ok.events] == [8, 9, 10]

    # Stale client pointing into pruned history: reset + full retained window.
    stale = store.replay_after(2, campaign_id="c1")
    assert stale.reset
    assert sorted(e.seq for e in stale.events) == [8, 9, 10]


def test_prune_noop_when_under_limit() -> None:
    store = EventStore()
    store.append("e", {}, campaign_id="c1")
    assert store.prune(keep=100, campaign_id="c1") == 0
    assert store.prune(keep=1, campaign_id="c1") == 0


def test_chain_detects_mutation() -> None:
    store = EventStore()
    store.append("e", {"v": 1}, campaign_id="c1")
    store.append("e", {"v": 2}, campaign_id="c1")
    assert store.verify(campaign_id="c1")

    # Tamper with a payload after the fact — verify must fail.
    victim = store._logs["c1"][0]
    tampered = object.__new__(type(victim))
    tampered.__dict__.update(victim.__dict__)
    tampered.payload.__setitem__("v", 999)
    store._logs["c1"][0] = tampered
    assert not store.verify(campaign_id="c1")


def test_chain_detects_deletion_without_anchor() -> None:
    store = EventStore()
    for i in range(3):
        store.append("e", {"i": i}, campaign_id="c1")
    # Simulate someone deleting a middle event behind the API's back.
    del store._logs["c1"][1]
    assert not store.verify(campaign_id="c1")


def test_verify_survives_prune() -> None:
    store = EventStore()
    for i in range(6):
        store.append("e", {"i": i}, campaign_id="c1")
    assert store.verify(campaign_id="c1")
    store.prune(keep=2, campaign_id="c1")
    # The retained window plus its gap anchor must still form a valid chain.
    assert store.verify(campaign_id="c1")


def test_append_validation() -> None:
    store = EventStore()
    with pytest.raises(ValueError):
        store.append("", {})
    with pytest.raises(TypeError):
        store.append("e", ["not", "a", "dict"])  # type: ignore[arg-type]


def test_persist_before_deliver_semantics_documented_by_ordering() -> None:
    """seq assignment happens inside append; the returned event is the durable record.

    With a real DB backend (#53) this becomes a transactional guarantee; here
    we assert the reference behavior the backend must replicate: the seq of an
    event is fixed at append time and later appends never reuse or reorder it.
    """
    store = EventStore()
    first = store.append("e", {}, campaign_id="c1")
    second = store.append("e", {}, campaign_id="c1")
    assert second.seq == first.seq + 1


def test_frozen_events_cannot_be_mutated_via_api() -> None:
    store = EventStore()
    ev = store.append("e", {"k": "v"}, campaign_id="c1")
    # Events are frozen dataclasses; the payload dict is shared, so verify()
    # recomputing hashes over canonical JSON is what actually guards content.
    with pytest.raises(AttributeError):  # frozen dataclass: no attribute writes
        ev.seq = 99  # type: ignore[misc]
