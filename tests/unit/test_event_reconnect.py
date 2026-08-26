"""Event-stream reconnection protocol tests (issue #256, PLAN §13)."""

from __future__ import annotations

import pytest

from api.event_reconnect import StreamHub
from observability.event_store import EventStore


@pytest.fixture()
def store():
    return EventStore()


def feed(store: EventStore, n: int, campaign_id: str | None = None) -> list:
    return [store.append("tick", {"i": i}, campaign_id=campaign_id) for i in range(1, n + 1)]


class TestNoLostNoDuplicate:
    def test_replay_after_last_seen_returns_exactly_the_gap(self, store):
        hub = StreamHub(store)
        events = feed(store, 10)
        session = hub.register("s1")
        # Client saw the first 4 before disconnecting.
        for e in events[:4]:
            session.observe(e.seq)
        plan = hub.reconnect("s1", client_last_seen_id=4)
        assert not plan.reset
        assert [e.seq for e in plan.events] == [5, 6, 7, 8, 9, 10]
        assert plan.last_event_id == 10

    def test_deliver_advances_cursor_without_duplicates(self, store):
        hub = StreamHub(store)
        hub.register("s2")
        feed(store, 3)
        first = hub.deliver("s2")
        second = hub.deliver("s2")  # nothing new
        assert [e.seq for e in first] == [1, 2, 3]
        assert second == ()
        assert hub.get("s2").last_seen_id == 3

    def test_partial_delivery_then_resume(self, store):
        hub = StreamHub(store)
        hub.register("s3")
        feed(store, 5)
        batch1 = hub.deliver("s3", limit=2)
        batch2 = hub.deliver("s3", limit=2)
        batch3 = hub.deliver("s3")
        assert [e.seq for e in batch1] == [1, 2]
        assert [e.seq for e in batch2] == [3, 4]
        assert [e.seq for e in batch3] == [5]


class TestRestartMidStream:
    def test_server_restart_client_converges(self, store):
        hub = StreamHub(store)
        hub.register("s4")
        feed(store, 5)
        hub.deliver("s4", limit=3)  # client applied 1..3
        seen = hub.get("s4").last_seen_id

        # Server "restarts": a fresh hub over the SAME durable store.
        hub2 = StreamHub(store)
        hub2.register("s4b")
        feed(store, 5)  # more events happen after restart
        plan = hub2.reconnect("s4b", client_last_seen_id=seen)
        assert not plan.reset
        # Client state converges exactly to the authoritative head.
        assert [e.seq for e in plan.events] == list(range(seen + 1, 11))
        assert plan.last_event_id == store.latest_id()

    def test_client_state_matches_authoritative_after_apply(self, store):
        hub = StreamHub(store)
        hub.register("s5")
        feed(store, 7)
        plan = hub.reconnect("s5", client_last_seen_id=0)
        applied = {e.seq for e in plan.events}
        assert applied == set(range(1, 8))
        assert hub.get("s5").last_seen_id == store.latest_id() == 7


class TestGapDetectionAndSnapshotFallback:
    def test_pruned_history_triggers_reset_with_snapshot(self, store):
        hub = StreamHub(store)
        hub.register("s6")
        feed(store, 50)
        store.prune(keep=10)

        def snapshot():
            return StreamHub.snapshot_state(store)

        plan = hub.reconnect("s6", client_last_seen_id=5, make_snapshot=snapshot())
        assert plan.reset
        assert plan.snapshot is not None
        assert plan.snapshot["last_event_id"] == 50

    def test_future_id_resets(self, store):
        hub = StreamHub(store)
        hub.register("s7")
        feed(store, 3)
        plan = hub.reconnect("s7", client_last_seen_id=999)
        assert plan.reset  # can't honor a future id


class TestSessionBookkeeping:
    def test_unknown_session_rejected(self, store):
        hub = StreamHub(store)
        with pytest.raises(KeyError):
            hub.reconnect("ghost")

    def test_campaign_scoped_sessions_isolated(self, store):
        hub = StreamHub(store)
        hub.register("c1", campaign_id="camp-a")
        feed(store, 2, campaign_id="camp-a")
        feed(store, 2, campaign_id="camp-b")
        events = hub.deliver("c1")
        assert [e.seq for e in events] == [1, 2]  # only camp-a's log
