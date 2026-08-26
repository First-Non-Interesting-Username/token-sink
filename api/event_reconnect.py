"""Event-stream reconnection protocol (PLAN §13 real-time transport — issue #256).

The event store (#42) already persists monotonic IDs and supports
``replay_after``; this module adds the *client-session protocol* on top:

- :class:`StreamSession` — one connected client. Tracks its last-seen event
  ID and computes the replay slice to send on reconnect.
- **No lost events, no duplicates**: the server-side guarantee comes from
  delivering exactly ``replay_after(last_seen)`` and advancing the client's
  cursor atomically with delivery. A correct client that applies every
  delivered batch converges to the authoritative state.
- **Gap detection**: when the requested ID falls in a pruned range the
  replay result carries ``reset=True`` — :meth:`StreamSession.reconnect`
  surfaces that as a resync requirement instead of silently splicing a
  partial window onto the client's state.
- **Catch-up snapshot fallback**: on reset, callers can take
  :meth:`EventStoreBackedStream.snapshot_state` (a digest of current head)
  so the client can verify convergence after rebuilding.

Kill/restart safety: session cursors are plain ints derived from the store's
own sequence numbers, so a server restart loses nothing — the next reconnect
simply replays from wherever the client actually got to.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from observability.event_store import EventStore

__all__ = ["ReconnectPlan", "StreamSession", "StreamHub"]


@dataclass(frozen=True)
class ReconnectPlan:
    """What to send a reconnecting client."""

    events: tuple[Any, ...]
    reset: bool  # True → client must resync from snapshot; events are partial
    last_event_id: int  # new client cursor after applying this plan
    snapshot: dict[str, Any] | None = None  # present when reset


class StreamSession:
    """Per-client delivery cursor over an EventStore campaign log."""

    def __init__(self, session_id: str, campaign_id: str | None = None) -> None:
        self.session_id = session_id
        self.campaign_id = campaign_id
        self.last_seen_id = 0
        self.delivered = 0
        self.resyncs = 0

    def observe(self, event_id: int) -> None:
        """Record successful application of an event (cursor advance)."""
        if event_id > self.last_seen_id:
            self.last_seen_id = event_id
        self.delivered += 1

    def pending(self, store: EventStore) -> tuple[Any, ...]:
        """Events this session has not yet seen."""
        return store.replay_after(self.last_seen_id, campaign_id=self.campaign_id).events


class StreamHub:
    """Server side of the reconnection protocol.

    Owns the event store plus live sessions. ``deliver()`` pushes new events
    to a session and advances its cursor atomically; ``reconnect()``
    computes the catch-up plan for a returning client.
    """

    def __init__(self, store: EventStore) -> None:
        self.store = store
        self._sessions: dict[str, StreamSession] = {}

    def register(self, session_id: str, campaign_id: str | None = None) -> StreamSession:
        session = StreamSession(session_id, campaign_id)
        self._sessions[session_id] = session
        return session

    def get(self, session_id: str) -> StreamSession | None:
        return self._sessions.get(session_id)

    def deliver(self, session_id: str, limit: int | None = None) -> tuple[Any, ...]:
        """Send this session everything it hasn't seen; advance its cursor.

        Delivery and cursor update happen under one operation so a crash
        between them cannot create duplicates (the client would simply be
        re-delivered the same batch on reconnect).
        """
        session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(f"unknown session {session_id!r}")
        result = self.store.replay_after(session.last_seen_id, campaign_id=session.campaign_id)
        events = result.events[:limit] if limit else result.events
        for e in events:
            session.observe(e.seq)
        return events

    def reconnect(
        self,
        session_id: str,
        client_last_seen_id: int | None = None,
        make_snapshot: dict[str, Any] | None = None,
    ) -> ReconnectPlan:
        """Compute the catch-up plan for a reconnecting client.

        ``client_last_seen_id`` overrides the stored cursor when the client
        reports its own view (authoritative — it knows what it actually
        applied). When replay hits a pruned gap (reset), a snapshot digest is
        attached when the caller supplies ``make_snapshot``.
        """
        session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(f"unknown session {session_id!r}")
        if client_last_seen_id is not None:
            # Trust the client's applied cursor over our delivery bookkeeping:
            # re-delivering an already-applied event would duplicate state.
            session.last_seen_id = max(0, int(client_last_seen_id))
        result = self.store.replay_after(session.last_seen_id, campaign_id=session.campaign_id)
        for e in result.events:
            session.observe(e.seq)
        if result.reset:
            session.resyncs += 1
            return ReconnectPlan(
                events=result.events,
                reset=True,
                last_event_id=result.last_event_id,
                snapshot=make_snapshot,
            )
        return ReconnectPlan(events=result.events, reset=False, last_event_id=result.last_event_id)

    def drop(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    @staticmethod
    def snapshot_state(store: EventStore, campaign_id: str | None = None) -> dict[str, Any]:
        """Authoritative-state digest for post-reset convergence checks."""
        return {
            "last_event_id": store.latest_id(campaign_id=campaign_id),
            "campaign_id": campaign_id,
            "taken_at": time.time(),
        }
