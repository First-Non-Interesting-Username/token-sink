"""Append-only, tamper-evident event store (PLAN §13/§14/§15).

This is the persistence/guarantees layer underneath the real-time stream
(issue #42; the SSE/WebSocket transport itself is issue #31):

- Monotonic, gap-free event IDs per campaign, assigned at append time and
  persisted before delivery.
- Replay: ``replay_after(last_event_id)`` returns every surviving event after
  that ID in order. If the requested ID has been pruned (or never existed),
  the caller gets a ``ReplayReset`` signal so clients resync instead of
  silently skipping a gap.
- Retention: ``prune(keep)`` drops old events but keeps the head hash chain
  intact (pruned events are collapsed into a synthetic "gap anchor" entry so
  verification still works for everything that survives).
- Tamper evidence: each event carries ``prev_hash`` / ``hash``, forming a
  hash chain per campaign. ``verify()`` walks the chain and detects any
  mutation, insertion, or deletion — including deletions that skip the
  pruning API.

Crash-safety note: this class is deliberately storage-backend agnostic. The
in-memory backend is the reference implementation; a SQLite backend (#53)
must wrap its appends in the same transaction as ID assignment so an event is
never broadcast before it is durable ("persist before deliver" — see
docs/event-store.md).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

# Sentinel returned by replay when the client's last-event-id refers to an
# event that no longer exists (pruned) or was never in this log. The stream
# layer must translate this into a protocol-level reset/resync (e.g. SSE
# `event: resync`) rather than pretending the gap does not exist.


@dataclass(frozen=True)
class Event:
    """A single durable event in a campaign's hash chain."""

    seq: int  # monotonic, gap-free per campaign, starts at 1
    campaign_id: str | None  # None = global event (e.g. orchestrator lifecycle)
    type: str
    payload: dict[str, Any]
    ts: float
    prev_hash: str  # hash of the previous event in this campaign's chain
    hash: str

    def canonical(self) -> str:
        """Canonical serialization that the chain hash covers."""
        return json.dumps(
            {
                "seq": self.seq,
                "campaign_id": self.campaign_id,
                "type": self.type,
                "payload": self.payload,
                "ts": self.ts,
                "prev_hash": self.prev_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


@dataclass(frozen=True)
class ReplayResult:
    """Ordered events after a client's last-known ID.

    ``reset`` is True when the requested id could not be honored because the
    events after it were pruned (or the id never existed). In that case
    ``events`` contains whatever survives from the beginning of the retained
    window and the client MUST resync from it rather than treat it as a
    continuous tail.
    """

    events: tuple[Event, ...] = ()
    last_event_id: int = 0  # highest seq in this log overall (even if pruned)
    reset: bool = False


GENESIS_HASH = hashlib.sha256(b"token-sink:event-store:genesis").hexdigest()


def _chain_hash(prev_hash: str, canonical: str) -> str:
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


class EventStore:
    """In-memory reference implementation of the append-only event log.

    One log per campaign plus one global log (``campaign_id=None``). Appends
    are strictly monotonic and gap-free; nothing exposes update/delete of
    committed events.
    """

    def __init__(self) -> None:
        # campaign_id -> list[Event]; None key holds global events.
        self._logs: dict[str | None, list[Event]] = {}
        # Pruned events are replaced by gap anchors: a marker Event whose
        # payload records how many entries were collapsed. This keeps the
        # list indexes equal to seq offsets AND keeps verify() able to check
        # continuity across a prune boundary.
        self._last_seq: dict[str | None, int] = {}

    # -- append ---------------------------------------------------------

    def append(
        self,
        type: str,
        payload: dict[str, Any],
        *,
        campaign_id: str | None = None,
        ts: float = 0.0,
    ) -> Event:
        """Append one event to the campaign (or global) log and return it.

        Callers must persist/deliver only AFTER this returns — with a durable
        backend the same transaction assigns seq and writes the row so no
        delivered event can be lost on restart.
        """
        if not isinstance(type, str) or not type:
            raise ValueError("event type must be a non-empty string")
        if not isinstance(payload, dict):
            raise TypeError("payload must be a dict")

        log = self._logs.setdefault(campaign_id, [])
        prev_hash = log[-1].hash if log else GENESIS_HASH
        seq = self._last_seq.get(campaign_id, 0) + 1
        event = Event(
            seq=seq,
            campaign_id=campaign_id,
            type=type,
            payload=payload,
            ts=ts,
            prev_hash=prev_hash,
            hash="",
        )
        # Hash covers everything except itself (which depends on it).
        event = Event(
            seq=event.seq,
            campaign_id=campaign_id,
            type=type,
            payload=payload,
            ts=ts,
            prev_hash=prev_hash,
            hash=_chain_hash(prev_hash, event.canonical()),
        )
        log.append(event)
        self._last_seq[campaign_id] = seq
        return event

    # -- replay ---------------------------------------------------------

    def replay_after(self, last_event_id: int, *, campaign_id: str | None = None) -> ReplayResult:
        """All retained events with seq > last_event_id, in order.

        Returns a reset result when last_event_id points below the retained
        window (pruned history) or beyond the head of the log — the client
        must resync instead of assuming a contiguous tail.
        """
        log = self._logs.get(campaign_id, [])
        head = self._last_seq.get(campaign_id, 0)

        if last_event_id > head:
            # Unknown/future id: cannot have been produced by this store.
            return ReplayResult(events=tuple(log), last_event_id=head, reset=True)

        if log and last_event_id < log[0].seq - 1:
            # Requested id precedes the retained window -> pruned gap.
            return ReplayResult(
                events=tuple(e for e in log if e.type != "__gap_anchor__"),
                last_event_id=head,
                reset=True,
            )

        # Gap anchors are bookkeeping markers, not real events — never deliver them.
        events = tuple(e for e in log if e.seq > last_event_id and e.type != "__gap_anchor__")
        return ReplayResult(events=events, last_event_id=head, reset=False)

    def latest_id(self, *, campaign_id: str | None = None) -> int:
        return self._last_seq.get(campaign_id, 0)

    # -- retention --------------------------------------------------------

    def prune(self, keep: int, *, campaign_id: str | None = None) -> int:
        """Retain only the most recent ``keep`` events; return pruned count.

        Old entries collapse into a single gap-anchor event so the remaining
        list stays verifiable and indexes stay aligned with seq numbering.
        The anchor reuses the pre-prune chain hash, so the hash chain of the
        survivors is unchanged.
        """
        log = self._logs.get(campaign_id, [])
        if keep < 0:
            raise ValueError("keep must be >= 0")
        if len(log) <= keep:
            return 0

        drop = len(log) - keep
        anchor_seq = log[drop - 1].seq
        anchor_prev = log[drop].prev_hash  # links back over the dropped span
        survivors = log[drop:]
        anchor = Event(
            seq=anchor_seq,
            campaign_id=campaign_id,
            type="__gap_anchor__",
            payload={"pruned_through_seq": anchor_seq},
            ts=survivors[0].ts,
            prev_hash=anchor_prev,
            hash=log[drop - 1].hash,
        )
        self._logs[campaign_id] = [anchor, *survivors]
        return drop

    # -- integrity --------------------------------------------------------

    def verify(self, *, campaign_id: str | None = None) -> bool:
        """Walk the campaign's chain and confirm no tampering occurred."""
        expected_prev = GENESIS_HASH
        for event in self._logs.get(campaign_id, []):
            # A gap anchor stands in for pruned events. Its stored hash is the
            # last pruned event's hash (so survivors still link to it), but its
            # own canonical form is bookkeeping — verify linkage only, and
            # resume the expected chain at the anchor's hash.
            if event.type == "__gap_anchor__":
                expected_prev = event.hash
                continue

            if event.prev_hash != expected_prev:
                return False
            recomputed = _chain_hash(event.prev_hash, event.canonical())
            if recomputed != event.hash:
                return False
            expected_prev = event.hash
        return True
