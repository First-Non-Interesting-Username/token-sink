# Event store (issues #42 / PLAN §13–§15)

Design notes for `observability/event_store.py` — the append-only,
tamper-evident event log that backs the real-time stream (#31 is the
SSE/WebSocket transport; this is the guarantees layer underneath it).

## Core decisions

- **Per-campaign hash chains, one global log.** Each campaign gets its own
  monotonic, gap-free sequence (starting at 1) plus a global log keyed by
  `campaign_id=None`. Independent chains keep verification local and cheap;
  every chain starts from a fixed `GENESIS_HASH`.
- **Hash chaining for tamper evidence.** Each event's `hash` covers its full
  canonical JSON plus the previous event's hash. Any mutation, insertion, or
  deletion breaks `verify()`. This satisfies the §15 "tamper-evident audit
  log" requirement at the storage level.
- **Frozen dataclasses.** `Event` and `ReplayResult` are immutable — there is
  no update path by construction; the API exposes append/replay/prune only.

## Replay and reset semantics

`replay_after(last_event_id)` returns:

- the ordered tail after the given id (normal case), or
- a **reset** result when the id points into pruned history or beyond the log
  head. The transport layer (#31) MUST translate `reset=True` into a
  protocol-level resync signal (e.g. an SSE `event: resync` with a snapshot)
  rather than silently delivering a discontinuous tail — silently skipping a
  gap would violate §13's reconnect-recovery requirement.

## Retention: gap anchors

`prune(keep)` collapses dropped events into a single synthetic
`__gap_anchor__` event that carries forward the last pruned event's hash.
This keeps two invariants intact:

1. list position stays aligned with sequence numbering, and
2. `verify()` still validates the retained window as one unbroken chain.

## Crash safety ("persist before deliver")

The in-memory store assigns seq and computes the hash inside `append()`; the
caller delivers/broadcasts only after it returns. A durable backend (#53)
must replicate this as a single transaction (INSERT row + seq assignment), so
an event recorded as delivered always survives restart — no loss window
between commit and broadcast. See §21 acceptance criterion "Restarting the
application does not lose campaign or finding state."
