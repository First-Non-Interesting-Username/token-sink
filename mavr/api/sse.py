"""Server-Sent Events endpoint (spec §13).

The SSE endpoint at ``/api/events/stream`` tails the persisted
``system_events`` table. Clients reconnect by passing the last event
id as the ``last_event_id`` query parameter; the server replays every
event with ``id > last_event_id`` before opening the live tail. The
DB is the ring buffer: rows older than the retention window are
pruned by :func:`prune_old_events`.
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass

from fastapi import Request
from starlette.responses import StreamingResponse

from mavr.observability.events import EventBus, SystemEvent
from mavr.storage.database import Database

DEFAULT_POLL_INTERVAL = 1.0
DEFAULT_RING_BUFFER_SIZE = 5000


@dataclass
class SSEHub:
    """In-process metadata for the SSE endpoint.

    The DB is the actual ring buffer; the hub just exposes tunables
    and a per-client fan-out via :func:`stream_events`.
    """

    db: Database
    events: EventBus
    poll_interval: float = DEFAULT_POLL_INTERVAL
    ring_buffer_size: int = DEFAULT_RING_BUFFER_SIZE

    async def replay(self, last_event_id: int, limit: int = 1000) -> list[SystemEvent]:
        return await self.events.list_since(last_id=last_event_id, limit=limit)

    async def tail(self, last_event_id: int) -> list[SystemEvent]:
        return await self.events.list_since(last_id=last_event_id, limit=500)

    async def prune(self) -> int:
        return await self.events.prune(keep_last=self.ring_buffer_size)


def _format_sse(event: SystemEvent) -> bytes:
    data = json.dumps(event.to_sse(), ensure_ascii=False)
    return (
        f"id: {event.id}\n"
        f"event: {event.event_type}\n"
        f"data: {data}\n\n"
    ).encode()


def _format_heartbeat(seq: int) -> bytes:
    payload = {"type": "heartbeat", "seq": seq}
    return (
        f"event: heartbeat\n"
        f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
    ).encode()


async def stream_events(
    db: Database,
    *,
    events: EventBus,
    last_event_id: int,
    request: Request,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
) -> AsyncIterator[bytes]:
    """Yield SSE-encoded events for as long as the client is connected."""
    seen_id = int(last_event_id or 0)
    hub = SSEHub(db=db, events=events, poll_interval=poll_interval)

    # 1. Replay anything the client missed.
    replayed = await hub.replay(seen_id)
    for ev in replayed:
        yield _format_sse(ev)
        seen_id = max(seen_id, ev.id)

    # 2. Open the live tail.
    seq = 0
    try:
        while True:
            if await request.is_disconnected():
                break
            await asyncio.sleep(poll_interval)
            tail = await hub.tail(seen_id)
            if tail:
                for ev in tail:
                    yield _format_sse(ev)
                    seen_id = max(seen_id, ev.id)
            else:
                seq += 1
                yield _format_heartbeat(seq)
    except asyncio.CancelledError:
        # Client disconnected; uvicorn cancels the generator.
        return


async def sse_response(
    db: Database,
    *,
    events: EventBus,
    last_event_id: int = 0,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
) -> StreamingResponse:
    """Helper for tests: produce a StreamingResponse that auto-closes."""
    hub = SSEHub(db=db, events=events, poll_interval=poll_interval)

    async def _gen() -> AsyncIterator[bytes]:
        seen_id = int(last_event_id or 0)
        replayed = await hub.replay(seen_id)
        for ev in replayed:
            yield _format_sse(ev)
            seen_id = max(seen_id, ev.id)
        seq = 0
        while True:
            await asyncio.sleep(poll_interval)
            tail = await hub.tail(seen_id)
            if tail:
                for ev in tail:
                    yield _format_sse(ev)
                    seen_id = max(seen_id, ev.id)
            else:
                seq += 1
                yield _format_heartbeat(seq)

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


__all__ = [
    "DEFAULT_POLL_INTERVAL",
    "DEFAULT_RING_BUFFER_SIZE",
    "SSEHub",
    "sse_response",
    "stream_events",
]
