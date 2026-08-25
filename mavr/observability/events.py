"""System event bus (spec §14).

Components (orchestrator, agents, routers, approvals, etc.) call
:meth:`EventBus.publish` to record a structured event. The SSE endpoint
tails the same table. Events are also exposed via :meth:`list_since` so
clients can replay after a disconnect using the last event id.

All events are persisted to the ``system_events`` table (see migration
0006) so they survive a restart. The in-memory tail is for hot reads
and is rebuilt from the DB on startup.

All public methods are safe to call concurrently from the asyncio event
loop; the underlying connection is acquired through :class:`Database`.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from mavr.observability.logging import get_logger
from mavr.storage.database import Database

log = get_logger(__name__)


VALID_SEVERITIES: frozenset[str] = frozenset({"debug", "info", "warning", "error"})


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class SystemEvent:
    id: int
    event_type: str
    severity: str
    campaign_id: str | None
    agent_id: str | None
    task_id: str | None
    finding_id: str | None
    correlation_id: str
    payload: dict[str, Any]
    created_at: str

    def to_sse(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.event_type,
            "severity": self.severity,
            "campaign_id": self.campaign_id,
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "finding_id": self.finding_id,
            "correlation_id": self.correlation_id,
            "payload": self.payload,
            "created_at": self.created_at,
        }


def _row_to_event(row: Any) -> SystemEvent:
    try:
        payload = json.loads(row["payload"]) if row["payload"] else {}
    except (TypeError, ValueError):
        payload = {}
    return SystemEvent(
        id=int(row["id"]),
        event_type=row["event_type"],
        severity=row["severity"] or "info",
        campaign_id=row["campaign_id"],
        agent_id=row["agent_id"],
        task_id=row["task_id"],
        finding_id=row["finding_id"],
        correlation_id=row["correlation_id"] or "",
        payload=payload if isinstance(payload, dict) else {"value": payload},
        created_at=row["created_at"],
    )


class EventBus:
    """Append-only event log; the SSE endpoint tails this."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def publish(
        self,
        *,
        event_type: str,
        payload: dict[str, Any] | None = None,
        severity: str = "info",
        campaign_id: str | None = None,
        agent_id: str | None = None,
        task_id: str | None = None,
        finding_id: str | None = None,
        correlation_id: str = "",
    ) -> int:
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"invalid severity: {severity!r}")
        if not event_type:
            raise ValueError("event_type must be non-empty")
        from mavr.schemas import entities as schema

        cur = await self._db.execute(
            "INSERT INTO system_events("
            "schema_version, event_type, severity, campaign_id, agent_id, "
            "task_id, finding_id, correlation_id, payload, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                schema.SCHEMA_VERSION,
                event_type,
                severity,
                campaign_id,
                agent_id,
                task_id,
                finding_id,
                correlation_id,
                json.dumps(payload or {}, separators=(",", ":"), ensure_ascii=False),
                _now_iso(),
            ),
        )
        return int(cur.lastrowid or 0)

    async def list_since(self, last_id: int, limit: int = 500) -> list[SystemEvent]:
        if last_id < 0:
            last_id = 0
        if limit <= 0 or limit > 5000:
            limit = 500
        async with self._db.acquire() as conn:
            cur = await conn.execute(
                "SELECT id, event_type, severity, campaign_id, agent_id, task_id, "
                "finding_id, correlation_id, payload, created_at "
                "FROM system_events WHERE id > ? ORDER BY id ASC LIMIT ?",
                (last_id, limit),
            )
            return [_row_to_event(r) for r in await cur.fetchall()]

    async def latest(self, limit: int = 50) -> list[SystemEvent]:
        if limit <= 0 or limit > 500:
            limit = 50
        async with self._db.acquire() as conn:
            cur = await conn.execute(
                "SELECT id, event_type, severity, campaign_id, agent_id, task_id, "
                "finding_id, correlation_id, payload, created_at "
                "FROM system_events ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            return list(reversed([_row_to_event(r) for r in await cur.fetchall()]))

    async def count(self) -> int:
        async with self._db.acquire() as conn:
            cur = await conn.execute("SELECT COUNT(*) AS n FROM system_events")
            row = await cur.fetchone()
            return int(row["n"] if row else 0)

    async def prune(self, keep_last: int = 10000) -> int:
        """Drop the oldest rows beyond ``keep_last``; returns rows removed."""
        if keep_last <= 0:
            raise ValueError("keep_last must be positive")
        async with self._db.acquire() as conn:
            cur = await conn.execute(
                "DELETE FROM system_events WHERE id <= ("
                "  SELECT COALESCE(MAX(id), 0) - ? FROM (SELECT id FROM system_events)"
                ")",
                (keep_last,),
            )
            return int(cur.rowcount or 0)


def filter_events(
    events: Iterable[SystemEvent],
    *,
    campaign_id: str | None = None,
    event_type: str | None = None,
    severity: str | None = None,
) -> list[SystemEvent]:
    out: list[SystemEvent] = []
    for e in events:
        if campaign_id is not None and e.campaign_id != campaign_id:
            continue
        if event_type is not None and e.event_type != event_type:
            continue
        if severity is not None and e.severity != severity:
            continue
        out.append(e)
    return out


__all__ = [
    "EventBus",
    "SystemEvent",
    "VALID_SEVERITIES",
    "filter_events",
]
