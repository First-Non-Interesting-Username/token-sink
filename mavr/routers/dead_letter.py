"""Dead-letter queue for unroutable tasks (spec §7.3).

A task ends up in the dead-letter queue when:

* the free-only filter rejects every candidate (``policy_violation``)
* the circuit breaker is open for the chosen model (``circuit_open``)
* the candidate set is empty after filtering (``no_candidates``)
* a coordinator-level timeout occurred (``timeout``)
* an unhandled error escaped the router (``error``)
* the task is intrinsically unroutable for any reason (``unroutable``)

The dead-letter queue is never silently consumed: a record stays
until a human inspects it. ``list`` returns recent entries for the
``system provider list`` view; the upcoming UI surfaces a counter.
"""
from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from mavr.observability.logging import get_logger
from mavr.schemas.routing import DeadLetterEntry, DeadLetterReason
from mavr.storage.database import Database

log = get_logger(__name__)


class DeadLetterQueue:
    def __init__(self, db: Database) -> None:
        self._db = db

    async def enqueue(
        self,
        *,
        reason: str,
        detail: str = "",
        task_id: str | None = None,
        campaign_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> str:
        try:
            reason_enum = DeadLetterReason(reason)
        except ValueError:
            reason_enum = DeadLetterReason.UNROUTABLE
        # Validate FK targets — drop ids that don't exist so the
        # dead-letter entry itself still gets persisted.
        if task_id is not None:
            row = await self._db.fetchone("SELECT id FROM tasks WHERE id = ?", (task_id,))
            if row is None:
                task_id = None
        if campaign_id is not None:
            row = await self._db.fetchone(
                "SELECT id FROM campaigns WHERE id = ?", (campaign_id,)
            )
            if row is None:
                campaign_id = None
        entry = DeadLetterEntry(
            task_id=task_id,
            campaign_id=campaign_id,
            reason=reason_enum,
            detail=detail,
            payload=payload or {},
        )
        row_id = str(uuid4())
        await self._db.execute(
            """
            INSERT INTO dead_letter(
                id, schema_version, task_id, campaign_id, reason, detail,
                payload, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row_id,
                "1.0.0",
                entry.task_id,
                entry.campaign_id,
                entry.reason.value,
                entry.detail,
                json.dumps(entry.payload, sort_keys=True, default=str),
                entry.created_at.isoformat(),
            ),
        )
        log.warning(
            "dead_letter",
            id=row_id,
            reason=entry.reason.value,
            task_id=task_id,
            detail=detail[:200],
        )
        return row_id

    async def list(
        self, *, campaign_id: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        if campaign_id is not None:
            rows = await self._db.fetchall(
                """
                SELECT id, task_id, campaign_id, reason, detail, payload, created_at
                FROM dead_letter
                WHERE campaign_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (campaign_id, int(limit)),
            )
        else:
            rows = await self._db.fetchall(
                """
                SELECT id, task_id, campaign_id, reason, detail, payload, created_at
                FROM dead_letter
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (int(limit),),
            )
        return [dict(r) for r in rows]

    async def count(self, *, campaign_id: str | None = None) -> int:
        if campaign_id is None:
            row = await self._db.fetchone("SELECT COUNT(*) AS c FROM dead_letter")
        else:
            row = await self._db.fetchone(
                "SELECT COUNT(*) AS c FROM dead_letter WHERE campaign_id = ?", (campaign_id,)
            )
        return int(row["c"]) if row else 0
