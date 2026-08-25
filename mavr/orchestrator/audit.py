"""Audit event helpers.

Every state transition, policy decision, and approval should produce an
:class:`mavr.schemas.entities.AuditEvent` that is persisted in the
``audit_events`` table. The helpers here keep the writing path boring
and consistent so we never forget the ``event_id`` (idempotency) or
``schema_version`` fields.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import aiosqlite

from mavr.observability.logging import get_logger
from mavr.schemas import entities as schema

log = get_logger(__name__)


def _now() -> datetime:
    return datetime.now(UTC)


def new_event_id() -> str:
    """Return a fresh event_id (used for idempotency)."""
    return f"evt_{uuid4().hex}"


def _row_to_event(row: aiosqlite.Row) -> schema.AuditEvent:
    metadata = json.loads(row["metadata"]) if row["metadata"] else {}
    return schema.AuditEvent(
        id=row["id"],
        event_id=row["event_id"],
        actor_id=row["actor_id"],
        actor_kind=schema.ActorKind(row["actor_kind"]),
        category=schema.AuditCategory(row["category"]),
        subject_kind=row["subject_kind"],
        subject_id=row["subject_id"],
        prior_state=row["prior_state"],
        new_state=row["new_state"],
        reason=row["reason"],
        metadata=metadata,
        created_at=datetime.fromisoformat(row["created_at"]),
    )


async def record(
    conn: aiosqlite.Connection,
    *,
    actor_id: str | None,
    actor_kind: schema.ActorKind,
    category: schema.AuditCategory,
    subject_kind: str | None = None,
    subject_id: str | None = None,
    prior_state: str | None = None,
    new_state: str | None = None,
    reason: str = "",
    metadata: dict[str, Any] | None = None,
    event_id: str | None = None,
) -> schema.AuditEvent:
    """Insert an audit event and return the parsed entity.

    If the ``event_id`` already exists, the call is a no-op and the
    existing row is returned. This makes audit recording idempotent
    across retries.
    """
    eid = event_id or new_event_id()
    now = _now().isoformat()
    cur = await conn.execute(
        "SELECT id, event_id, actor_id, actor_kind, category, subject_kind, subject_id, "
        "prior_state, new_state, reason, metadata, created_at "
        "FROM audit_events WHERE event_id = ?",
        (eid,),
    )
    row = await cur.fetchone()
    if row is not None:
        return _row_to_event(row)
    new_uuid = str(uuid4())
    payload = json.dumps(metadata or {}, ensure_ascii=False)
    await conn.execute(
        "INSERT INTO audit_events("
        "id, event_id, schema_version, actor_id, actor_kind, category, "
        "subject_kind, subject_id, prior_state, new_state, reason, metadata, created_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            new_uuid,
            eid,
            schema.SCHEMA_VERSION,
            actor_id,
            actor_kind.value,
            category.value,
            subject_kind,
            subject_id,
            prior_state,
            new_state,
            reason,
            payload,
            now,
        ),
    )
    await conn.commit()
    log.info(
        "audit_event",
        event_id=eid,
        actor_kind=actor_kind.value,
        category=category.value,
        subject_kind=subject_kind,
        subject_id=subject_id,
        prior_state=prior_state,
        new_state=new_state,
    )
    return schema.AuditEvent(
        id=new_uuid,
        event_id=eid,
        actor_id=actor_id,
        actor_kind=actor_kind,
        category=category,
        subject_kind=subject_kind,
        subject_id=subject_id,
        prior_state=prior_state,
        new_state=new_state,
        reason=reason,
        metadata=metadata or {},
        created_at=_now(),
    )


async def list_for_subject(
    conn: aiosqlite.Connection,
    subject_kind: str,
    subject_id: str,
) -> list[schema.AuditEvent]:
    cur = await conn.execute(
        "SELECT id, event_id, actor_id, actor_kind, category, subject_kind, subject_id, "
        "prior_state, new_state, reason, metadata, created_at "
        "FROM audit_events WHERE subject_kind = ? AND subject_id = ? ORDER BY created_at",
        (subject_kind, subject_id),
    )
    return [_row_to_event(r) for r in await cur.fetchall()]


async def count(
    conn: aiosqlite.Connection,
    *,
    category: schema.AuditCategory | None = None,
    since: datetime | None = None,
) -> int:
    sql = "SELECT COUNT(*) AS n FROM audit_events WHERE 1=1"
    params: list[Any] = []
    if category is not None:
        sql += " AND category = ?"
        params.append(category.value)
    if since is not None:
        sql += " AND created_at >= ?"
        params.append(since.isoformat())
    cur = await conn.execute(sql, params)
    row = await cur.fetchone()
    return int(row["n"]) if row else 0
