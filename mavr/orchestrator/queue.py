"""Task queue with leases, heartbeat, idempotency, and DAG dependencies.

Design (spec §6, §12):

* Tasks are persisted in the ``tasks`` table from migration 0001, plus
  the ``task_dependencies`` DAG table from migration 0002.
* Lease acquisition is atomic via ``UPDATE ... WHERE status='pending'``,
  so only one worker can grab a given task.
* Heartbeat refresh extends ``lease_expires_at`` if the worker is still
  the current owner. Stale leases are reclaimed by the sweeper.
* A unique index on ``idempotency_key`` makes task creation idempotent
  — retries with the same key return the original task.
* Tasks are dequeued in ``(priority DESC, created_at ASC)`` order
  (FIFO within a priority class).
* Tasks whose dependencies are unmet are skipped during dequeue.
"""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import aiosqlite

from mavr.observability.logging import get_logger
from mavr.schemas import entities as schema

log = get_logger(__name__)


class QueueError(RuntimeError):
    """Raised on non-recoverable queue violations."""


class IdempotencyConflict(QueueError):
    """Raised when a new task would collide with an existing one."""


@dataclass(frozen=True)
class LeasePolicy:
    """Tunable parameters for the queue.

    Defaults are safe for the dev loop; the orchestrator can override
    these from configuration.
    """

    lease_ttl_seconds: int = 60
    heartbeat_interval_seconds: float = 15.0
    sweeper_interval_seconds: float = 10.0
    dead_letter_after_attempts: int = 5
    max_dependency_depth: int = 64

    def __post_init__(self) -> None:
        if self.lease_ttl_seconds < 1:
            raise ValueError("lease_ttl_seconds must be >= 1")
        if self.heartbeat_interval_seconds <= 0:
            raise ValueError("heartbeat_interval_seconds must be > 0")
        if self.dead_letter_after_attempts < 1:
            raise ValueError("dead_letter_after_attempts must be >= 1")
        if self.max_dependency_depth < 1:
            raise ValueError("max_dependency_depth must be >= 1")


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat()


def _new_task_id() -> str:
    return str(uuid4())


def _new_lease_token() -> str:
    return f"lease_{secrets.token_urlsafe(16)}"


def _row_to_task(row: aiosqlite.Row) -> schema.Task:
    payload = json.loads(row["payload"]) if row["payload"] else {}
    result = json.loads(row["result"]) if row["result"] else None
    return schema.Task(
        id=row["id"],
        schema_version=row["schema_version"],
        campaign_id=row["campaign_id"],
        parent_task_id=row["parent_task_id"],
        kind=schema.TaskKind(row["kind"]),
        status=schema.TaskStatus(row["status"]),
        priority=row["priority"],
        payload=payload,
        result=result,
        error=row["error"],
        idempotency_key=row["idempotency_key"],
        attempt=row["attempt"],
        max_attempts=row["max_attempts"],
        lease_owner=row["lease_owner"],
        lease_expires_at=datetime.fromisoformat(row["lease_expires_at"]) if row["lease_expires_at"] else None,
        lease_heartbeat_at=datetime.fromisoformat(row["lease_heartbeat_at"]) if row["lease_heartbeat_at"] else None,
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
        started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
        finished_at=datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None,
    )


# ---- enqueue --------------------------------------------------------------


async def _existing_by_idem(conn: aiosqlite.Connection, key: str) -> schema.Task | None:
    cur = await conn.execute(
        "SELECT * FROM tasks WHERE idempotency_key = ?", (key,)
    )
    row = await cur.fetchone()
    return _row_to_task(row) if row else None


async def enqueue(
    conn: aiosqlite.Connection,
    *,
    campaign_id: str,
    kind: schema.TaskKind,
    payload: dict[str, Any] | None = None,
    parent_task_id: str | None = None,
    priority: int = 0,
    idempotency_key: str | None = None,
    max_attempts: int = 3,
    depends_on: list[str] | None = None,
) -> schema.Task:
    """Enqueue a new task. Idempotent on ``idempotency_key``."""
    if idempotency_key:
        existing = await _existing_by_idem(conn, idempotency_key)
        if existing is not None:
            return existing
    if depends_on:
        if len(depends_on) > 64:
            raise QueueError("too many dependencies (max 64)")
        cur = await conn.execute(
            f"SELECT id FROM tasks WHERE id IN ({','.join('?' * len(depends_on))})",
            depends_on,
        )
        found = {r["id"] for r in await cur.fetchall()}
        missing = [d for d in depends_on if d not in found]
        if missing:
            raise QueueError(f"dependency task(s) not found: {missing}")
    now = _now()
    task_id = _new_task_id()
    now_iso = _iso(now)
    await conn.execute(
        "INSERT INTO tasks("
        "id, schema_version, campaign_id, parent_task_id, kind, status, priority, "
        "payload, idempotency_key, attempt, max_attempts, created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            task_id,
            schema.SCHEMA_VERSION,
            campaign_id,
            parent_task_id,
            kind.value,
            schema.TaskStatus.PENDING.value,
            int(priority),
            json.dumps(payload or {}, ensure_ascii=False),
            idempotency_key,
            0,
            int(max_attempts),
            now_iso,
            now_iso,
        ),
    )
    for dep in depends_on or []:
        await conn.execute(
            "INSERT OR IGNORE INTO task_dependencies(task_id, depends_on_id, created_at) "
            "VALUES (?, ?, ?)",
            (task_id, dep, now_iso),
        )
    await conn.commit()
    log.info(
        "task_enqueued",
        task_id=task_id,
        kind=kind.value,
        priority=priority,
        idempotency_key=idempotency_key,
        depends_on_count=len(depends_on or []),
    )
    row = await (await conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))).fetchone()
    assert row is not None
    return _row_to_task(row)


# ---- dequeue / lease ------------------------------------------------------


async def _dependency_satisfied(
    conn: aiosqlite.Connection, task_id: str
) -> bool:
    cur = await conn.execute(
        "SELECT t2.status FROM task_dependencies d "
        "JOIN tasks t2 ON t2.id = d.depends_on_id "
        "WHERE d.task_id = ?",
        (task_id,),
    )
    rows = list(await cur.fetchall())
    if not rows:
        return True
    return all(r["status"] == schema.TaskStatus.COMPLETED.value for r in rows)


async def dequeue(
    conn: aiosqlite.Connection,
    *,
    owner: str,
    lease_policy: LeasePolicy | None = None,
    kinds: list[schema.TaskKind] | None = None,
    limit: int = 1,
) -> list[schema.Task]:
    """Lease up to ``limit`` pending tasks for ``owner``.

    Only tasks whose dependencies are completed are eligible.

    The returned :class:`mavr.schemas.entities.Task` carries a synthetic
    ``lease_owner`` of the form ``"{owner}:{token}"``; the token is a
    per-lease random secret generated here. Callers MUST use this exact
    string as the ``lease_owner`` argument on :func:`heartbeat`,
    :func:`start`, :func:`complete`, and :func:`fail` so that those
    operations are correctly attributed to the worker that won the
    lease.
    """
    if limit < 1:
        raise ValueError("limit must be >= 1")
    policy = lease_policy or LeasePolicy()
    now = _now()
    expires = now + timedelta(seconds=policy.lease_ttl_seconds)
    leased: list[schema.Task] = []
    for _ in range(limit * 4):  # bounded scan; we do not want runaway loops
        where = "WHERE status = 'pending'"
        params: list[Any] = []
        if kinds:
            placeholders = ",".join("?" for _ in kinds)
            where += f" AND kind IN ({placeholders})"
            params.extend(k.value for k in kinds)
        cur = await conn.execute(
            "SELECT id FROM tasks "
            f"{where} "
            "ORDER BY priority DESC, created_at ASC LIMIT 200",
            params,
        )
        candidates = [r["id"] for r in await cur.fetchall()]
        if not candidates:
            break
        picked: str | None = None
        for cand in candidates:
            if not await _dependency_satisfied(conn, cand):
                continue
            picked = cand
            break
        if picked is None:
            break
        token = _new_lease_token()
        now_iso = _iso(now)
        expires_iso = _iso(expires)
        # Atomic lease acquisition.
        cur = await conn.execute(
            "UPDATE tasks SET status = ?, lease_owner = ?, lease_expires_at = ?, "
            "lease_heartbeat_at = ?, updated_at = ?, started_at = COALESCE(started_at, ?) "
            "WHERE id = ? AND status = 'pending'",
            (
                schema.TaskStatus.LEASED.value,
                f"{owner}:{token}",
                expires_iso,
                now_iso,
                now_iso,
                now_iso,
                picked,
            ),
        )
        if cur.rowcount != 1:
            # Lost the race; loop and try the next candidate.
            continue
        row = await (await conn.execute("SELECT * FROM tasks WHERE id = ?", (picked,))).fetchone()
        assert row is not None
        leased.append(_row_to_task(row))
        if len(leased) >= limit:
            break
    if leased:
        await conn.commit()
    return leased


async def reacquire_lease_by_id(
    conn: aiosqlite.Connection,
    *,
    task_id: str,
    owner: str,
    lease_policy: LeasePolicy | None = None,
) -> schema.Task | None:
    """Re-lease a specific task by id (used by the runtime between attempts).

    Atomic: only one worker can transition the row from ``pending`` /
    ``failed`` back to ``leased``. Returns the leased task with a fresh
    ``lease_owner`` of the form ``"{owner}:{token}"``, or ``None`` if
    the row is in any other state (including leased by another worker).

    This is intentionally not implemented as a dequeue-by-kind: a
    transient retry MUST end up holding the same task, even when
    sibling tasks of the same kind exist in the queue.
    """
    policy = lease_policy or LeasePolicy()
    now = _now()
    expires = now + timedelta(seconds=policy.lease_ttl_seconds)
    token = _new_lease_token()
    now_iso = _iso(now)
    expires_iso = _iso(expires)
    cur = await conn.execute(
        "UPDATE tasks SET status = ?, lease_owner = ?, lease_expires_at = ?, "
        "lease_heartbeat_at = ?, updated_at = ? "
        "WHERE id = ? AND status IN ('pending','failed')",
        (
            schema.TaskStatus.LEASED.value,
            f"{owner}:{token}",
            expires_iso,
            now_iso,
            now_iso,
            task_id,
        ),
    )
    if cur.rowcount != 1:
        await conn.commit()
        return None
    await conn.commit()
    row = await (await conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))).fetchone()
    assert row is not None
    return _row_to_task(row)


# ---- lease lifecycle ------------------------------------------------------


async def heartbeat(
    conn: aiosqlite.Connection,
    *,
    task_id: str,
    lease_owner: str,
    lease_policy: LeasePolicy | None = None,
) -> bool:
    """Refresh the lease for ``task_id`` if ``lease_owner`` still owns it.

    Returns True on success, False if the lease has been lost (e.g. the
    sweeper reassigned the task).
    """
    policy = lease_policy or LeasePolicy()
    now = _now()
    expires = now + timedelta(seconds=policy.lease_ttl_seconds)
    cur = await conn.execute(
        "UPDATE tasks SET lease_expires_at = ?, lease_heartbeat_at = ?, updated_at = ? "
        "WHERE id = ? AND lease_owner = ? AND status IN ('leased','running')",
        (_iso(expires), _iso(now), _iso(now), task_id, lease_owner),
    )
    return cur.rowcount == 1


async def start(
    conn: aiosqlite.Connection, *, task_id: str, lease_owner: str
) -> bool:
    """Transition a leased task to running, asserting ownership."""
    now_iso = _iso(_now())
    cur = await conn.execute(
        "UPDATE tasks SET status = ?, updated_at = ? "
        "WHERE id = ? AND lease_owner = ? AND status = 'leased'",
        (schema.TaskStatus.RUNNING.value, now_iso, task_id, lease_owner),
    )
    if cur.rowcount == 1:
        await conn.commit()
    return cur.rowcount == 1


async def complete(
    conn: aiosqlite.Connection,
    *,
    task_id: str,
    lease_owner: str,
    result: dict[str, Any] | None = None,
) -> bool:
    now_iso = _iso(_now())
    cur = await conn.execute(
        "UPDATE tasks SET status = ?, result = ?, lease_owner = NULL, "
        "lease_expires_at = NULL, lease_heartbeat_at = NULL, updated_at = ?, finished_at = ? "
        "WHERE id = ? AND lease_owner = ? AND status IN ('leased','running')",
        (
            schema.TaskStatus.COMPLETED.value,
            json.dumps(result or {}, ensure_ascii=False),
            now_iso,
            now_iso,
            task_id,
            lease_owner,
        ),
    )
    if cur.rowcount == 1:
        await conn.commit()
    return cur.rowcount == 1


async def fail(
    conn: aiosqlite.Connection,
    *,
    task_id: str,
    lease_owner: str | None,
    error: str,
    classification: str,
    release_lease: bool = True,
) -> None:
    """Record a terminal failure on a task.

    Lease is cleared (or not, when ``release_lease`` is False) so the
    sweeper can decide whether to retry or dead-letter.
    """
    now_iso = _iso(_now())
    if release_lease:
        await conn.execute(
            "UPDATE tasks SET status = ?, error = ?, lease_owner = NULL, "
            "lease_expires_at = NULL, lease_heartbeat_at = NULL, updated_at = ?, finished_at = ? "
            "WHERE id = ? AND (lease_owner IS NULL OR lease_owner = ?)",
            (
                schema.TaskStatus.FAILED.value,
                f"[{classification}] {error}",
                now_iso,
                now_iso,
                task_id,
                lease_owner,
            ),
        )
    else:
        await conn.execute(
            "UPDATE tasks SET error = ?, updated_at = ? "
            "WHERE id = ? AND (lease_owner IS NULL OR lease_owner = ?)",
            (f"[{classification}] {error}", now_iso, task_id, lease_owner),
        )
    await conn.commit()


async def cancel(
    conn: aiosqlite.Connection, *, task_id: str, reason: str = ""
) -> bool:
    now_iso = _iso(_now())
    cur = await conn.execute(
        "UPDATE tasks SET status = ?, error = COALESCE(error, ?), updated_at = ?, finished_at = ? "
        "WHERE id = ? AND status IN ('pending','leased','running')",
        (
            schema.TaskStatus.CANCELLED.value,
            reason or "cancelled",
            now_iso,
            now_iso,
            task_id,
        ),
    )
    if cur.rowcount == 1:
        await conn.commit()
    return cur.rowcount == 1


async def requeue(
    conn: aiosqlite.Connection, *, task_id: str, classification: str
) -> bool:
    """Re-queue a task for another attempt (resets lease fields).

    The caller is responsible for bumping ``attempt`` if needed; we
    preserve the counter here.
    """
    now_iso = _iso(_now())
    cur = await conn.execute(
        "UPDATE tasks SET status = 'pending', lease_owner = NULL, "
        "lease_expires_at = NULL, lease_heartbeat_at = NULL, "
        "error = ?, updated_at = ? WHERE id = ? AND status IN ('failed','leased')",
        (f"[{classification}] retry scheduled", now_iso, task_id),
    )
    if cur.rowcount == 1:
        await conn.commit()
    return cur.rowcount == 1


async def quarantine(
    conn: aiosqlite.Connection, *, task_id: str, reason: str, classification: str = "poison"
) -> None:
    now_iso = _iso(_now())
    await conn.execute(
        "UPDATE tasks SET status = ?, error = ?, updated_at = ?, finished_at = ? "
        "WHERE id = ?",
        (
            schema.TaskStatus.QUARANTINED.value,
            f"[{classification}] {reason}",
            now_iso,
            now_iso,
            task_id,
        ),
    )
    await conn.commit()


# ---- sweeper --------------------------------------------------------------


@dataclass(frozen=True)
class SweepResult:
    reclaimed: int
    dead_lettered: int
    requeued: int


async def sweep_stale_leases(
    conn: aiosqlite.Connection,
    *,
    policy: LeasePolicy | None = None,
) -> SweepResult:
    """Reclaim expired leases and dead-letter poison tasks.

    A task whose lease has expired is moved back to ``pending`` so it
    can be dequeued again. A task whose attempt count exceeds
    ``dead_letter_after_attempts`` is moved to ``quarantined``.
    """
    p = policy or LeasePolicy()
    now = _now()
    now_iso = _iso(now)
    # 1. Reclaim expired leases.
    cur = await conn.execute(
        "UPDATE tasks SET status = 'pending', lease_owner = NULL, "
        "lease_expires_at = NULL, lease_heartbeat_at = NULL, updated_at = ? "
        "WHERE status IN ('leased','running') AND lease_expires_at IS NOT NULL "
        "AND lease_expires_at < ?",
        (now_iso, now_iso),
    )
    reclaimed = int(cur.rowcount or 0)
    # 2. Dead-letter tasks that exceeded retry budget.
    cur = await conn.execute(
        "UPDATE tasks SET status = ?, error = COALESCE(error, ?), updated_at = ?, finished_at = ? "
        "WHERE status = 'failed' AND attempt >= ?",
        (
            schema.TaskStatus.QUARANTINED.value,
            f"dead-lettered after {p.dead_letter_after_attempts} attempts",
            now_iso,
            now_iso,
            p.dead_letter_after_attempts,
        ),
    )
    dead = int(cur.rowcount or 0)
    # Commit so the reclaimed state is visible to subsequent workers
    # using a different connection.
    await conn.commit()
    return SweepResult(reclaimed=reclaimed, dead_lettered=dead, requeued=0)


# ---- DAG helpers ----------------------------------------------------------


async def add_dependency(
    conn: aiosqlite.Connection, *, task_id: str, depends_on_id: str
) -> None:
    await conn.execute(
        "INSERT OR IGNORE INTO task_dependencies(task_id, depends_on_id, created_at) "
        "VALUES (?, ?, ?)",
        (task_id, depends_on_id, _iso(_now())),
    )


async def dependencies_of(
    conn: aiosqlite.Connection, task_id: str
) -> list[schema.Task]:
    cur = await conn.execute(
        "SELECT t.* FROM task_dependencies d "
        "JOIN tasks t ON t.id = d.depends_on_id "
        "WHERE d.task_id = ? ORDER BY t.created_at",
        (task_id,),
    )
    return [_row_to_task(r) for r in await cur.fetchall()]


async def dependents_of(
    conn: aiosqlite.Connection, task_id: str
) -> list[schema.Task]:
    cur = await conn.execute(
        "SELECT t.* FROM task_dependencies d "
        "JOIN tasks t ON t.id = d.task_id "
        "WHERE d.depends_on_id = ? ORDER BY t.created_at",
        (task_id,),
    )
    return [_row_to_task(r) for r in await cur.fetchall()]


async def get(conn: aiosqlite.Connection, task_id: str) -> schema.Task | None:
    cur = await conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
    row = await cur.fetchone()
    return _row_to_task(row) if row else None


async def pending_count(
    conn: aiosqlite.Connection, campaign_id: str | None = None
) -> int:
    sql = "SELECT COUNT(*) AS n FROM tasks WHERE status = 'pending'"
    params: list[Any] = []
    if campaign_id is not None:
        sql += " AND campaign_id = ?"
        params.append(campaign_id)
    cur = await conn.execute(sql, params)
    row = await cur.fetchone()
    return int(row["n"]) if row else 0
