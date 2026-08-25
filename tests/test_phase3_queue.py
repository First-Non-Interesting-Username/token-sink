"""Tests for the task queue: idempotency, leases, heartbeat, sweeper, DAG."""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from mavr.orchestrator import queue
from mavr.schemas import entities as schema


@pytest.mark.asyncio
async def test_enqueue_is_idempotent(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        t1 = await queue.enqueue(
            conn,
            campaign_id=campaign_id,
            kind=schema.TaskKind.SEARCH,
            payload={"q": "x"},
            idempotency_key="idem-1",
        )
        t2 = await queue.enqueue(
            conn,
            campaign_id=campaign_id,
            kind=schema.TaskKind.SEARCH,
            payload={"q": "x"},
            idempotency_key="idem-1",
        )
        assert t1.id == t2.id


@pytest.mark.asyncio
async def test_enqueue_creates_pending_and_dependencies(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        a = await queue.enqueue(
            conn, campaign_id=campaign_id, kind=schema.TaskKind.SEARCH
        )
        b = await queue.enqueue(
            conn,
            campaign_id=campaign_id,
            kind=schema.TaskKind.IMPACT,
            depends_on=[a.id],
        )
        assert b.id != a.id
        deps = await queue.dependencies_of(conn, b.id)
        assert [d.id for d in deps] == [a.id]


@pytest.mark.asyncio
async def test_dequeue_skips_unmet_dependencies(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        a = await queue.enqueue(
            conn, campaign_id=campaign_id, kind=schema.TaskKind.SEARCH
        )
        b = await queue.enqueue(
            conn,
            campaign_id=campaign_id,
            kind=schema.TaskKind.IMPACT,
            depends_on=[a.id],
            priority=10,
        )
        leased = await queue.dequeue(conn, owner="worker-1", limit=5)
        # a is not yet completed, so only b... wait, b depends on a.
        # b is filtered out; a is eligible.
        ids = [t.id for t in leased]
        assert a.id in ids
        assert b.id not in ids


@pytest.mark.asyncio
async def test_lease_is_exclusive(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        t = await queue.enqueue(
            conn, campaign_id=campaign_id, kind=schema.TaskKind.SEARCH
        )
        first = await queue.dequeue(conn, owner="worker-1")
        second = await queue.dequeue(conn, owner="worker-2")
        assert [x.id for x in first] == [t.id]
        assert second == []


@pytest.mark.asyncio
async def test_heartbeat_extends_lease(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        t = await queue.enqueue(
            conn, campaign_id=campaign_id, kind=schema.TaskKind.SEARCH
        )
        [leased] = await queue.dequeue(conn, owner="worker-1", lease_policy=queue.LeasePolicy(lease_ttl_seconds=1))
        original_expiry = leased.lease_expires_at
        await asyncio.sleep(0.1)
        ok = await queue.heartbeat(
            conn, task_id=t.id, lease_owner=leased.lease_owner,
            lease_policy=queue.LeasePolicy(lease_ttl_seconds=2),
        )
        assert ok
        again = await queue.get(conn, t.id)
        assert again.lease_expires_at > original_expiry


@pytest.mark.asyncio
async def test_sweeper_reclaims_stale_lease(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        t = await queue.enqueue(
            conn, campaign_id=campaign_id, kind=schema.TaskKind.SEARCH
        )
        [leased] = await queue.dequeue(
            conn, owner="worker-1", lease_policy=queue.LeasePolicy(lease_ttl_seconds=1)
        )
        # simulate stale lease: rewind lease_expires_at
        stale = (datetime.now(UTC) - timedelta(seconds=10)).isoformat()
        await conn.execute(
            "UPDATE tasks SET lease_expires_at = ? WHERE id = ?", (stale, t.id)
        )
        result = await queue.sweep_stale_leases(
            conn, policy=queue.LeasePolicy(lease_ttl_seconds=1)
        )
        assert result.reclaimed == 1
        current = await queue.get(conn, t.id)
        assert current.status == schema.TaskStatus.PENDING
        # owner can now re-lease
        re_leased = await queue.dequeue(
            conn, owner="worker-2", lease_policy=queue.LeasePolicy(lease_ttl_seconds=5)
        )
        assert [x.id for x in re_leased] == [t.id]


@pytest.mark.asyncio
async def test_sweeper_dead_letters_after_budget(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        t = await queue.enqueue(
            conn,
            campaign_id=campaign_id,
            kind=schema.TaskKind.SEARCH,
            max_attempts=2,
        )
        # bump attempt to budget
        await conn.execute("UPDATE tasks SET status='failed', attempt=10 WHERE id=?", (t.id,))
        result = await queue.sweep_stale_leases(
            conn, policy=queue.LeasePolicy(dead_letter_after_attempts=3)
        )
        assert result.dead_lettered == 1
        current = await queue.get(conn, t.id)
        assert current.status == schema.TaskStatus.QUARANTINED


@pytest.mark.asyncio
async def test_priority_fifo_within_priority(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        first = await queue.enqueue(
            conn, campaign_id=campaign_id, kind=schema.TaskKind.SEARCH, priority=0
        )
        second = await queue.enqueue(
            conn, campaign_id=campaign_id, kind=schema.TaskKind.SEARCH, priority=5
        )
        third = await queue.enqueue(
            conn, campaign_id=campaign_id, kind=schema.TaskKind.SEARCH, priority=5
        )
        leased = await queue.dequeue(conn, owner="w", limit=3)
        # Highest priority first; FIFO within priority.
        assert [t.id for t in leased] == [second.id, third.id, first.id]


@pytest.mark.asyncio
async def test_dependency_satisfied_after_completion(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        a = await queue.enqueue(
            conn, campaign_id=campaign_id, kind=schema.TaskKind.SEARCH
        )
        b = await queue.enqueue(
            conn,
            campaign_id=campaign_id,
            kind=schema.TaskKind.IMPACT,
            depends_on=[a.id],
        )
        # complete a
        [leased_a] = await queue.dequeue(conn, owner="w1")
        await queue.complete(conn, task_id=a.id, lease_owner=leased_a.lease_owner)
        leased_b = await queue.dequeue(conn, owner="w2")
        assert [t.id for t in leased_b] == [b.id]
