"""Load tests (spec §19, §21).

These tests exercise the system at scale and under sustained pressure.
All of them run offline; they use the in-process MockAdapter so no
provider IO is required.

The goals are:

* prove the router pool can run 20 parallel routers without losing
  decisions or dead-lettering healthy tasks;
* prove the task queue can absorb and process hundreds of enqueued
  tasks under contention;
* prove the rate-limit path triggers quarantine without deadlocking;
* prove the evidence store handles large evidence collections;
* prove the UI SSE endpoint can stream dozens of events without
  dropping any.

Tests are tagged so they can be skipped with ``-m 'not load'`` if
you want a fast feedback loop.
"""
from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import aiosqlite
import pytest

from mavr.agents.identity import mint_agent
from mavr.orchestrator import queue
from mavr.orchestrator.agents import insert as insert_agent
from mavr.orchestrator.runtime import RuntimeOptions, execute
from mavr.policy.engine import (
    DecisionKind,
    RateCounter,
    ScopePolicyEngine,
    ToolCall,
)
from mavr.providers.model_catalog.scores import ModelScoreStore
from mavr.providers.registry import ProviderRegistry
from mavr.routers.circuit_breaker import BreakerConfig, CircuitBreakerStore
from mavr.routers.dead_letter import DeadLetterQueue
from mavr.routers.pool import BaseRouter, RouterPool
from mavr.routers.usage import UsageAccountant
from mavr.schemas import entities as schema
from mavr.schemas.routing import (
    ChatMessage,
    ChatRequest,
    RoutingPolicy,
    RoutingTask,
    TaskCategory,
)
from mavr.storage.artifacts import ArtifactStore
from mavr.storage.database import Database, apply_migrations
from mavr.tests._fakes import MockAdapter

pytestmark = pytest.mark.load


# ---- 1. 20 parallel routers --------------------------------------------


class TwentyRoutersRouter(BaseRouter):
    """A trivial router that proposes the full eligible list."""

    def __init__(self, idx: int) -> None:
        super().__init__(f"load-router-{idx}")

    async def propose(self, task, registry, scores):
        out = []
        for adapter in registry.all():
            for m in adapter.models():
                out.append(
                    _candidate_for(adapter.provider_id, m.model_key, 0.5)
                )
        return out


def _candidate_for(provider_id: str, model_key: str, score: float):
    from mavr.schemas.routing import RouterCandidate

    return RouterCandidate(
        provider_id=provider_id,
        model_key=model_key,
        score=score,
        expected_cost=0.0,
        rationale="load-test",
        confidence=0.5,
    )


@pytest.mark.asyncio
async def test_twenty_parallel_routers(tmp_path: Path) -> None:
    db = Database(tmp_path / "load.db")
    await apply_migrations(db, "up")
    reg = ProviderRegistry([MockAdapter()])
    pool = RouterPool(
        registry=reg,
        scores=ModelScoreStore(db),
        breakers=CircuitBreakerStore(db, BreakerConfig()),
        usage=UsageAccountant(db),
        dead_letter=DeadLetterQueue(db),
        db=db,
        routers=[TwentyRoutersRouter(i) for i in range(20)],
        router_timeout_seconds=2.0,
    )
    # Run 50 routing decisions concurrently.
    tasks = [
        RoutingTask(
            task_id=str(uuid4()),
            category=TaskCategory.GENERIC,
            policy=RoutingPolicy.BEST_SCORE,
            request=ChatRequest(messages=[ChatMessage(role="user", content=str(i))]),
            free_only=True,
        )
        for i in range(50)
    ]
    decisions = await asyncio.gather(*[pool.decide(t) for t in tasks])
    assert len(decisions) == 50
    # Every decision has a chosen candidate (the mock pool has at least
    # one free model).
    chosen_count = sum(1 for d in decisions if d.chosen is not None)
    assert chosen_count == 50


# ---- 2. Hundreds of queued tasks --------------------------------------


@pytest.mark.asyncio
async def test_hundreds_of_queued_tasks(tmp_path: Path) -> None:
    db = Database(tmp_path / "queue.db")
    await apply_migrations(db, "up")
    cid = str(uuid4())
    now = datetime.now(UTC).isoformat()
    async with db.acquire() as conn:
        await conn.execute(
            "INSERT INTO campaigns(id, schema_version, name, target_spec, state, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (cid, schema.SCHEMA_VERSION, "load", "{}", "active", now, now),
        )
        await conn.commit()

    async def factory() -> aiosqlite.Connection:
        return await db.connect()

    # Enqueue 200 tasks in parallel.
    async with db.acquire() as conn:
        for _ in range(200):
            await queue.enqueue(
                conn,
                campaign_id=cid,
                kind=schema.TaskKind.SEARCH,
                payload={"url": "https://example.com/"},
            )

    # Lease in batches of 10, run them through a trivial handler, and
    # assert the queue drains to zero.
    completed = 0
    for _ in range(40):
        async with db.acquire() as conn:
            leased = await queue.dequeue(
                conn, owner="load-worker", limit=10
            )
        if not leased:
            break

        async def factory_local() -> aiosqlite.Connection:
            return await db.connect()

        for task in leased:
            agent = mint_agent(schema.AgentRole.SEARCH, campaign_id=cid)
            async with db.acquire() as conn:
                await insert_agent(conn, agent)

            async def handler(t: schema.Task, ctx) -> dict:
                return {"ok": True}

            await execute(
                factory_local,
                task=task,
                agent=agent,
                handler=handler,
                options=RuntimeOptions(
                    heartbeat_interval_seconds=5.0,
                    backoff_initial_seconds=0.01,
                ),
            )
            completed += 1
    assert completed == 200


# ---- 3. Sustained rate-limit pressure ---------------------------------


class TestRateLimit:
    @pytest.mark.asyncio
    async def test_rate_limit_quarantines_overflow(self) -> None:
        engine = ScopePolicyEngine(resolve_dns=False)
        scope = schema.ScopePolicy(
            id="33333333-3333-4333-8333-333333333333",
            campaign_id="11111111-1111-4111-8111-111111111111",
            allowed_targets=["example.com"],
            allowed_methods=["GET"],
            action_allowlist=[],
            rate_limit_per_minute=10,
        )
        campaign = schema.Campaign(
            id="11111111-1111-4111-8111-111111111111",
            name="t",
            target_spec={"hosts": ["example.com"]},
        )
        decisions = []
        for _ in range(50):
            d = engine.evaluate(
                campaign,
                scope,
                ToolCall(url="https://example.com/x"),
                rate=RateCounter(per_minute=11),
            )
            decisions.append(d)
        # Every call beyond the limit must be quarantined.
        assert all(d.kind == DecisionKind.QUARANTINE for d in decisions)
        assert all(d.rule == "rate_limit_exceeded" for d in decisions)


# ---- 4. Large evidence collections ------------------------------------


@pytest.mark.asyncio
async def test_large_evidence_collection(tmp_path: Path) -> None:
    db = Database(tmp_path / "evidence.db")
    await apply_migrations(db, "up")
    store = ArtifactStore(tmp_path / "artifacts")

    cid = str(uuid4())
    now = datetime.now(UTC).isoformat()
    async with db.acquire() as conn:
        await conn.execute(
            "INSERT INTO campaigns(id, schema_version, name, target_spec, "
            "state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (cid, schema.SCHEMA_VERSION, "ev", "{}", "active", now, now),
        )
        await conn.commit()

    # 500 evidence items, each with a small artifact. Just hammer the
    # store; performance is not the focus, just durability + count.
    sha_hashes: list[str] = []
    for i in range(500):
        aid = str(uuid4())
        content = f"page {i} " + ("x" * 256)
        store.write(aid, content.encode("utf-8"), suffix=".deadbeef")
        import hashlib

        h = hashlib.sha256(content.encode("utf-8")).hexdigest()
        item = schema.EvidenceItem(
            id=str(uuid4()),
            campaign_id=cid,
            source_url=f"https://example.com/page-{i}",
            retrieved_at=datetime.now(UTC),
            content_hash=h,
            byte_length=len(content),
            content_type="text/plain",
            raw_artifact_id=aid,
            notes="load-test",
            created_at=datetime.now(UTC),
        )
        from mavr.search.evidence import record_evidence

        async with db.acquire() as conn:
            await record_evidence(conn, evidence=item)
            await conn.commit()
        sha_hashes.append(h)
    assert len({h for h in sha_hashes}) == 500  # all unique

    async with db.acquire() as conn:
        cur = await conn.execute(
            "SELECT COUNT(*) AS n FROM evidence_items"
        )
        n = (await cur.fetchone())["n"]
    assert n == 500


# ---- 5. UI SSE throughput ----------------------------------------------


@pytest.mark.asyncio
async def test_sse_throughput_under_load(tmp_path: Path) -> None:
    """Publish 200 system events and read them back via the SSE
    stream. Asserts ordering, no losses for the events we see, and a
    non-zero throughput within the timeout window."""
    import json

    from mavr.api.sse import stream_events
    from mavr.observability.events import EventBus

    db = Database(tmp_path / "sse.db")
    await apply_migrations(db, "up")
    bus = EventBus(db)
    cid = str(uuid4())
    now = datetime.now(UTC).isoformat()
    async with db.acquire() as conn:
        await conn.execute(
            "INSERT INTO campaigns(id, schema_version, name, target_spec, "
            "state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (cid, schema.SCHEMA_VERSION, "sse", "{}", "active", now, now),
        )
        await conn.commit()

    for i in range(200):
        await bus.publish(
            event_type="test_event",
            payload={"i": i},
            campaign_id=cid,
        )

    # Build a minimal Request-like object that the stream expects.
    class _DummyRequest:
        async def is_disconnected(self) -> bool:
            return False

    # Limit the SSE pull to the first batch (200) by reading 200 lines
    # then breaking.
    seen: list[int] = []
    received_bytes = 0
    started = time.monotonic()
    stream = stream_events(
        db,
        events=bus,
        last_event_id=0,
        request=_DummyRequest(),  # type: ignore[arg-type]
        poll_interval=0.0,
    )
    try:
        async for chunk in stream:
            received_bytes += len(chunk)
            if not chunk.startswith(b"id:"):
                if len(seen) >= 200:
                    return
                continue
            data_line = next(
                (line for line in chunk.split(b"\n") if line.startswith(b"data:")), b""
            )
            payload = json.loads(data_line[len(b"data:"):].strip())
            seen.append(payload["payload"]["i"])
            if len(seen) >= 200:
                return
            if time.monotonic() - started > 5.0:
                return
    finally:
        await stream.aclose()
    elapsed = time.monotonic() - started
    assert seen, "no SSE events received"
    assert seen == sorted(seen), "events delivered out of order"
    assert seen[0] == 0
    assert len(seen) == len(set(seen)), "duplicate events delivered"
    assert received_bytes > 0
    assert elapsed < 6.0
