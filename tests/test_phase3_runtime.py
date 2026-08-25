"""Tests for the agent runtime: success, transient retry, quarantine, kill switch."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import BaseModel

from mavr.orchestrator import killswitch, queue, runtime
from mavr.orchestrator.failures import (
    PolicyViolation,
)
from mavr.schemas import entities as schema


class _Out(BaseModel):
    n: int


def _now() -> datetime:
    return datetime.now(UTC)


async def _register_agent(agent_id: str, role: schema.AgentRole = schema.AgentRole.SEARCH) -> schema.Agent:
    return schema.Agent(
        id=agent_id,
        schema_version=schema.SCHEMA_VERSION,
        parent_id=None,
        role=role,
        status=schema.AgentStatus.QUEUED,
        created_at=_now(),
        updated_at=_now(),
    )


async def _seed_agent(db, agent: schema.Agent) -> None:
    from mavr.orchestrator import agents as agents_mod
    async with db.acquire() as conn:
        await agents_mod.insert(conn, agent)


@pytest.mark.asyncio
async def test_runtime_success(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        task = await queue.enqueue(conn, campaign_id=campaign_id, kind=schema.TaskKind.SEARCH)
    # Lease via the queue
    async with migrated_db.acquire() as conn:
        leased = await queue.dequeue(conn, owner="worker-1", kinds=[schema.TaskKind.SEARCH])
    assert leased and leased[0].id == task.id
    agent = await _register_agent("55555555-5555-4555-8555-555555555555")
    await _seed_agent(migrated_db, agent)

    async def handler(t: schema.Task, ctx: runtime.RuntimeContext) -> dict[str, Any]:
        ctx.charge_tokens(10)
        return {"n": 42}

    async def factory():
        return await migrated_db.connect()

    final = await runtime.execute(
        factory,
        task=leased[0],
        agent=agent,
        handler=handler,
        output_schema=_Out,
    )
    assert final.status == schema.TaskStatus.COMPLETED
    assert final.result == {"n": 42}
    async with migrated_db.acquire() as conn:
        cur = await conn.execute(
            "SELECT tokens_used FROM agents WHERE id = ?", (agent.id,)
        )
        row = await cur.fetchone()
        assert row["tokens_used"] == 10


@pytest.mark.asyncio
async def test_runtime_transient_retries_then_succeeds(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        task = await queue.enqueue(
            conn, campaign_id=campaign_id, kind=schema.TaskKind.SEARCH, max_attempts=5
        )
    async with migrated_db.acquire() as conn:
        leased = await queue.dequeue(conn, owner="worker-1")
    agent = await _register_agent("66666666-6666-4666-8666-666666666666")
    await _seed_agent(migrated_db, agent)

    attempts = {"n": 0}

    async def handler(t: schema.Task, ctx: runtime.RuntimeContext) -> dict[str, Any]:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise ConnectionError("transient boom")
        return {"ok": True}

    async def factory():
        return await migrated_db.connect()

    opts = runtime.RuntimeOptions(
        backoff_initial_seconds=0.001,
        backoff_max_seconds=0.01,
        heartbeat_interval_seconds=1.0,
        reclassify_transient_after=99,
    )
    final = await runtime.execute(
        factory,
        task=leased[0],
        agent=agent,
        handler=handler,
        options=opts,
    )
    assert final.status == schema.TaskStatus.COMPLETED
    assert attempts["n"] == 3
    async with migrated_db.acquire() as conn:
        rows = await conn.execute(
            "SELECT attempt_number, outcome FROM task_attempts WHERE task_id = ? ORDER BY attempt_number",
            (task.id,),
        )
        outcomes = [(r["attempt_number"], r["outcome"]) for r in await rows.fetchall()]
        assert outcomes == [(1, "transient"), (2, "transient"), (3, "success")]


@pytest.mark.asyncio
async def test_runtime_policy_error_quarantines_with_redaction(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        task = await queue.enqueue(
            conn,
            campaign_id=campaign_id,
            kind=schema.TaskKind.SEARCH,
            payload={"api_key": "SECRET-VALUE", "user": "alice"},
        )
    async with migrated_db.acquire() as conn:
        leased = await queue.dequeue(conn, owner="worker-1")
    agent = await _register_agent("77777777-7777-4777-8777-777777777777")
    await _seed_agent(migrated_db, agent)

    async def handler(t: schema.Task, ctx: runtime.RuntimeContext) -> dict[str, Any]:
        raise PolicyViolation("out of scope")

    async def factory():
        return await migrated_db.connect()

    final = await runtime.execute(
        factory, task=leased[0], agent=agent, handler=handler
    )
    assert final.status == schema.TaskStatus.QUARANTINED
    async with migrated_db.acquire() as conn:
        cur = await conn.execute(
            "SELECT inputs_redacted, classification FROM quarantine_log WHERE subject_id = ?",
            (task.id,),
        )
        row = await cur.fetchone()
        assert row is not None
        body = json.loads(row["inputs_redacted"])
        # The api_key MUST be redacted in the quarantine log.
        assert body["payload"]["api_key"] == "***REDACTED***"
        assert body["payload"]["user"] == "alice"
        assert row["classification"] == "policy"


@pytest.mark.asyncio
async def test_runtime_model_quality_error_classified(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        await queue.enqueue(
            conn, campaign_id=campaign_id, kind=schema.TaskKind.SEARCH
        )
    async with migrated_db.acquire() as conn:
        leased = await queue.dequeue(conn, owner="worker-1")
    agent = await _register_agent("88888888-8888-4888-8888-888888888888")
    await _seed_agent(migrated_db, agent)

    async def handler(t: schema.Task, ctx: runtime.RuntimeContext) -> dict[str, Any]:
        return {"not_n": "wrong"}

    async def factory():
        return await migrated_db.connect()

    final = await runtime.execute(
        factory, task=leased[0], agent=agent, handler=handler, output_schema=_Out
    )
    assert final.status == schema.TaskStatus.QUARANTINED
    assert "model_quality" in (final.error or "")


@pytest.mark.asyncio
async def test_runtime_kill_switch_blocks_network(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        await queue.enqueue(
            conn, campaign_id=campaign_id, kind=schema.TaskKind.SEARCH
        )
    async with migrated_db.acquire() as conn:
        leased = await queue.dequeue(conn, owner="worker-1")
    agent = await _register_agent("99999999-9999-4999-8999-999999999999")
    await _seed_agent(migrated_db, agent)

    async def factory():
        return await migrated_db.connect()

    async with migrated_db.acquire() as conn:
        ks = await killswitch.activate(conn, reason="test", activated_by="t")

    async def handler(t: schema.Task, ctx: runtime.RuntimeContext) -> dict[str, Any]:
        ctx.charge_network()  # should raise PolicyViolation
        return {}

    final = await runtime.execute(
        factory, task=leased[0], agent=agent, handler=handler, kill_switch=ks
    )
    assert final.status == schema.TaskStatus.QUARANTINED
    assert "policy" in (final.error or "")


@pytest.mark.asyncio
async def test_budget_exceeded_is_permanent(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        await queue.enqueue(conn, campaign_id=campaign_id, kind=schema.TaskKind.SEARCH)
    async with migrated_db.acquire() as conn:
        leased = await queue.dequeue(conn, owner="worker-1")
    agent = schema.Agent(
        id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        schema_version=schema.SCHEMA_VERSION,
        parent_id=None,
        role=schema.AgentRole.SEARCH,
        status=schema.AgentStatus.QUEUED,
        budget=schema.AgentBudgets(max_tokens=1, max_time_seconds=1, max_tool_calls=0, max_network_requests=0),
        created_at=_now(),
        updated_at=_now(),
    )
    await _seed_agent(migrated_db, agent)

    async def factory():
        return await migrated_db.connect()

    async def handler(t: schema.Task, ctx: runtime.RuntimeContext) -> dict[str, Any]:
        ctx.charge_tokens(1000)
        return {}

    final = await runtime.execute(
        factory, task=leased[0], agent=agent, handler=handler
    )
    assert final.status == schema.TaskStatus.QUARANTINED
    assert "permanent" in (final.error or "")
