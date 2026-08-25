"""Tests for the kill switch, redaction, and the high-level orchestrator."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from mavr.orchestrator import killswitch, runtime
from mavr.orchestrator.redaction import redact
from mavr.schemas import entities as schema


def _now() -> datetime:
    return datetime.now(UTC)


def test_redaction_masks_secrets_recursively() -> None:
    payload = {
        "user": "alice",
        "api_key": "k-secret",
        "nested": {"Authorization": "Bearer xyz", "ok": 1},
        "list": [{"password": "p"}, "plain"],
    }
    out = redact(payload)
    assert out["user"] == "alice"
    assert out["api_key"] == "***REDACTED***"
    assert out["nested"]["Authorization"] == "***REDACTED***"
    assert out["nested"]["ok"] == 1
    assert out["list"][0]["password"] == "***REDACTED***"
    assert out["list"][1] == "plain"


@pytest.mark.asyncio
async def test_kill_switch_round_trip(migrated_db) -> None:
    async with migrated_db.acquire() as conn:
        s = await killswitch.get(conn)
        assert not s.active
        await killswitch.activate(conn, reason="demo", activated_by="tester")
        s2 = await killswitch.get(conn)
        assert s2.active
        banner = killswitch.banner(s2)
        assert "KILL SWITCH ACTIVE" in banner
        assert killswitch.is_network_action_allowed(s2) is False
        await killswitch.deactivate(conn, deactivated_by="tester")
        s3 = await killswitch.get(conn)
        assert not s3.active
        assert killswitch.is_network_action_allowed(s3) is True


@pytest.mark.asyncio
async def test_orchestrator_cancel_propagates(orchestrator, campaign_id) -> None:
    parent = await orchestrator.register_agent(
        role=schema.AgentRole.IMPACT, campaign_id=campaign_id
    )
    child = await orchestrator.spawn_subagent(
        parent=parent,
        request=runtime.SubagentRequest(objective="helper"),
    )
    assert child.parent_id == parent.id
    # cancel subtree
    n = await orchestrator.cancel_agent(parent.id, reason="halt")
    assert n == 2


@pytest.mark.asyncio
async def test_orchestrator_enqueue_and_cancel_task(orchestrator, campaign_id) -> None:
    t = await orchestrator.enqueue_task(
        campaign_id=campaign_id, kind=schema.TaskKind.SEARCH, payload={"q": "x"}
    )
    n = await orchestrator.cancel_task(t.id, reason="manual")
    assert n == 1
    t2 = await orchestrator.enqueue_task(
        campaign_id=campaign_id, kind=schema.TaskKind.IMPACT, depends_on=[t.id]
    )
    # the parent is cancelled; the dependent should still be cancellable
    n2 = await orchestrator.cancel_task(t2.id, reason="manual")
    assert n2 == 1


@pytest.mark.asyncio
async def test_orchestrator_kill_switch_banner(orchestrator) -> None:
    await orchestrator.activate_kill_switch(reason="test", activated_by="op")
    s = await orchestrator.kill_switch_state()
    assert s.active
    assert "KILL SWITCH ACTIVE" in killswitch.banner(s)
    await orchestrator.deactivate_kill_switch(deactivated_by="op")
    s2 = await orchestrator.kill_switch_state()
    assert not s2.active


@pytest.mark.asyncio
async def test_orchestrator_dispatch_runs_handler(orchestrator, campaign_id) -> None:
    task = await orchestrator.enqueue_task(
        campaign_id=campaign_id, kind=schema.TaskKind.SEARCH
    )
    agent = await orchestrator.register_agent(
        role=schema.AgentRole.SEARCH, campaign_id=campaign_id
    )

    async def handler(t: schema.Task, ctx: runtime.RuntimeContext) -> dict[str, Any]:
        return {"echo": t.payload, "tokens": ctx.tokens_used}

    results = await orchestrator.dispatch(
        owner="worker-1", handler=handler, agent=agent, kinds=[schema.TaskKind.SEARCH]
    )
    assert len(results) == 1
    assert results[0].status == schema.TaskStatus.COMPLETED
    assert results[0].result == {"echo": {}, "tokens": 0}
    # task in DB marked completed
    async with orchestrator._conn() as conn:  # noqa: SLF001
        from mavr.orchestrator import queue as q

        current = await q.get(conn, task.id)
        assert current.status == schema.TaskStatus.COMPLETED
