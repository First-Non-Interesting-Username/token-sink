"""Tests for the audit log + state-machine guards."""
from __future__ import annotations

import pytest

from mavr.orchestrator import agents as agents_mod
from mavr.orchestrator import audit
from mavr.schemas import entities as schema


@pytest.mark.asyncio
async def test_audit_record_is_idempotent(migrated_db) -> None:
    async with migrated_db.acquire() as conn:
        eid = "evt-dup"
        actor = "11111111-1111-4111-8111-111111111111"
        subj = "11111111-1111-4111-8111-111111111112"
        first = await audit.record(
            conn,
            actor_id=actor,
            actor_kind=schema.ActorKind.AGENT,
            category=schema.AuditCategory.STATE_TRANSITION,
            subject_kind="agent",
            subject_id=subj,
            prior_state="created",
            new_state="queued",
            reason="enqueue",
            event_id=eid,
        )
        second = await audit.record(
            conn,
            actor_id=actor,
            actor_kind=schema.ActorKind.AGENT,
            category=schema.AuditCategory.STATE_TRANSITION,
            subject_kind="agent",
            subject_id=subj,
            prior_state="created",
            new_state="queued",
            reason="enqueue",
            event_id=eid,
        )
        assert first.id == second.id
        count = await audit.count(
            conn, category=schema.AuditCategory.STATE_TRANSITION
        )
        # at least 1 — could be more from other tests sharing the DB
        assert count >= 1


@pytest.mark.asyncio
async def test_agent_transition_legal(migrated_db) -> None:
    agent = schema.Agent(
        id="11111111-1111-4111-8111-111111111111",
        schema_version=schema.SCHEMA_VERSION,
        parent_id=None,
        role=schema.AgentRole.SEARCH,
        status=schema.AgentStatus.CREATED,
        created_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        updated_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
    )
    async with migrated_db.acquire() as conn:
        await agents_mod.insert(conn, agent)
        moved = await agents_mod.transition(
            conn,
            agent_id=agent.id,
            new_status=schema.AgentStatus.QUEUED,
            actor_id=None,
            reason="queued",
        )
        assert moved.status == schema.AgentStatus.QUEUED
        moved2 = await agents_mod.transition(
            conn,
            agent_id=agent.id,
            new_status=schema.AgentStatus.ASSIGNED,
            actor_id=None,
        )
        assert moved2.status == schema.AgentStatus.ASSIGNED


@pytest.mark.asyncio
async def test_agent_transition_illegal(migrated_db) -> None:
    agent = schema.Agent(
        id="22222222-2222-4222-8222-222222222222",
        schema_version=schema.SCHEMA_VERSION,
        parent_id=None,
        role=schema.AgentRole.SEARCH,
        status=schema.AgentStatus.CREATED,
        created_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        updated_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
    )
    async with migrated_db.acquire() as conn:
        await agents_mod.insert(conn, agent)
        with pytest.raises(agents_mod.AgentStateError):
            await agents_mod.transition(
                conn,
                agent_id=agent.id,
                new_status=schema.AgentStatus.RUNNING,
                actor_id=None,
            )


@pytest.mark.asyncio
async def test_agent_cancel_subtree(migrated_db) -> None:
    parent = schema.Agent(
        id="33333333-3333-4333-8333-333333333333",
        schema_version=schema.SCHEMA_VERSION,
        parent_id=None,
        role=schema.AgentRole.IMPACT,
        status=schema.AgentStatus.RUNNING,
        created_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        updated_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
    )
    child = schema.Agent(
        id="44444444-4444-4444-8444-444444444444",
        schema_version=schema.SCHEMA_VERSION,
        parent_id=parent.id,
        role=schema.AgentRole.SUBAGENT,
        status=schema.AgentStatus.QUEUED,
        created_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        updated_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
    )
    async with migrated_db.acquire() as conn:
        await agents_mod.insert(conn, parent)
        await agents_mod.insert(conn, child)
        n = await agents_mod.cancel_subtree(
            conn, agent_id=parent.id, actor_id=None, reason="shutdown"
        )
        assert n == 2
        p = await agents_mod.get(conn, parent.id)
        c = await agents_mod.get(conn, child.id)
        assert p.status == schema.AgentStatus.CANCELLED
        assert c.status == schema.AgentStatus.CANCELLED
