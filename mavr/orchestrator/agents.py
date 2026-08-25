"""Agent state machine (spec §6).

States:
    created -> queued -> assigned -> running -> waiting -> completed
    with side states: failed, cancelled, blocked.

Transitions are persisted on the ``agents`` row and an audit event is
emitted for every change. The legal transitions are declared in
:data:`ALLOWED_TRANSITIONS`; an attempt to skip a state raises
:class:`AgentStateError`.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import aiosqlite

from mavr.observability.logging import get_logger
from mavr.orchestrator import audit
from mavr.schemas import entities as schema

log = get_logger(__name__)


class AgentStateError(RuntimeError):
    """Raised on illegal agent state transitions."""


ALLOWED_TRANSITIONS: dict[schema.AgentStatus, set[schema.AgentStatus]] = {
    schema.AgentStatus.CREATED: {
        schema.AgentStatus.QUEUED,
        schema.AgentStatus.CANCELLED,
        schema.AgentStatus.FAILED,
        schema.AgentStatus.BLOCKED,
    },
    schema.AgentStatus.QUEUED: {
        schema.AgentStatus.ASSIGNED,
        schema.AgentStatus.CANCELLED,
        schema.AgentStatus.FAILED,
        schema.AgentStatus.BLOCKED,
    },
    schema.AgentStatus.ASSIGNED: {
        schema.AgentStatus.RUNNING,
        schema.AgentStatus.CANCELLED,
        schema.AgentStatus.FAILED,
        schema.AgentStatus.BLOCKED,
    },
    schema.AgentStatus.RUNNING: {
        schema.AgentStatus.WAITING,
        schema.AgentStatus.COMPLETED,
        schema.AgentStatus.FAILED,
        schema.AgentStatus.CANCELLED,
        schema.AgentStatus.BLOCKED,
    },
    schema.AgentStatus.WAITING: {
        schema.AgentStatus.RUNNING,
        schema.AgentStatus.COMPLETED,
        schema.AgentStatus.CANCELLED,
        schema.AgentStatus.FAILED,
        schema.AgentStatus.BLOCKED,
    },
    schema.AgentStatus.BLOCKED: {
        schema.AgentStatus.QUEUED,
        schema.AgentStatus.ASSIGNED,
        schema.AgentStatus.CANCELLED,
        schema.AgentStatus.FAILED,
    },
    # terminal states have no outgoing transitions
    schema.AgentStatus.COMPLETED: set(),
    schema.AgentStatus.FAILED: set(),
    schema.AgentStatus.CANCELLED: set(),
}


def can_transition(
    prior: schema.AgentStatus, new: schema.AgentStatus
) -> bool:
    return new in ALLOWED_TRANSITIONS.get(prior, set())


def _now() -> datetime:
    return datetime.now(UTC)


def _row_to_agent(row: aiosqlite.Row) -> schema.Agent:
    metadata = json.loads(row["metadata"]) if row["metadata"] else {}
    return schema.Agent(
        id=row["id"],
        schema_version=row["schema_version"],
        parent_id=row["parent_id"],
        role=schema.AgentRole(row["role"]),
        status=schema.AgentStatus(row["status"]),
        campaign_id=row["campaign_id"],
        task_id=row["task_id"],
        budget=schema.AgentBudgets(
            max_tokens=row["budget_tokens"],
            max_time_seconds=row["budget_time_seconds"],
            max_tool_calls=row["budget_tool_calls"],
            max_network_requests=row["budget_network_requests"],
        ),
        tokens_used=row["tokens_used"],
        time_used_seconds=row["time_used_seconds"],
        tool_calls_used=row["tool_calls_used"],
        network_requests_used=row["network_requests_used"],
        metadata=metadata,
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )


async def insert(
    conn: aiosqlite.Connection, agent: schema.Agent
) -> schema.Agent:
    now_iso = _now().isoformat()
    await conn.execute(
        "INSERT INTO agents("
        "id, schema_version, parent_id, role, status, campaign_id, task_id, "
        "created_at, updated_at, budget_tokens, budget_time_seconds, budget_tool_calls, "
        "budget_network_requests, tokens_used, time_used_seconds, tool_calls_used, "
        "network_requests_used, metadata"
        ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            agent.id,
            agent.schema_version,
            agent.parent_id,
            agent.role.value,
            agent.status.value,
            agent.campaign_id,
            agent.task_id,
            now_iso,
            now_iso,
            agent.budget.max_tokens,
            agent.budget.max_time_seconds,
            agent.budget.max_tool_calls,
            agent.budget.max_network_requests,
            agent.tokens_used,
            agent.time_used_seconds,
            agent.tool_calls_used,
            agent.network_requests_used,
            json.dumps(agent.metadata, ensure_ascii=False),
        ),
    )
    await audit.record(
        conn,
        actor_id=agent.parent_id,
        actor_kind=schema.ActorKind.AGENT,
        category=schema.AuditCategory.STATE_TRANSITION,
        subject_kind="agent",
        subject_id=agent.id,
        prior_state=None,
        new_state=agent.status.value,
        reason="agent created",
        metadata={"role": agent.role.value, "campaign_id": agent.campaign_id},
        event_id=f"agent_created_{agent.id}",
    )
    await conn.commit()
    return agent


async def get(conn: aiosqlite.Connection, agent_id: str) -> schema.Agent | None:
    cur = await conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
    row = await cur.fetchone()
    return _row_to_agent(row) if row else None


async def list_children(
    conn: aiosqlite.Connection, parent_id: str
) -> list[schema.Agent]:
    cur = await conn.execute(
        "SELECT * FROM agents WHERE parent_id = ? ORDER BY created_at",
        (parent_id,),
    )
    return [_row_to_agent(r) for r in await cur.fetchall()]


async def transition(
    conn: aiosqlite.Connection,
    *,
    agent_id: str,
    new_status: schema.AgentStatus,
    actor_id: str | None,
    reason: str = "",
    metadata: dict[str, Any] | None = None,
    force: bool = False,
) -> schema.Agent:
    """Move ``agent_id`` to ``new_status``.

    Emits an :class:`AuditEvent` for the transition. If the transition
    is not in :data:`ALLOWED_TRANSITIONS`, raises
    :class:`AgentStateError` unless ``force=True`` (only for system
    recovery paths).
    """
    cur = await conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
    row = await cur.fetchone()
    if row is None:
        raise AgentStateError(f"agent {agent_id} not found")
    agent = _row_to_agent(row)
    if agent.status == new_status:
        return agent
    if not force and not can_transition(agent.status, new_status):
        raise AgentStateError(
            f"illegal transition for agent {agent_id}: "
            f"{agent.status.value} -> {new_status.value}"
        )
    now_iso = _now().isoformat()
    await conn.execute(
        "UPDATE agents SET status = ?, updated_at = ? WHERE id = ?",
        (new_status.value, now_iso, agent_id),
    )
    await audit.record(
        conn,
        actor_id=actor_id,
        actor_kind=schema.ActorKind.AGENT if actor_id else schema.ActorKind.SYSTEM,
        category=schema.AuditCategory.STATE_TRANSITION,
        subject_kind="agent",
        subject_id=agent_id,
        prior_state=agent.status.value,
        new_state=new_status.value,
        reason=reason,
        metadata=metadata or {},
        event_id=f"agent_transition_{agent_id}_{agent.status.value}_to_{new_status.value}",
    )
    await conn.commit()
    log.info(
        "agent_transition",
        agent_id=agent_id,
        prior=agent.status.value,
        new=new_status.value,
        reason=reason,
    )
    agent.status = new_status
    agent.updated_at = _now()
    return agent


async def cancel_subtree(
    conn: aiosqlite.Connection, *, agent_id: str, actor_id: str | None, reason: str
) -> int:
    """Cancel an agent and all non-terminal descendants. Returns count cancelled."""
    cancelled = 0
    stack = [agent_id]
    while stack:
        current = stack.pop()
        for child in await list_children(conn, current):
            stack.append(child.id)
        agent = await get(conn, current)
        if agent is None or agent.status in (
            schema.AgentStatus.COMPLETED,
            schema.AgentStatus.FAILED,
            schema.AgentStatus.CANCELLED,
        ):
            continue
        try:
            await transition(
                conn,
                agent_id=current,
                new_status=schema.AgentStatus.CANCELLED,
                actor_id=actor_id,
                reason=reason,
                force=True,
            )
            cancelled += 1
        except AgentStateError:
            continue
    await conn.commit()
    return cancelled
