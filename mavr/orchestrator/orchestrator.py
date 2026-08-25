"""High-level orchestrator (spec §6, §12).

Glues together the task queue, agent runtime, audit log, and finding
state machine. The orchestrator is responsible for:

* accepting work (tasks, subagent requests, finding transitions),
* assigning tasks to agents,
* propagating cancellation to children,
* persisting every transition in the audit log,
* honouring the global kill switch.

This Phase 3 implementation is fully local; there are no LLM calls or
network operations. Real provider / router integration lands in
Phase 4.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import aiosqlite

from mavr.agents import identity as identity_mod
from mavr.observability.logging import get_logger
from mavr.orchestrator import agents as agents_mod
from mavr.orchestrator import audit, queue, runtime
from mavr.orchestrator import killswitch as killswitch_mod
from mavr.schemas import entities as schema

log = get_logger(__name__)


# Re-export for convenience

# ---- core orchestrator -----------------------------------------------------


@dataclass
class Orchestrator:
    """Local, in-process orchestrator.

    The orchestrator owns the database connection factory and the
    background lease sweeper. Tasks are dispatched by ``dispatch`` and
    can be cancelled via :meth:`cancel_task`.
    """

    db_factory: Callable[[], Awaitable[aiosqlite.Connection]]
    lease_policy: queue.LeasePolicy = field(default_factory=queue.LeasePolicy)
    runtime_options: runtime.RuntimeOptions = field(default_factory=runtime.RuntimeOptions)
    sweeper_task: asyncio.Task[None] | None = None
    _stop_event: asyncio.Event = field(default_factory=asyncio.Event)

    # ---- lifecycle -------------------------------------------------------

    async def start(self) -> None:
        self._stop_event.clear()
        if self.sweeper_task is None:
            self.sweeper_task = asyncio.create_task(
                self._sweeper_loop(), name="orchestrator-sweeper"
            )
        log.info("orchestrator_started", lease_ttl=self.lease_policy.lease_ttl_seconds)

    async def stop(self) -> None:
        self._stop_event.set()
        if self.sweeper_task is not None:
            try:
                await asyncio.wait_for(self.sweeper_task, timeout=2.0)
            except TimeoutError:
                self.sweeper_task.cancel()
            self.sweeper_task = None
        log.info("orchestrator_stopped")

    async def _sweeper_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                conn = await self.db_factory()
                try:
                    result = await queue.sweep_stale_leases(conn, policy=self.lease_policy)
                    if result.reclaimed or result.dead_lettered:
                        log.info(
                            "sweep",
                            reclaimed=result.reclaimed,
                            dead_lettered=result.dead_lettered,
                        )
                finally:
                    await conn.close()
            except Exception as exc:  # noqa: BLE001
                log.error("sweeper_error", error=str(exc))
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self.lease_policy.sweeper_interval_seconds,
                )
            except TimeoutError:
                pass

    # ---- helpers ---------------------------------------------------------

    @asynccontextmanager
    async def _conn(self):
        conn = await self.db_factory()
        try:
            yield conn
        finally:
            await conn.close()

    async def kill_switch_state(self) -> killswitch_mod.KillSwitchState:
        async with self._conn() as conn:
            return await killswitch_mod.get(conn)

    async def activate_kill_switch(self, *, reason: str, activated_by: str) -> None:
        async with self._conn() as conn:
            await killswitch_mod.activate(conn, reason=reason, activated_by=activated_by)
            await audit.record(
                conn,
                actor_id=None,
                actor_kind=schema.ActorKind.HUMAN,
                category=schema.AuditCategory.POLICY_DECISION,
                subject_kind="system",
                subject_id=None,
                prior_state="inactive",
                new_state="active",
                reason=f"{activated_by}: {reason}",
            )

    async def deactivate_kill_switch(self, *, deactivated_by: str) -> None:
        async with self._conn() as conn:
            await killswitch_mod.deactivate(conn, deactivated_by=deactivated_by)
            await audit.record(
                conn,
                actor_id=None,
                actor_kind=schema.ActorKind.HUMAN,
                category=schema.AuditCategory.POLICY_DECISION,
                subject_kind="system",
                subject_id=None,
                prior_state="active",
                new_state="inactive",
                reason=f"{deactivated_by}: kill switch cleared",
            )

    # ---- task lifecycle --------------------------------------------------

    async def enqueue_task(
        self,
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
        async with self._conn() as conn:
            return await queue.enqueue(
                conn,
                campaign_id=campaign_id,
                kind=kind,
                payload=payload,
                parent_task_id=parent_task_id,
                priority=priority,
                idempotency_key=idempotency_key,
                max_attempts=max_attempts,
                depends_on=depends_on,
            )

    async def cancel_task(self, task_id: str, *, reason: str = "cancelled") -> int:
        """Cancel a task and propagate to its children. Returns the count cancelled."""
        async with self._conn() as conn:
            task = await queue.get(conn, task_id)
            if task is None:
                return 0
            cancelled = 0
            stack: list[str] = [task_id]
            cancelled_tasks: list[str] = []
            while stack:
                current = stack.pop()
                dependents = await queue.dependents_of(conn, current)
                for d in dependents:
                    stack.append(d.id)
                ok = await queue.cancel(conn, task_id=current, reason=reason)
                if ok:
                    cancelled_tasks.append(current)
                    cancelled += 1
            for tid in cancelled_tasks:
                await audit.record(
                    conn,
                    actor_id=None,
                    actor_kind=schema.ActorKind.SYSTEM,
                    category=schema.AuditCategory.STATE_TRANSITION,
                    subject_kind="task",
                    subject_id=tid,
                    prior_state=None,
                    new_state=schema.TaskStatus.CANCELLED.value,
                    reason=reason,
                    metadata={"propagated": True, "from": task_id},
                )
            return cancelled

    # ---- agent lifecycle -------------------------------------------------

    async def register_agent(
        self,
        *,
        role: schema.AgentRole,
        campaign_id: str | None = None,
        parent_id: str | None = None,
        budget: schema.AgentBudgets | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> schema.Agent:
        agent = identity_mod.mint_agent(
            role,
            campaign_id=campaign_id,
            budget=budget,
            parent_id=parent_id,
            metadata=metadata,
        )
        async with self._conn() as conn:
            await agents_mod.insert(conn, agent)
        return agent

    async def transition_agent(
        self,
        *,
        agent_id: str,
        new_status: schema.AgentStatus,
        actor_id: str | None = None,
        reason: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> schema.Agent:
        async with self._conn() as conn:
            return await agents_mod.transition(
                conn,
                agent_id=agent_id,
                new_status=new_status,
                actor_id=actor_id,
                reason=reason,
                metadata=metadata,
            )

    async def cancel_agent(self, agent_id: str, *, reason: str) -> int:
        async with self._conn() as conn:
            return await agents_mod.cancel_subtree(
                conn, agent_id=agent_id, actor_id=None, reason=reason
            )

    # ---- subagent spawning ----------------------------------------------

    async def spawn_subagent(
        self,
        *,
        parent: schema.Agent,
        request: runtime.SubagentRequest,
    ) -> tuple[schema.Agent, schema.Task]:
        async with self._conn() as conn:
            return await runtime.spawn_subagent(conn, parent=parent, request=request)

    # ---- dispatch --------------------------------------------------------

    async def dispatch(
        self,
        *,
        owner: str,
        handler: runtime.AgentHandler,
        agent: schema.Agent,
        output_schema: type | None = None,
        kinds: list[schema.TaskKind] | None = None,
        limit: int = 1,
    ) -> list[schema.Task]:
        """Lease up to ``limit`` tasks and run them through ``handler``."""
        ks = await self.kill_switch_state()
        async with self._conn() as conn:
            leased = await queue.dequeue(
                conn, owner=owner, lease_policy=self.lease_policy, kinds=kinds, limit=limit
            )
        results: list[schema.Task] = []
        for task in leased:
            final = await runtime.execute(
                self.db_factory,
                task=task,
                agent=agent,
                handler=handler,
                options=self.runtime_options,
                kill_switch=ks,
                output_schema=output_schema,
            )
            results.append(final)
        return results
