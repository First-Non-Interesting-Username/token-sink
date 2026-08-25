"""Agent runtime (spec §6).

The runtime executes a :class:`mavr.schemas.entities.Task` against a
pluggable agent handler. It:

* holds the task lease (heartbeating in the background),
* enforces per-agent token/time/tool/request budgets,
* validates structured outputs against a pydantic schema,
* classifies failures (transient / permanent / policy / model-quality),
* retries transient failures with exponential backoff + jitter,
* sends permanent / policy failures to the quarantine log with the
  original inputs preserved and secrets redacted.

This is the Phase 3 runtime. It is provider-agnostic and runs entirely
locally; the actual LLM call lives behind the
:class:`AgentHandler` protocol and is supplied by Phase 4.
"""
from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import uuid4

import aiosqlite
from pydantic import BaseModel, ValidationError

from mavr.agents import identity as identity_mod
from mavr.observability.logging import get_logger
from mavr.orchestrator import audit, queue
from mavr.orchestrator.failures import (
    BudgetExceeded,
    FailureClass,
    PolicyViolation,
    classify,
)
from mavr.orchestrator.killswitch import KillSwitchState, is_network_action_allowed
from mavr.orchestrator.redaction import redact
from mavr.schemas import entities as schema

log = get_logger(__name__)


# ---- handler protocol -----------------------------------------------------


class AgentHandler(Protocol):
    """Pluggable agent handler.

    A handler implements the unit of work for a task. The runtime
    passes the :class:`mavr.schemas.entities.Task` and the
    :class:`RuntimeContext`; the handler returns a structured result
    (already validated against ``output_schema`` if provided).
    """

    async def __call__(
        self,
        task: schema.Task,
        ctx: RuntimeContext,
    ) -> dict[str, Any]:
        ...


# ---- runtime context ------------------------------------------------------


@dataclass
class RuntimeContext:
    """Mutable context passed to a handler.

    Tracks the budget counters and exposes helpers for charging tokens
    and tool / network usage. The runtime updates the corresponding
    agent row in the DB on every checkpoint.
    """

    agent: schema.Agent
    task: schema.Task
    db: aiosqlite.Connection
    kill_switch: KillSwitchState
    started_at: float = field(default_factory=time.monotonic)
    tokens_used: int = 0
    tool_calls: int = 0
    network_requests: int = 0
    checkpoints: int = 0

    def charge_tokens(self, n: int) -> None:
        if n < 0:
            raise ValueError("token charge must be >= 0")
        self.tokens_used += n
        if self.tokens_used > self.agent.budget.max_tokens:
            raise BudgetExceeded("tokens", self.tokens_used, self.agent.budget.max_tokens)

    def charge_tool_call(self) -> None:
        self.tool_calls += 1
        if self.tool_calls > self.agent.budget.max_tool_calls:
            raise BudgetExceeded("tool_calls", self.tool_calls, self.agent.budget.max_tool_calls)

    def charge_network(self) -> None:
        if not is_network_action_allowed(self.kill_switch):
            raise PolicyViolation(
                f"network action refused: {self.kill_switch.reason or 'kill switch active'}"
            )
        self.network_requests += 1
        if self.network_requests > self.agent.budget.max_network_requests:
            raise BudgetExceeded(
                "network_requests", self.network_requests, self.agent.budget.max_network_requests
            )

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.started_at

    def check_time_budget(self) -> None:
        if int(self.elapsed_seconds) > self.agent.budget.max_time_seconds:
            raise BudgetExceeded(
                "time_seconds", int(self.elapsed_seconds), self.agent.budget.max_time_seconds
            )


# ---- output validation ----------------------------------------------------


def validate_output(payload: dict[str, Any], schema_model: type[BaseModel]) -> BaseModel:
    try:
        return schema_model.model_validate(payload)
    except ValidationError as exc:
        from mavr.orchestrator.failures import ModelQualityError

        raise ModelQualityError(f"output validation failed: {exc}") from exc


# ---- attempt recording -----------------------------------------------------


def _now() -> datetime:
    return datetime.now(UTC)


async def _record_attempt_start(
    conn: aiosqlite.Connection,
    *,
    task_id: str,
    agent_id: str,
    attempt_number: int,
) -> str:
    attempt_id = str(uuid4())
    now_iso = _now().isoformat()
    await conn.execute(
        "INSERT INTO task_attempts("
        "id, task_id, attempt_number, agent_id, started_at, outcome"
        ") VALUES (?, ?, ?, ?, ?, ?)",
        (attempt_id, task_id, attempt_number, agent_id, now_iso, "running"),
    )
    return attempt_id


async def _record_attempt_end(
    conn: aiosqlite.Connection,
    *,
    attempt_id: str,
    outcome: str,
    error_class: str | None = None,
    error_message: str | None = None,
    tokens_used: int = 0,
    tool_calls: int = 0,
    network_requests: int = 0,
    wall_time_ms: int = 0,
) -> None:
    now_iso = _now().isoformat()
    await conn.execute(
        "UPDATE task_attempts SET finished_at = ?, outcome = ?, error_class = ?, "
        "error_message = ?, tokens_used = ?, tool_calls = ?, network_requests = ?, "
        "wall_time_ms = ? WHERE id = ?",
        (
            now_iso,
            outcome,
            error_class,
            error_message,
            tokens_used,
            tool_calls,
            network_requests,
            wall_time_ms,
            attempt_id,
        ),
    )


# ---- quarantine log -------------------------------------------------------


async def _quarantine(
    conn: aiosqlite.Connection,
    *,
    task: schema.Task,
    classification: str,
    reason: str,
    inputs: dict[str, Any],
) -> None:
    redacted_inputs = redact(inputs)
    await conn.execute(
        "INSERT INTO quarantine_log("
        "id, subject_kind, subject_id, campaign_id, classification, reason, inputs_redacted, created_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            str(uuid4()),
            "task",
            task.id,
            task.campaign_id,
            classification,
            reason,
            json.dumps(redacted_inputs, ensure_ascii=False),
            _now().isoformat(),
        ),
    )
    await queue.quarantine(
        conn, task_id=task.id, reason=reason, classification=classification
    )
    await audit.record(
        conn,
        actor_id=None,
        actor_kind=schema.ActorKind.SYSTEM,
        category=schema.AuditCategory.ERROR,
        subject_kind="task",
        subject_id=task.id,
        prior_state=task.status.value,
        new_state=schema.TaskStatus.QUARANTINED.value,
        reason=f"quarantined: {classification} — {reason}",
        metadata={"classification": classification},
    )


# ---- main entry -----------------------------------------------------------


@dataclass(frozen=True)
class RuntimeOptions:
    backoff_initial_seconds: float = 1.0
    backoff_max_seconds: float = 60.0
    backoff_multiplier: float = 2.0
    backoff_jitter: float = 0.25
    heartbeat_interval_seconds: float = 15.0
    reclassify_transient_after: int = 3  # after N attempts, transient -> permanent


async def execute(
    db_path_factory: Callable[[], Awaitable[aiosqlite.Connection]],
    *,
    task: schema.Task,
    agent: schema.Agent,
    handler: AgentHandler,
    options: RuntimeOptions | None = None,
    kill_switch: KillSwitchState | None = None,
    output_schema: type[BaseModel] | None = None,
) -> schema.Task:
    """Run a single task with retries.

    The ``db_path_factory`` is called for each attempt so the runtime
    can use short-lived connections. (Tests can pass a coroutine that
    returns the same fixture connection.)
    """
    from mavr.orchestrator.backoff import BackoffPolicy

    opts = options or RuntimeOptions()
    backoff = BackoffPolicy(
        initial_seconds=opts.backoff_initial_seconds,
        max_seconds=opts.backoff_max_seconds,
        multiplier=opts.backoff_multiplier,
        jitter=opts.backoff_jitter,
    )
    attempt = 0
    last_error: str | None = None
    while True:
        attempt += 1
        conn = await db_path_factory()
        try:
            ks = kill_switch or await _fetch_kill_switch(conn)
            ctx = RuntimeContext(agent=agent, task=task, db=conn, kill_switch=ks)
            # Lease + start.
            assert task.lease_owner, "execute() requires a leased task"
            await queue.heartbeat(
                conn,
                task_id=task.id,
                lease_owner=task.lease_owner,
                lease_policy=queue.LeasePolicy(
                    heartbeat_interval_seconds=opts.heartbeat_interval_seconds
                ),
            )
            started = await queue.start(conn, task_id=task.id, lease_owner=task.lease_owner)
            if not started:
                # Lease lost between dequeue and start; abort and let the
                # orchestrator redrive.
                raise queue.QueueError("lease lost before start")
            await audit.record(
                conn,
                actor_id=agent.id,
                actor_kind=schema.ActorKind.AGENT,
                category=schema.AuditCategory.STATE_TRANSITION,
                subject_kind="task",
                subject_id=task.id,
                prior_state=schema.TaskStatus.LEASED.value,
                new_state=schema.TaskStatus.RUNNING.value,
                reason=f"attempt {attempt}",
                metadata={"agent_id": agent.id, "attempt": attempt},
            )
            attempt_id = await _record_attempt_start(
                conn, task_id=task.id, agent_id=agent.id, attempt_number=attempt
            )
            wall_start = time.monotonic()
            try:
                result = await handler(task, ctx)
                if output_schema is not None:
                    validated = validate_output(result, output_schema)
                    result = validated.model_dump(mode="json")
                wall_ms = int((time.monotonic() - wall_start) * 1000)
                await _record_attempt_end(
                    conn,
                    attempt_id=attempt_id,
                    outcome="success",
                    tokens_used=ctx.tokens_used,
                    tool_calls=ctx.tool_calls,
                    network_requests=ctx.network_requests,
                    wall_time_ms=wall_ms,
                )
                await _checkpoint_agent(conn, agent.id, ctx)
                await queue.complete(
                    conn, task_id=task.id, lease_owner=task.lease_owner, result=result
                )
                await audit.record(
                    conn,
                    actor_id=agent.id,
                    actor_kind=schema.ActorKind.AGENT,
                    category=schema.AuditCategory.STATE_TRANSITION,
                    subject_kind="task",
                    subject_id=task.id,
                    prior_state=schema.TaskStatus.RUNNING.value,
                    new_state=schema.TaskStatus.COMPLETED.value,
                    reason="handler returned valid result",
                    metadata={"attempt": attempt, "wall_ms": wall_ms},
                )
                task.status = schema.TaskStatus.COMPLETED
                task.result = result
                task.attempt = attempt
                task.finished_at = _now()
                return task
            except BaseException as exc:  # noqa: BLE001
                wall_ms = int((time.monotonic() - wall_start) * 1000)
                cls = classify(exc)
                if cls == FailureClass.CANCELLED:
                    await _record_attempt_end(
                        conn,
                        attempt_id=attempt_id,
                        outcome="cancelled",
                        tokens_used=ctx.tokens_used,
                        tool_calls=ctx.tool_calls,
                        network_requests=ctx.network_requests,
                        wall_time_ms=wall_ms,
                    )
                    await queue.fail(
                        conn,
                        task_id=task.id,
                        lease_owner=task.lease_owner,
                        error=str(exc),
                        classification="cancelled",
                    )
                    raise
                # Transient retries that have burnt through their budget
                # get reclassified as permanent to avoid livelock.
                if cls == FailureClass.TRANSIENT and attempt > opts.reclassify_transient_after:
                    cls = FailureClass.PERMANENT
                await _record_attempt_end(
                    conn,
                    attempt_id=attempt_id,
                    outcome=cls.value,
                    error_class=cls.value,
                    error_message=str(exc),
                    tokens_used=ctx.tokens_used,
                    tool_calls=ctx.tool_calls,
                    network_requests=ctx.network_requests,
                    wall_time_ms=wall_ms,
                )
                await _checkpoint_agent(conn, agent.id, ctx)
                last_error = f"{cls.value}: {exc}"
                if cls == FailureClass.TRANSIENT and attempt < task.max_attempts:
                    await queue.fail(
                        conn,
                        task_id=task.id,
                        lease_owner=task.lease_owner,
                        error=last_error,
                        classification=cls.value,
                    )
                    await queue.requeue(
                        conn, task_id=task.id, classification=cls.value
                    )
                    await audit.record(
                        conn,
                        actor_id=agent.id,
                        actor_kind=schema.ActorKind.AGENT,
                        category=schema.AuditCategory.STATE_TRANSITION,
                        subject_kind="task",
                        subject_id=task.id,
                        prior_state=schema.TaskStatus.RUNNING.value,
                        new_state=schema.TaskStatus.PENDING.value,
                        reason=f"transient retry {attempt}/{task.max_attempts}: {exc}",
                        metadata={"classification": cls.value, "attempt": attempt},
                    )
                    task.attempt = attempt
                    task.error = last_error
                    delay = backoff.delay_for(attempt)
                    log.warning(
                        "task_retry",
                        task_id=task.id,
                        attempt=attempt,
                        delay_seconds=delay,
                        error=last_error,
                    )
                    await asyncio.sleep(delay)
                    # Re-lease for the next attempt.
                    renewed = await _reacquire_lease(conn, task, agent.id)
                    if renewed is None:
                        raise queue.QueueError("could not re-lease after transient failure") from exc
                    task = renewed
                    continue
                # Non-retryable: quarantine with redacted inputs.
                await _quarantine(
                    conn,
                    task=task,
                    classification=cls.value,
                    reason=str(exc),
                    inputs={"payload": task.payload, "error": str(exc)},
                )
                # Release the lease so the row no longer shows as leased.
                await queue.fail(
                    conn,
                    task_id=task.id,
                    lease_owner=task.lease_owner,
                    error=last_error,
                    classification=cls.value,
                    release_lease=True,
                )
                task.status = schema.TaskStatus.QUARANTINED
                task.error = last_error
                task.attempt = attempt
                task.finished_at = _now()
                log.error(
                    "task_quarantined",
                    task_id=task.id,
                    classification=cls.value,
                    reason=str(exc),
                )
                return task
        finally:
            await conn.close()


async def _checkpoint_agent(
    conn: aiosqlite.Connection, agent_id: str, ctx: RuntimeContext
) -> None:
    ctx.checkpoints += 1
    await conn.execute(
        "UPDATE agents SET tokens_used = ?, time_used_seconds = ?, tool_calls_used = ?, "
        "network_requests_used = ?, updated_at = ? WHERE id = ?",
        (
            ctx.tokens_used,
            int(ctx.elapsed_seconds),
            ctx.tool_calls,
            ctx.network_requests,
            _now().isoformat(),
            agent_id,
        ),
    )


async def _fetch_kill_switch(conn: aiosqlite.Connection) -> KillSwitchState:
    from mavr.orchestrator import killswitch

    return await killswitch.get(conn)


async def _reacquire_lease(
    conn: aiosqlite.Connection, task: schema.Task, new_owner: str
) -> schema.Task | None:
    """After a transient failure, re-lease the task for the next attempt."""
    renewed = await queue.dequeue(conn, owner=new_owner, kinds=[task.kind], limit=1)
    for cand in renewed:
        if cand.id == task.id:
            return cand
    return None


# ---- subagent spawning ----------------------------------------------------


@dataclass(frozen=True)
class SubagentRequest:
    objective: str
    role: schema.AgentRole = schema.AgentRole.SUBAGENT
    output_schema: type[BaseModel] | None = None
    allowed_tools: tuple[str, ...] = ()
    scope: dict[str, Any] = field(default_factory=dict)
    budget: schema.AgentBudgets | None = None
    timeout_seconds: int = 600
    active_testing_allowed: bool = False
    completion_criteria: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


async def spawn_subagent(
    conn: aiosqlite.Connection,
    *,
    parent: schema.Agent,
    request: SubagentRequest,
    task: schema.Task | None = None,
) -> schema.Agent:
    """Mint a child agent and link it to ``parent``.

    The child is queued (not yet leased) and an audit event records the
    parent linkage.
    """
    child = identity_mod.spawn_subagent(
        request.role,
        parent,
        campaign_id=parent.campaign_id,
        budget=request.budget or parent.budget,
        metadata={
            "objective": request.objective,
            "allowed_tools": list(request.allowed_tools),
            "scope": request.scope,
            "active_testing_allowed": request.active_testing_allowed,
            "completion_criteria": request.completion_criteria,
            "timeout_seconds": request.timeout_seconds,
            "parent_objective": parent.metadata.get("objective", ""),
        },
    )
    from mavr.orchestrator import agents as agents_mod

    await agents_mod.insert(conn, child)
    if task is not None:
        # Mark the parent task's metadata with the new subagent id.
        await conn.execute(
            "UPDATE tasks SET result = COALESCE(result, '{}') WHERE id = ?",
            (task.id,),
        )
    return child
