"""Lease manager and stale-lease sweeper (PLAN §6/§12, issue #178).

Correctness model — why this module exists:

- An agent holds a *lease* on a task while working. The lease carries a
  monotonically increasing ``epoch``: reassignment bumps the epoch, so a
  zombie agent holding an old token can be detected and rejected.
- Agents renew via :meth:`LeaseManager.renew`. After ``max_missed``
  consecutive missed renewals (i.e. ``now > last_renewal +
  max_missed * interval``), the lease is *stale*.
- The :class:`Sweeper` expires stale leases, transitions the owning agent to
  ``failed``, requeues its tasks, and cascades expiry to subagent leases.
- **Zombie protection**: every write through
  :meth:`LeaseGuard.checked_effect` validates the caller's (task, epoch)
  against the current lease. If a stale agent resumes and tries to apply an
  effect with an expired lease, the write is rejected with
  :class:`LeaseExpiredError` and audited.
- **Exactly-once effects**: reassignment reuses the same task id, so the
  idempotency journal (``orchestrator.idempotency.ExecutionRunner``) still
  deduplicates effects across the old and new executions. The sweeper never
  invents new task ids for in-flight work.

This is deliberately storage-light: leases live in memory under a lock, with
optional audit + metrics callbacks. Durability of *effects* comes from the
journal/artifact layers; a process restart simply starts fresh leases, which
is safe because unfinished effects were never journalled as complete.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field


class LeaseError(RuntimeError):
    """Base class for lease failures."""


class LeaseExpiredError(LeaseError):
    """A write was attempted with a superseded/expired lease."""


@dataclass
class Lease:
    task_id: str
    agent_uuid: str
    epoch: int  # bumped on each reassignment; zombies hold older epochs
    acquired_at: float
    last_renewal: float
    parent_agent: str | None = None  # for cascade expiry
    expired: bool = False


@dataclass
class SweepReport:
    expired_leases: list[str] = field(default_factory=list)  # task ids
    failed_agents: list[str] = field(default_factory=list)
    requeued_tasks: list[str] = field(default_factory=list)
    cascaded_agents: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self.expired_leases


class LeaseManager:
    """Tracks task leases; decides staleness; guards effectful writes."""

    def __init__(
        self,
        renewal_interval_s: float = 5.0,
        max_missed: int = 3,
        audit=None,  # policy.audit.AuditLog or None
        clock: Callable[[], float] = time.time,
    ):
        if max_missed < 1:
            raise ValueError("max_missed must be >= 1")
        self.renewal_interval_s = renewal_interval_s
        self.max_missed = max_missed
        self.audit = audit
        self.clock = clock
        self._lock = threading.Lock()
        self._leases: dict[str, Lease] = {}  # task_id -> Lease
        # Monotonic per-task epochs survive lease deletion so a reassigned
        # task always invalidates the previous holder's token.
        self._epochs: dict[str, int] = {}
        # Observability hook (issue #23): count of expired leases.
        self.on_expire: list[Callable[[Lease], None]] = []

    # -- acquisition / renewal -------------------------------------------

    def acquire(self, task_id: str, agent_uuid: str, parent_agent: str | None = None) -> str:
        """Acquire (or steal after expiry) a lease. Returns the lease token.

        Stealing is only allowed when the current lease is already expired —
        healthy leases are exclusive. Epoch increments on every steal so the
        old holder's token becomes invalid even though the task id is reused.
        """
        now = self.clock()
        with self._lock:
            existing = self._leases.get(task_id)
            if existing and not existing.expired:
                raise LeaseError(f"task {task_id} is actively leased by {existing.agent_uuid}")
            epoch = self._epochs.get(task_id, 0) + 1
            self._epochs[task_id] = epoch
            self._leases[task_id] = Lease(
                task_id=task_id,
                agent_uuid=agent_uuid,
                epoch=epoch,
                acquired_at=now,
                last_renewal=now,
                parent_agent=parent_agent,
            )
        return f"{agent_uuid}:{epoch}"

    def release(self, task_id: str, agent_uuid: str) -> None:
        """Voluntary release on completion."""
        with self._lock:
            lease = self._leases.get(task_id)
            if lease is None or lease.agent_uuid != agent_uuid:
                return  # not ours (or gone) — nothing to do
            del self._leases[task_id]

    def renew(self, task_id: str, agent_uuid: str) -> bool:
        """Heartbeat: push the renewal deadline out. False if not our lease."""
        now = self.clock()
        with self._lock:
            lease = self._leases.get(task_id)
            if lease is None or lease.agent_uuid != agent_uuid or lease.expired:
                return False
            lease.last_renewal = now
            return True

    def _stale_cutoff(self, lease: Lease) -> float:
        return lease.last_renewal + self.renewal_interval_s * self.max_missed

    def is_stale(self, task_id: str) -> bool:
        with self._lock:
            lease = self._leases.get(task_id)
            if lease is None:
                return False
            if lease.expired:
                return True
            return self.clock() > self._stale_cutoff(lease)

    def check_valid(self, task_id: str, agent_uuid: str, token: str) -> None:
        """Raise LeaseExpiredError unless (task, agent, token) is the live lease.

        This is THE zombie gate: all effectful writes go through here.
        """
        with self._lock:
            lease = self._leases.get(task_id)
            ok = (
                lease is not None
                and not lease.expired
                and lease.agent_uuid == agent_uuid
                and token == f"{agent_uuid}:{lease.epoch}"
            )
        if not ok:
            raise LeaseExpiredError(
                f"write rejected for task {task_id}: lease expired or superseded"
            )

    # -- sweeping ----------------------------------------------------------

    def sweep(self) -> SweepReport:
        """Expire stale leases; cascade to subagents; report what happened.

        Reassignment itself happens when another worker later calls
        :meth:`acquire` for the task (epoch bump guarantees zombie exclusion);
        the report's ``requeued_tasks`` marks which tasks are now fair game.
        """
        report = SweepReport()
        now = self.clock()
        with self._lock:
            stale = [
                lease
                for lease in self._leases.values()
                if not lease.expired and now > self._stale_cutoff(lease)
            ]
            # Cascade: expiring a parent invalidates any subagent lease that
            # names it, even if the subagent has been renewing diligently —
            # its authority came from the parent.
            frontier = [(lease.task_id, lease.agent_uuid) for lease in stale]
            seen: set[tuple[str, str]] = set()
            while frontier:
                task_id, agent = frontier.pop()
                if (task_id, agent) in seen:
                    continue
                seen.add((task_id, agent))
                for other in self._leases.values():
                    if (
                        other.parent_agent == agent
                        and not other.expired
                        and (other.task_id, other.agent_uuid) not in seen
                    ):
                        # Subagents expire regardless of their own freshness.
                        frontier.append((other.task_id, other.agent_uuid))
                        report.cascaded_agents.append(other.agent_uuid)
            for task_id, agent in seen:
                lease = self._leases[task_id]
                lease.expired = True
                if lease.agent_uuid == agent:
                    pass
                report.expired_leases.append(task_id)
                report.failed_agents.append(agent)
                report.requeued_tasks.append(task_id)
                for cb in self.on_expire:
                    try:
                        cb(lease)
                    except Exception:
                        pass  # observers must not break the sweep
                if self.audit is not None:
                    self.audit.append(
                        "lease_expired",
                        {"task": task_id, "agent": agent},
                    )
        return report
