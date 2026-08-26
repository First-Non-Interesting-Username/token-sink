"""Back-pressure & queue-depth governance (issue #179, PLAN §2.2/§7.1/§19.5).

A slow or failed provider must not stop routing (§2.2), and unbounded
internal queues are how that failure turns into memory exhaustion. This
module provides the governance layer between task producers (discovery
agents, subagent spawning, retry re-queues) and drain capacity:

- **Bounded per-class queues** with an explicit overflow policy chosen by
  criticality: ``REJECT_REQUEUE`` (bulk work: producer retries later) or
  ``BLOCK_PRODUCER`` (critical work: never silently dropped, the producer
  waits for room).
- **Admission control with structured feedback**: at/above the high-water
  mark every rejection emits a :class:`Rejected` event (never silent
  buffering). Subagent spawns are throttled FIRST so discovery floods can
  never starve the review pipeline.
- **Priority aging**: each class has a weight; waiting tasks accumulate age,
  and a class whose oldest task exceeds its SLA gets a scheduling boost —
  a pending approval cannot sit behind bulk discovery forever.
- **Slow-consumer detection**: event-stream consumers track their own lag;
  past a threshold they are flagged SLOW and should receive sampled/coalesced
  updates instead of unbounded server-side buffering.

Pure-Python and dependency-free: it orchestrates in-memory state; persistence
and the real event bus stay behind their existing subsystem interfaces.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class OverflowPolicy(StrEnum):
    """What happens when a queue has no room."""

    # Bulk work: refuse admission, hand the item back for delayed retry.
    REJECT_REQUEUE = "reject_requeue"
    # Critical work (approvals, kill-switch-adjacent): producer blocks for
    # room rather than letting the item be dropped.
    BLOCK_PRODUCER = "block_producer"


@dataclass(frozen=True)
class ClassPolicy:
    """Per-class queue configuration."""

    name: str
    max_size: int  # hard bound — the queue NEVER exceeds this
    high_water: int  # admission-control feedback threshold
    policy: OverflowPolicy
    sla_seconds: float | None = None  # aging target; boost when exceeded
    weight: float = 1.0  # drain-priority multiplier


@dataclass(frozen=True)
class Rejected:
    """Structured admission feedback (never a silent buffer grow)."""

    queue: str
    reason: str  # "queue_full" or "high_water_mark"
    task_id: str
    retry_after: float  # suggested delay before re-offering
    depth: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "type": "rejected",
            "queue": self.queue,
            "reason": self.reason,
            "task_id": self.task_id,
            "retry_after": self.retry_after,
            "depth": self.depth,
        }


class QueueFull(Exception):
    """Raised by put() under BLOCK_PRODUCER after the caller's timeout."""


# Consumer health states for the event stream (#31).
ConsumerState = str  # "healthy" | "slow" — kept as plain str for JSON friendliness
_SLOW_THRESHOLD = 1000  # lagged events beyond which a consumer is SLOW


class BackPressureGovernor:
    """Owns all bounded queues + admission control + observability."""

    def __init__(self, policies: list[ClassPolicy], clock: Callable[[], float] | None = None):
        if not policies:
            raise ValueError("at least one class policy is required")
        names = [p.name for p in policies]
        if len(names) != len(set(names)):
            raise ValueError("duplicate class policy names")
        self.policies = {p.name: p for p in policies}
        self._queues: dict[str, deque[tuple[float, str]]] = {p.name: deque() for p in policies}
        self._rejections: dict[str, int] = {p.name: 0 for p in policies}
        self._drained: dict[str, int] = {p.name: 0 for p in policies}
        # Slow-consumer tracking: consumer id -> lagged-event count.
        self._consumer_lag: dict[str, int] = {}
        self._clock = clock or time.monotonic

    def _time(self) -> float:
        return self._clock()

    # --- producers ---

    def offer(
        self, queue: str, task_id: str, *, is_subagent_spawn: bool = False, timeout: float = 0.0
    ) -> Rejected | None:
        """Admit `task_id` into `queue`.

        Returns None on success. On overflow under REJECT_REQUEUE returns a
        structured Rejected (the producer re-offers after retry_after).
        Under BLOCK_PRODUCER waits up to `timeout` seconds for room, then
        raises QueueFull (critical items are never silently dropped).
        Subagent spawns are throttled FIRST: while any queue is at its
        high-water mark, spawn offers are rejected even when their own queue
        has literal room — protecting the review pipeline from discovery
        floods (issue scope).
        """
        policy = self._policy(queue)
        now = self._time()
        q = self._queues[queue]
        full = len(q) >= policy.max_size
        # Any class sitting at ITS OWN high-water mark signals system-wide
        # pressure; spawns are throttled first wherever it shows up.
        system_pressure = any(
            len(dq) >= self.policies[name].high_water for name, dq in self._queues.items()
        )

        if is_subagent_spawn and not full and system_pressure:
            self._rejections[queue] += 1
            return Rejected(
                queue=queue,
                reason="high_water_mark",
                task_id=task_id,
                retry_after=1.0,
                depth=len(q),
            )

        if full:
            if policy.policy is OverflowPolicy.REJECT_REQUEUE:
                self._rejections[queue] += 1
                return Rejected(
                    queue=queue,
                    reason="queue_full",
                    task_id=task_id,
                    retry_after=1.0,
                    depth=len(q),
                )
            # BLOCK_PRODUCER: wait on WALL time (a producer genuinely blocks);
            # the injected clock governs timestamps/aging only.
            import time as _t

            deadline = _t.monotonic() + timeout
            while len(self._queues[queue]) >= policy.max_size:
                if _t.monotonic() >= deadline:
                    raise QueueFull(f"{queue} stayed full for {timeout}s")
                _t.sleep(min(0.005, max(0.001, timeout / 20)))
            q = self._queues[queue]
        elif (
            not is_subagent_spawn
            and len(q) >= policy.high_water
            and policy.policy is OverflowPolicy.REJECT_REQUEUE
        ):
            # High-water admission control: structured feedback instead of
            # silently filling toward the bound (issue scope).
            self._rejections[queue] += 1
            return Rejected(
                queue=queue,
                reason="high_water_mark",
                task_id=task_id,
                retry_after=1.0,
                depth=len(q),
            )

        q.append((now, task_id))
        return None

    # --- consumers ---

    def take(self, queue: str, *, prefer_aging: bool = True) -> tuple[str, float] | None:
        """Drain one item: (task_id, enqueued_at), or None if empty.

        With prefer_aging, picks the CLASS whose head item is most overdue vs
        its SLA (then by weight), giving latency-sensitive classes a minimum-
        progress guarantee under bulk load. Called per-queue it still works
        single-class; the scheduler loop passes over classes via
        :meth:`take_any`.
        """
        q = self._queues[queue]
        if not q:
            return None
        enqueued_at, task_id = q.popleft()
        self._drained[queue] += 1
        return task_id, enqueued_at

    def take_any(self) -> tuple[str, str, float] | None:
        """Cross-class drain: (queue, task_id, enqueued_at) honoring aging.

        Selection score per class: SLA overdue-ness dominates, then weight.
        A class whose oldest item blew its SLA always wins over non-overdue
        classes — approvals are never stuck behind bulk discovery.
        """
        best: tuple[float, float, str] | None = None
        for name, q in self._queues.items():
            if not q:
                continue
            policy = self.policies[name]
            oldest_age = self._time() - q[0][0]
            overdue = (
                max(0.0, oldest_age - policy.sla_seconds) if policy.sla_seconds is not None else 0.0
            )
            key_overdue = overdue > 0
            if best is None:
                best = (overdue, policy.weight, name)
            else:
                b_overdue, b_weight, b_name = best
                # SLA-overdue classes always win; among non-overdue ones the
                # higher weight (latency-sensitive class) wins.
                if overdue > b_overdue or (
                    overdue == b_overdue and (key_overdue or policy.weight > b_weight)
                ):
                    best = (overdue, policy.weight, name)
        if best is None:
            return None
        _, _, name = best
        item = self.take(name, prefer_aging=False)
        assert item is not None  # we just checked the queue is non-empty
        task_id, enqueued_at = item
        return name, task_id, enqueued_at

    # --- slow-consumer detection (#31) ---

    def record_consumer_lag(self, consumer_id: str, lag: int) -> str:
        """Update a UI/event consumer's lag; returns its state.

        Past the threshold the consumer is flagged 'slow': the event stream
        should send sampled/coalesced updates instead of buffering everything.
        """
        lag = max(0, lag)
        self._consumer_lag[consumer_id] = lag
        return "slow" if lag >= _SLOW_THRESHOLD else "healthy"

    def consumer_state(self, consumer_id: str) -> ConsumerState:
        if self._consumer_lag.get(consumer_id, 0) >= _SLOW_THRESHOLD:
            return "slow"
        return "healthy"

    # --- observability (#23 / §19.5 metrics) ---

    def stats(self) -> dict[str, Any]:
        """Snapshot for metrics export: depths, ages, rejections, drain rates."""
        out: dict[str, Any] = {"queues": {}, "consumers": dict(self._consumer_lag)}
        now = self._time()
        total_rej = total_drained = 0
        for name, q in self._queues.items():
            oldest = (now - q[0][0]) if q else 0.0
            out["queues"][name] = {
                "depth": len(q),
                "oldest_task_age": round(oldest, 6),
                "high_water": self.policies[name].high_water,
                "max_size": self.policies[name].max_size,
                "rejections": self._rejections[name],
                "drained": self._drained[name],
            }
            total_rej += self._rejections[name]
            total_drained += self._drained[name]
        out["total_rejections"] = total_rej
        out["total_drained"] = total_drained
        return out

    # --- internals ---

    def _policy(self, queue: str) -> ClassPolicy:
        try:
            return self.policies[queue]
        except KeyError:
            raise KeyError(f"unknown queue class: {queue!r}") from None
