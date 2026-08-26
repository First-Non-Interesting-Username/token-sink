"""Dead-letter queue + replay workflow (issue #149, PLAN §7.3, §18).

Tasks whose recovery path is ``dead_letter`` (see
``orchestrator.failures.RECOVERY_PATHS``) land here instead of retrying
forever or vanishing. The DLQ is deliberately boring:

- **Capture**: one entry per dead task with its failure classification,
  structured reason, and full attempt history (append-only — history is
  evidence, never edited).
- **Retention bound**: oldest entries beyond the capacity cap are evicted
  FIFO; eviction is recorded as a tombstone in the audit trail so a task
  can never silently disappear.
- **Replay**: re-enqueues via an injected callback (caller wires it to the
  real queue) while preserving the original idempotency key, so replayed
  tasks cannot duplicate already-executed work. A per-entry replay cap
  guards against poison tasks cycling forever.

Pure in-memory policy module like the rest of orchestrator/; persistence
is the storage layer's job.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field


class DLQError(RuntimeError):
    """Invalid DLQ operation (unknown entry, cap exceeded, etc.)."""


class EntryState(enum.StrEnum):
    DEAD = "dead"  # sitting in the queue
    REPLAYED = "replayed"  # handed back to the queue
    DISCARDED = "discarded"  # explicitly discarded by an operator decision


@dataclass
class Attempt:
    """One failed execution attempt."""

    at: float  # epoch seconds (injected clock keeps tests deterministic)
    failure_class: str
    detail: str = ""


@dataclass
class DLQEntry:
    task_id: str
    idempotency_key: str
    reason: str
    attempts: list[Attempt] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    state: EntryState = EntryState.DEAD
    replay_count: int = 0


class DeadLetterQueue:
    """Bounded capture + audited replay for unroutable/failed tasks."""

    def __init__(
        self,
        capacity: int = 1_000,
        max_replays_per_entry: int = 3,
        audit_log=None,
        clock=None,
    ):
        # audit_log: policy.audit.AuditLog-compatible (append(event_type,
        # payload)) so every eviction/replay leaves a trail (PLAN §15/§18).
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self.capacity = capacity
        self.max_replays_per_entry = max_replays_per_entry
        self.audit = audit_log
        self._clock = clock or _default_clock
        self._entries: dict[str, DLQEntry] = {}
        self._order: list[str] = []  # FIFO eviction order

    # -- capture --------------------------------------------------------------

    def enqueue(
        self,
        task_id: str,
        idempotency_key: str,
        reason: str,
        attempts: list[Attempt] | None = None,
    ) -> DLQEntry:
        if task_id in {e.task_id for e in self._entries.values() if e.state is EntryState.DEAD}:
            # One live DLQ row per task: duplicates would double-count and
            # allow racing replays of the same work.
            raise DLQError(f"task {task_id} is already in the dead-letter queue")
        entry = DLQEntry(
            task_id=task_id,
            idempotency_key=idempotency_key,
            reason=reason,
            attempts=list(attempts or []),
        )
        # Carry the replay history forward from any prior row for this task:
        # without this, a task that cycles dead→replay→dead would reset its
        # counter each time and never hit the poison-task cap.
        prior = max(
            (e.replay_count for e in self._entries.values() if e.task_id == task_id),
            default=0,
        )
        entry.replay_count = prior
        self._evict_if_full()
        self._entries[entry.id] = entry
        self._order.append(entry.id)
        return entry

    def record_attempt(self, entry_id: str, attempt: Attempt) -> None:
        entry = self._require(entry_id)
        if entry.state is not EntryState.DEAD:
            raise DLQError("cannot append attempts to a non-dead entry")
        entry.attempts.append(attempt)

    def _evict_if_full(self) -> None:
        while len(self._order) >= self.capacity:
            evicted_id = self._order.pop(0)
            evicted = self._entries.pop(evicted_id)
            self._audit_event(
                "dlq_evicted",
                {
                    "entry_id": evicted.id,
                    "task_id": evicted.task_id,
                    "replay_count": evicted.replay_count,
                },
            )

    # -- replay -----------------------------------------------------------------

    def replay(self, entry_id: str, enqueue_task) -> DLQEntry:
        """Re-enqueue a dead task via *enqueue_task*.

        ``enqueue_task(task_id, idempotency_key) -> Any`` is injected so the
        DLQ stays decoupled from the concrete queue implementation. The
        ORIGINAL idempotency key travels with the replay — that's what makes
        duplicate execution impossible even across crash-replay cycles.
        """
        entry = self._require(entry_id)
        if entry.state is not EntryState.DEAD:
            raise DLQError(f"entry {entry_id} is '{entry.state.value}', only dead entries replay")
        if entry.replay_count >= self.max_replays_per_entry:
            # Poison-task guard: beyond the cap the entry needs human triage,
            # not another automatic cycle.
            raise DLQError(
                f"entry {entry_id} hit the replay cap ({self.max_replays_per_entry}) "
                "— manual triage required"
            )
        enqueue_task(entry.task_id, entry.idempotency_key)
        entry.state = EntryState.REPLAYED
        entry.replay_count += 1
        self._audit_event(
            "dlq_replayed",
            {"entry_id": entry.id, "task_id": entry.task_id, "replay_number": entry.replay_count},
        )
        return entry

    def discard(self, entry_id: str, actor: str = "") -> DLQEntry:
        """Operator-explicit discard (audit-trailed; never silent deletion)."""
        entry = self._require(entry_id)
        if entry.state is not EntryState.DEAD:
            raise DLQError(f"entry {entry_id} is '{entry.state.value}'")
        entry.state = EntryState.DISCARDED
        self._audit_event("dlq_discarded", {"entry_id": entry.id, "task_id": entry.task_id})
        return entry

    # -- read surface -----------------------------------------------------------

    def pending(self) -> list[DLQEntry]:
        return [e for e in self._entries.values() if e.state is EntryState.DEAD]

    def get(self, entry_id: str) -> DLQEntry:
        return self._require(entry_id)

    def stats(self) -> dict:
        states = [e.state for e in self._entries.values()]
        return {
            "pending": states.count(EntryState.DEAD),
            "replayed": sum(e.replay_count for e in self._entries.values()),
            "discarded": states.count(EntryState.DISCARDED),
            "live_rows": len(self._entries),
            "capacity": self.capacity,
        }

    # -- helpers ------------------------------------------------------------------

    def _require(self, entry_id: str) -> DLQEntry:
        try:
            return self._entries[entry_id]
        except KeyError:
            raise DLQError(f"unknown DLQ entry {entry_id}") from None

    def _audit_event(self, event_type: str, payload: dict) -> None:
        if self.audit is not None:
            self.audit.append(event_type, payload)


def _default_clock() -> float:
    import time

    return time.time()
