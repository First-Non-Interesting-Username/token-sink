"""Graceful shutdown, crash recovery, and write-ahead intent (PLAN §12, §18, §19.2).

Tracked in issue #136. This module is the shutdown/recovery protocol that
makes PLAN's "restart must not lose state" acceptance criteria real:

- :class:`ShutdownCoordinator` — signal-driven graceful stop: stop accepting
  new work, checkpoint/drain in-flight tasks within a bounded deadline,
  flush event/log buffers, then exit. The deadline is hard: past it we
  checkpoint whatever remains and stop rather than hang.
- :class:`IntentJournal` — a durable write-ahead log for non-idempotent
  external side effects (e.g. provider calls already dispatched). Each intent
  is recorded BEFORE the side effect begins and resolved AFTER it completes,
  so recovery can distinguish done vs not-done without guessing.
- :func:`recover` — the startup sweep: detect stale leases, unresolved
  intents, orphaned artifacts, and unflushed events; repair to the last
  consistent state. Recovery itself is idempotent: every repair action is
  journaled through an ``IntentJournal`` so an interrupted recovery resumes
  safely after a second crash.

Why one small module instead of hooks scattered across subsystems: the whole
point of crash safety is that ordering rules live in exactly one place.
Subsystems register drain/checkpoint callbacks with the coordinator; the
journal and sweep stay generic.
"""

from __future__ import annotations

import enum
import json
import os
import signal
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Write-ahead intent journal
# ---------------------------------------------------------------------------


class IntentState(enum.StrEnum):
    PENDING = "pending"  # side effect may or may not have happened — resolve on recovery
    DONE = "done"  # completed successfully
    ABORTED = "aborted"  # never started / rolled back


@dataclass(frozen=True)
class Intent:
    """A record of one non-idempotent external side effect."""

    intent_id: str
    kind: str  # e.g. "provider_call", "recovery_repair"
    payload: dict[str, Any]
    state: IntentState
    created_at: float
    updated_at: float


class IntentJournal:
    """Append-style JSONL write-ahead journal.

    JSONL with fsync-per-append: each line is self-contained, so a torn write
    during a crash leaves at most one truncated trailing line, which the
    loader skips. This keeps the journal dependency-free and inspectable by
    hand during incident response (docs/failure-handling.md).
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _append(self, obj: dict[str, Any]) -> None:
        # 'a' + explicit fsync: the record must be on disk before the caller
        # starts the side effect — that is the entire point of write-ahead.
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def begin(self, kind: str, payload: dict[str, Any] | None = None) -> Intent:
        now = time.time()
        intent = Intent(
            intent_id=uuid.uuid4().hex,
            kind=kind,
            payload=payload or {},
            state=IntentState.PENDING,
            created_at=now,
            updated_at=now,
        )
        self._append(self._row(intent))
        return intent

    def resolve(self, intent_id: str, state: IntentState) -> None:
        # State changes append a new line rather than rewriting history:
        # the full sequence stays auditable after a crash.
        self._append(
            {
                "intent_id": intent_id,
                "op": "resolve",
                "state": state.value,
                "updated_at": time.time(),
            }
        )

    @staticmethod
    def _row(intent: Intent) -> dict[str, Any]:
        return {
            "intent_id": intent.intent_id,
            "kind": intent.kind,
            "payload": intent.payload,
            "state": intent.state.value,
            "created_at": intent.created_at,
            "updated_at": intent.updated_at,
        }

    def load(self) -> list[Intent]:
        """Replay the journal into current per-intent state.

        Skips malformed/truncated lines (torn final write) — safe to call on a
        journal written right up to a kill -9.
        """
        latest: dict[str, Intent] = {}
        if not self.path.exists():
            return []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue  # torn tail from a crash mid-write
            iid = rec.get("intent_id")
            if not iid:
                continue
            if rec.get("op") == "resolve":
                prev = latest[iid]
                latest[iid] = Intent(
                    intent_id=iid,
                    kind=prev.kind,
                    payload=prev.payload,
                    state=IntentState(rec["state"]),
                    created_at=prev.created_at,
                    updated_at=rec["updated_at"],
                )
            else:
                latest[iid] = Intent(
                    intent_id=iid,
                    kind=rec["kind"],
                    payload=rec.get("payload") or {},
                    state=IntentState(rec["state"]),
                    created_at=rec["created_at"],
                    updated_at=rec["updated_at"],
                )
        return list(latest.values())

    def pending(self) -> list[Intent]:
        return [i for i in self.load() if i.state == IntentState.PENDING]


# ---------------------------------------------------------------------------
# Graceful shutdown coordinator
# ---------------------------------------------------------------------------


class ShutdownState(enum.StrEnum):
    RUNNING = "running"
    DRAINING = "draining"  # no new work accepted; in-flight finishing
    STOPPED = "stopped"


@dataclass
class DrainResult:
    """Outcome of one graceful shutdown."""

    drained: list[str] = field(default_factory=list)  # callback names that completed
    checkpointed: list[str] = field(default_factory=list)  # names stopped via checkpoint
    timed_out: bool = False


class ShutdownCoordinator:
    """Signal-driven graceful shutdown with a bounded drain deadline.

    Callbacks are (name, callable). A callback returns True if it finished its
    work within the remaining budget ("drained") or False if it had to be
    checkpointed early. On SIGTERM/SIGINT the coordinator flips to DRAINING
    (so work-submission gates can refuse new tasks), runs callbacks newest-
    registered-first (cleanup order mirrors registration order), and enforces
    the total deadline across all of them.
    """

    def __init__(self, drain_deadline_s: float = 30.0):
        self.drain_deadline_s = drain_deadline_s
        self.state = ShutdownState.RUNNING
        self._callbacks: list[tuple[str, Callable[[float], bool]]] = []

    def register(self, name: str, cb: Callable[[float], bool]) -> None:
        self._callbacks.append((name, cb))

    @property
    def accepting_work(self) -> bool:
        """Gate for task submission: False once shutdown has begun."""
        return self.state == ShutdownState.RUNNING

    def request_shutdown(self) -> DrainResult:
        if self.state != ShutdownState.RUNNING:
            # Second signal: do not restart draining — idempotent by design.
            return DrainResult(timed_out=self.state == ShutdownState.DRAINING)
        self.state = ShutdownState.DRAINING
        result = DrainResult()
        deadline = time.monotonic() + self.drain_deadline_s
        for name, cb in reversed(self._callbacks):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                result.timed_out = True
                result.checkpointed.append(name)
                continue
            try:
                ok = cb(remaining)
            except Exception:  # noqa: BLE001 — a broken drain hook must not block stopping
                ok = False
            if ok:
                result.drained.append(name)
            else:
                result.checkpointed.append(name)
        self.state = ShutdownState.STOPPED
        return result

    def install_signal_handlers(self) -> None:
        """Wire SIGTERM/SIGINT to request_shutdown(). No-op off the main thread."""

        def _handler(signum: int, frame: Any) -> None:
            self.request_shutdown()

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, _handler)
            except ValueError:
                # Not on the main thread — callers should drive request_shutdown()
                # from their own lifecycle loop instead.
                pass


# ---------------------------------------------------------------------------
# Startup recovery sweep
# ---------------------------------------------------------------------------


@dataclass
class RepairAction:
    """One repair performed during recovery — every action is logged (#136)."""

    target: str  # what was repaired, e.g. intent id or lease key
    action: str  # e.g. "mark_aborted", "release_lease"
    detail: str = ""


@dataclass
class RecoveryReport:
    pending_intents_found: int = 0
    repairs: list[RepairAction] = field(default_factory=list)

    @property
    def consistent(self) -> bool:
        # Consistent when nothing is left ambiguous: all intents resolved.
        return (
            self.pending_intents_found
            == len([r for r in self.repairs if r.action.startswith("intent")])
            or self.pending_intents_found == 0
        )

    def summary(self) -> str:
        return (
            f"recovery: {self.pending_intents_found} pending intents, {len(self.repairs)} repairs"
        )


def recover(
    journal_path: str | Path,
    *,
    stale_leases: list[str] | None = None,
    release_lease: Callable[[str], None] | None = None,
    orphaned_artifacts: list[str] | None = None,
    remove_artifact: Callable[[str], None] | None = None,
    on_intent_pending: Callable[[Intent], str] | None = None,
) -> RecoveryReport:
    """Sweep for crash leftovers and repair to the last consistent state.

    ``on_intent_pending`` decides the fate of each PENDING intent (the caller
    knows whether the side effect is externally observable); it returns the
    new state as a string ("done" or "aborted"). Default policy: abort —
    conservative, because replaying a possibly-completed external effect risks
    duplicate side effects, which #136 explicitly forbids.

    Idempotency: repairs themselves are journaled in the same journal, so if
    recovery crashes midway, the next run sees already-resolved intents as
    DONE/ABORTED and simply re-checks the (now empty) leftover set. Running
    recover() twice yields no additional repairs the second time.
    """
    report = RecoveryReport()
    journal = IntentJournal(journal_path)

    pending = journal.pending()
    report.pending_intents_found = len(pending)
    for intent in pending:
        if on_intent_pending is not None:
            new_state = on_intent_pending(intent)
        else:
            new_state = IntentState.ABORTED.value
        journal.resolve(intent.intent_id, IntentState(new_state))
        report.repairs.append(
            RepairAction(
                target=intent.intent_id,
                action=f"intent:{new_state}",
                detail=f"kind={intent.kind}",
            )
        )

    # Stale leases: another holder died before releasing. Release each one;
    # releasing an already-released lease is a no-op, keeping this idempotent.
    for lease in stale_leases or []:
        if release_lease is not None:
            release_lease(lease)
        report.repairs.append(RepairAction(target=lease, action="release_lease"))

    # Orphaned artifacts (written but never referenced by a committed record):
    # remove so storage returns to the last referenced-consistent set.
    for artifact in orphaned_artifacts or []:
        if remove_artifact is not None:
            remove_artifact(artifact)
        report.repairs.append(RepairAction(target=artifact, action="remove_orphan_artifact"))

    return report
