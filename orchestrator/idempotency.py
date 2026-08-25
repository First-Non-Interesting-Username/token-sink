"""Idempotent task execution (PLAN §12, issue #126).

Wraps side-effectful task steps so that retries after a crash or restart
never duplicate their effects. The pattern is *journal intent first*:

1. Before running a side effect, the executor writes a ``started`` marker
   for (execution_id, step) into the metadata DB. The write is protected by
   the storage layer's UNIQUE ``idempotency_key`` constraint, so two
   processes racing on the same step cannot both win the insert.
2. The side effect runs only if no ``completed`` record exists yet.
3. On success the result is stored in a ``completed`` record whose
   idempotency key is derived from (execution_id, step). If the process dies
   between the effect and the completion write, the next attempt sees the
   ``started`` marker but no ``completed`` record and re-runs the effect —
   which is why every side-effectful callable handed to
   :meth:`ExecutionRunner.run` must itself be safe to re-run (e.g. writes go
   through content-addressed artifacts or idempotent storage calls).

Exactly-once *effects* are achieved by construction of those callables plus
the journal; exactly-once *invocation after successful completion* is
guaranteed by the journal lookup alone.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any

from storage.base import RecordExistsError, Storage

# Record kinds used by the journal. Kept distinct from domain records so
# exports/filters can treat execution bookkeeping separately.
KIND_EXECUTION = "execution"
KIND_STEP = "execution_step"


def _safe_component(s: str) -> str:
    # Journal keys are hashed rather than embedded raw: keeps ids inside the
    # storage layer's _SAFE_ID charset even for arbitrary task/step names,
    # and avoids leaking target/task text into DB ids shown in logs/exports.
    return hashlib.sha256(s.encode()).hexdigest()[:40]


class DuplicateExecutionError(Exception):
    """A different execution is already journalled for this task."""


class ExecutionRunner:
    """Journal-backed runner giving at-most-once *effects* per execution."""

    def __init__(self, storage: Storage):
        self.storage = storage

    # --- journal ---------------------------------------------------------

    def begin(self, task_id: str, execution_id: str) -> None:
        """Open an execution for a task. Raises DuplicateExecutionError if the
        task already has a *different* open-or-done execution — one task, one
        execution identity, so restarts reuse the SAME execution_id and get
        dedupe for free."""
        exec_key = f"exec:{_safe_component(execution_id)}"
        try:
            self.storage.insert_record(
                KIND_EXECUTION,
                f"exec-{_safe_component(execution_id)}",
                {"task_id": task_id},
                idempotency_key=exec_key,
            )
        except RecordExistsError:
            existing = self.storage.get_record(
                KIND_EXECUTION, f"exec-{_safe_component(execution_id)}"
            )
            if not existing or existing["data"].get("task_id") != task_id:
                raise DuplicateExecutionError(
                    f"execution {execution_id} already journalled for a different task"
                ) from None
            return  # same task, same id: restart path is fine
        # New execution: reject if the task already has ANY other execution,
        # so one task can never fork into two execution identities.
        own_id = f"exec-{_safe_component(execution_id)}"
        for rec in self.storage.list_records(KIND_EXECUTION, limit=1000):
            if rec["data"].get("task_id") == task_id and rec["id"] != own_id:
                raise DuplicateExecutionError(
                    f"task {task_id} already has execution {rec['data'].get('execution_id')}"
                )

    def step_state(self, execution_id: str, step: str) -> str | None:
        """'started' | 'completed' | None for this (execution, step)."""
        rec = self.storage.get_record(KIND_EXECUTION, f"exec-{_safe_component(execution_id)}")
        if rec is None:
            return None
        row = self.storage.get_record(KIND_STEP, _step_id(execution_id, step))
        return row["state"] if row else None

    def completed_result(self, execution_id: str, step: str) -> Any | None:
        row = self.storage.get_record(KIND_STEP, _step_id(execution_id, step))
        if row is not None and row["state"] == "completed":
            return row["data"].get("result")
        return None

    # --- execution -------------------------------------------------------

    def run(self, execution_id: str, step: str, fn: Callable[[], Any]) -> tuple[Any, bool]:
        """Run one side-effectful step exactly once per execution.

        Returns ``(result, executed)`` where ``executed`` is False when a
        previously completed attempt's journalled result was returned instead
        of re-running ``fn`` (crash-recovery / retry path).
        """
        if self.step_state(execution_id, step) == "completed":
            # Keyed off journalled *state*, not the result value: effects may
            # legitimately return None.
            return self.completed_result(execution_id, step), False

        step_rec_id = _step_id(execution_id, step)
        try:
            self.storage.insert_record(
                KIND_STEP,
                step_rec_id,
                {"execution_id": execution_id, "step": step},
                idempotency_key=f"step:{_safe_component(execution_id + ':' + step)}",
            )
        except RecordExistsError:
            # Row exists from an earlier crashed attempt: either 'started'
            # (safe to re-run fn per module contract) or 'completed' (already
            # handled by the cache lookup above).
            pass
        else:
            self.storage.transition(
                KIND_STEP,
                step_rec_id,
                "created",
                "started",
                reason="journal intent before side effect",
            )

        result = fn()  # must be re-runnable: see module docstring WHY

        row = self.storage.get_record(KIND_STEP, step_rec_id)
        assert row is not None
        self.storage.update_record(
            KIND_STEP, step_rec_id, int(row["version"]), {"result": _jsonable(result)}
        )
        self.storage.transition(
            KIND_STEP,
            step_rec_id,
            "started",
            "completed",
            reason="effect applied and result journalled",
        )
        return result, True


def _step_id(execution_id: str, step: str) -> str:
    return f"step-{_safe_component(execution_id + ':' + step)}"


def _jsonable(v: Any) -> Any:
    # Results are journalled as JSON; coerce common non-JSON types instead of
    # failing the (already-applied) effect's bookkeeping.
    try:
        json.dumps(v)
        return v
    except TypeError:
        return repr(v)
