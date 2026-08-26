"""DB-level task→execution binding (issue #245).

The one-execution-per-task invariant must be enforced by a UNIQUE constraint
on the bind record, not by scanning prior executions in Python — the old
scan was O(n) and silently capped, so a task could fork into a second
execution identity once more than `limit` executions existed.
"""

import pytest

from orchestrator.idempotency import (
    KIND_TASK_BIND,
    DuplicateExecutionError,
    ExecutionRunner,
    _safe_component,
)
from storage.base import RecordExistsError
from storage.sqlite import SQLiteStorage


@pytest.fixture()
def store(tmp_path):
    s = SQLiteStorage(tmp_path / "meta.db", tmp_path / "artifacts")
    s.migrate()
    yield s
    s.close()


@pytest.fixture()
def runner(store):
    return ExecutionRunner(store)


def test_bind_record_is_unique_per_task(runner, store):
    runner.begin("task-1", "exec-a")
    # The binding is a real journal row with a UNIQUE idempotency key: a second
    # execution cannot claim task-1 even via a raw storage insert.
    with pytest.raises(RecordExistsError):
        store.insert_record(
            KIND_TASK_BIND,
            "bind-other",
            {"execution_id": "exec-b"},
            idempotency_key=f"bind:{_safe_component('task-1')}",
        )


def test_second_execution_for_same_task_rejected_via_db(runner):
    runner.begin("task-1", "exec-a")
    with pytest.raises(DuplicateExecutionError):
        runner.begin("task-1", "exec-b")


def test_binding_survives_many_unrelated_executions(store):
    """The old implementation scanned list_records(limit=1000): after >1000
    unrelated executions the scan silently missed older rows. The DB-level
    unique key must not degrade with execution count."""
    runner = ExecutionRunner(store)
    for i in range(1005):
        runner.begin(f"filler-{i}", f"exec-filler-{i}")
    runner.begin("task-x", "exec-x")
    with pytest.raises(DuplicateExecutionError):
        runner.begin("task-x", "exec-y")
