"""Crash/restart integration test for idempotent task execution (issue #126).

Simulates a crash between journal steps: a fresh SQLiteStorage over the same
files must see the journalled state and never duplicate provider-call-shaped
effects or double-append events.
"""

import pytest

from orchestrator.idempotency import ExecutionRunner
from storage.sqlite import SQLiteStorage


@pytest.mark.integration
def test_crash_between_steps_no_duplicate_effects_or_events(tmp_path):
    def open_store() -> SQLiteStorage:
        s = SQLiteStorage(tmp_path / "meta.db", tmp_path / "artifacts")
        s.migrate()
        return s

    store1 = open_store()
    runner = ExecutionRunner(store1)
    task_id, exec_id = "task-crash", "exec-crash-1"
    runner.begin(task_id, exec_id)

    calls: list[str] = []
    runner.run(exec_id, "step-1", lambda: calls.append("provider-call-1"))

    # Crash *inside* step-2's effect: intent is journalled, completion is not.
    def crashing_effect():
        calls.append("provider-call-2-attempt")
        raise RuntimeError("simulated crash mid-step")

    try:
        runner.run(exec_id, "step-2", crashing_effect)
    except RuntimeError:
        pass
    # An event was appended before the crash.
    store1.insert_record("event", "ev-1", {"n": 1}, idempotency_key=f"{exec_id}:ev-1")
    store1.close()

    # --- restart on the same files ---
    store2 = open_store()
    runner2 = ExecutionRunner(store2)

    # Same execution id after restart; step-1 must NOT re-run.
    _, executed = runner2.run(exec_id, "step-1", lambda: calls.append("DUP-1"))
    assert executed is False

    # Step-2 re-runs exactly once (its first attempt never completed).
    runner2.run(exec_id, "step-2", lambda: calls.append("provider-call-2"))

    # Event insert retried with same id or same key: DB-level dedupe.
    from storage.base import RecordExistsError

    with pytest.raises(RecordExistsError):
        store2.insert_record("event", "ev-1-dup", {"n": 1}, idempotency_key=f"{exec_id}:ev-1")
    with pytest.raises(RecordExistsError):
        store2.insert_record("event", "ev-1", {"n": 1}, idempotency_key=f"{exec_id}:ev-1")

    assert calls == [
        "provider-call-1",
        "provider-call-2-attempt",  # crashed attempt
        "provider-call-2",  # single successful re-run after restart
    ]
    events = store2.list_records("event", limit=10)
    assert len(events) == 1  # no double-appended events after restart
    store2.close()
