"""Unit tests for idempotent task execution (PLAN §12, issue #126)."""

import pytest

from orchestrator.idempotency import (
    KIND_STEP,
    DuplicateExecutionError,
    ExecutionRunner,
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


class FlakyEffect:
    """Counts invocations of an effect; stands in for provider/network calls."""

    def __init__(self, result: object = "ok"):
        self.calls = 0
        self.result = result

    def __call__(self):
        self.calls += 1
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def test_run_executes_once_and_returns_result(runner):
    runner.begin("task-1", "exec-a")
    effect = FlakyEffect(result={"answer": 42})
    res, executed = runner.run("exec-a", "fetch-target", effect)
    assert executed is True
    assert res == {"answer": 42}
    assert effect.calls == 1
    assert runner.step_state("exec-a", "fetch-target") == "completed"


def test_retry_after_completion_does_not_re_run_effect(runner):
    runner.begin("task-1", "exec-a")
    runner.run("exec-a", "step1", FlakyEffect("first"))
    effect = FlakyEffect("second")
    res, executed = runner.run("exec-a", "step1", effect)  # e.g. process restarted
    assert executed is False
    assert res == "first"
    assert effect.calls == 0


def test_intent_journalled_before_effect(runner):
    runner.begin("task-1", "exec-a")
    seen_state = {}

    def effect():
        seen_state["during"] = runner.step_state("exec-a", "s")
        return 1

    runner.run("exec-a", "s", effect)
    # While the side effect ran, the journal already said 'started'.
    assert seen_state["during"] == "started"


def test_crash_between_start_and_complete_re_runs(runner, store):
    runner.begin("task-1", "exec-a")
    boom = FlakyEffect(result=RuntimeError("crash after intent"))
    with pytest.raises(RuntimeError):
        runner.run("exec-a", "step", boom)
    # Journal shows started, not completed.
    assert (
        store.get_record(
            KIND_STEP,
            store.conn.execute("SELECT id FROM records WHERE kind=?", (KIND_STEP,)).fetchone()[0],
        )["state"]
        == "started"
    )
    assert boom.calls == 1
    # Restart path: same execution re-runs the (re-runnable) effect and completes.
    effect2 = FlakyEffect(result="done")
    res, executed = runner.run("exec-a", "step", effect2)
    assert executed is True
    assert res == "done"
    assert effect2.calls == 1


def test_duplicate_execution_for_same_task_rejected(runner):
    runner.begin("task-1", "exec-a")
    with pytest.raises(DuplicateExecutionError):
        runner.begin("task-1", "exec-b")


def test_same_execution_id_across_restart_is_allowed(runner):
    runner.begin("task-1", "exec-a")
    runner.begin("task-1", "exec-a")  # restart with the SAME id: fine


def test_execution_id_bound_to_one_task(runner):
    runner.begin("task-1", "exec-a")
    with pytest.raises(DuplicateExecutionError):
        runner.begin("task-2", "exec-a")


def test_unique_event_ids_enforced_at_db_level(store):
    # §12: unique constraints for UUIDs/event IDs live in the DB, not app code.
    store.insert_record("event", "e1", {}, idempotency_key="evt-x")
    with pytest.raises(RecordExistsError):
        store.insert_record("event", "e2", {}, idempotency_key="evt-x")
