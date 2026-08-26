"""Unit tests for the lease manager / stale-lease sweeper (issue #178)."""

from __future__ import annotations

import threading

import pytest

from orchestrator.leases import LeaseError, LeaseExpiredError, LeaseManager
from policy.audit import AuditLog


def test_acquire_renew_release_roundtrip():
    lm = LeaseManager(renewal_interval_s=1, max_missed=3)
    lm.acquire("t1", "agent-a")
    assert lm.renew("t1", "agent-a") is True
    lm.release("t1", "agent-a")
    # Released: another agent can acquire immediately, epoch bumps.
    token2 = lm.acquire("t1", "agent-b")
    assert token2 == "agent-b:2"


def test_double_acquire_of_healthy_lease_rejected():
    lm = LeaseManager()
    lm.acquire("t1", "agent-a")
    with pytest.raises(LeaseError):
        lm.acquire("t1", "agent-b")


def test_stale_detection_after_missed_renewals():
    now = [1000.0]
    lm = LeaseManager(renewal_interval_s=5, max_missed=3, clock=lambda: now[0])
    lm.acquire("t1", "agent-a")
    # Within window (15s) it's fresh.
    now[0] = 1010.0
    assert lm.is_stale("t1") is False
    now[0] = 1016.0
    assert lm.is_stale("t1") is True


def test_sweep_expires_stale_and_requeues():
    now = [1000.0]
    lm = LeaseManager(renewal_interval_s=5, max_missed=3, clock=lambda: now[0])
    lm.acquire("t1", "agent-a")
    lm.acquire("t2", "agent-b")

    # t2 keeps its heartbeat alive across the window; t1 goes silent.
    now[0] = 1012.0
    lm.renew("t2", "agent-b")  # fresh until 1027
    now[0] = 1020.0  # t1 stale at 1015; t2 still fresh
    report = lm.sweep()
    assert report.expired_leases == ["t1"]
    assert report.failed_agents == ["agent-a"]
    assert report.requeued_tasks == ["t1"]


def test_zombie_write_rejected_after_reassignment():
    """The core correctness scenario: original agent resumes late and tries
    to write after its task was reassigned — the write must be rejected."""
    now = [1000.0]
    lm = LeaseManager(renewal_interval_s=5, max_missed=3, clock=lambda: now[0])
    zombie_token = lm.acquire("task-9", "zombie-agent")

    now[0] = 1020.0
    report = lm.sweep()  # zombie presumed dead; task requeued
    assert "task-9" in report.requeued_tasks

    new_token = lm.acquire("task-9", "fresh-agent")  # epoch bump
    assert new_token == "fresh-agent:2"

    # Zombie wakes up and attempts a write with its old token.
    with pytest.raises(LeaseExpiredError):
        lm.check_valid("task-9", "zombie-agent", zombie_token)
    # The legitimate holder writes fine.
    lm.check_valid("task-9", "fresh-agent", new_token)


def test_cascade_expiry_to_subagents():
    now = [1000.0]
    lm = LeaseManager(renewal_interval_s=5, max_missed=3, clock=lambda: now[0])
    lm.acquire("parent-task", "parent")
    lm.acquire("child-task", "child", parent_agent="parent")
    lm.acquire("grandchild-task", "grand", parent_agent="child")

    # Children keep renewing diligently; the parent goes silent.
    for t in range(1005, 1026, 5):
        now[0] = float(t)
        lm.renew("child-task", "child")
        lm.renew("grandchild-task", "grand")

    now[0] = 1020.0  # parent stale since 1015
    report = lm.sweep()
    # Parent death cascades through the whole subtree regardless of the
    # children's own freshness.
    assert set(report.expired_leases) == {"parent-task", "child-task", "grandchild-task"}
    assert set(report.cascaded_agents) == {"child", "grand"}


def test_subagent_cascade_even_when_child_renews_freshly():
    now = [1000.0]
    lm = LeaseManager(renewal_interval_s=5, max_missed=3, clock=lambda: now[0])
    lm.acquire("p", "parent")
    lm.acquire("c", "child", parent_agent="parent")

    now[0] = 1016.0  # parent stale (>15s), child keeps renewing
    lm.renew("c", "child")
    report = lm.sweep()
    assert "p" in report.expired_leases
    assert "c" in report.cascaded_agents or "c" in report.expired_leases
    # Child's write is rejected despite its fresh heartbeat.
    with pytest.raises(LeaseExpiredError):
        lm.check_valid("c", "child", "child:1")


def test_expired_lease_count_metric_hook():
    counts = []
    now = [1000.0]
    lm = LeaseManager(renewal_interval_s=5, max_missed=3, clock=lambda: now[0])
    lm.on_expire.append(lambda lease: counts.append(lease.task_id))
    lm.acquire("t1", "a1")
    now[0] = 1020.0
    lm.sweep()
    assert counts == ["t1"]


def test_sweep_writes_audit_events(tmp_path):
    from pathlib import Path

    audit = AuditLog(Path(tmp_path) / "audit.jsonl")
    now = [1000.0]
    lm = LeaseManager(renewal_interval_s=5, max_missed=3, clock=lambda: now[0], audit=audit)
    lm.acquire("t1", "agent-x")
    now[0] = 1020.0
    lm.sweep()

    events = [e for e in audit.entries() if e["event_type"] == "lease_expired"]
    assert len(events) == 1
    assert events[0]["payload"]["task"] == "t1"
    assert events[0]["payload"]["agent"] == "agent-x"
    assert audit.verify()


def test_concurrent_acquires_only_one_wins():
    lm = LeaseManager()
    winners: list[str] = []
    lock = threading.Lock()

    def try_acquire(agent: str) -> None:
        try:
            lm.acquire("contended", agent)
            with lock:
                winners.append(agent)
        except LeaseError:
            pass

    threads = [threading.Thread(target=try_acquire, args=(f"a{i}",)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(winners) == 1


def test_idempotent_effects_with_execution_runner(tmp_path):
    """Crash → reassign → zombie completes late ⇒ effect applied exactly once.

    Uses the repo's existing idempotency journal: both executions share the
    same task id, so the journal deduplicates the side effect.
    """
    from orchestrator.idempotency import ExecutionRunner
    from storage.sqlite import SQLiteStorage

    store = SQLiteStorage(tmp_path / "db.sqlite", tmp_path / "artifacts")
    store.migrate()
    runner = ExecutionRunner(store)

    effects: list[str] = []

    def do_effect() -> str:
        effects.append("ran")
        return "result"

    # First execution (original agent) journalled 'started' but crashed
    # before completing.
    runner.begin("task-z", "exec-1")

    # Reassignment: same task id, new execution — journal allows this because
    # exec-1 never completed... but the *effect* must not run twice once any
    # execution completed it.
    result, executed = runner.run("exec-1", "effect", do_effect)
    assert executed is True
    assert len(effects) == 1

    # Zombie completes late with the same (task, execution, step) key:
    # journal returns the recorded result without re-running the effect.
    result_again, executed_again = runner.run("exec-1", "effect", do_effect)
    assert executed_again is False
    assert len(effects) == 1
    store.close()
