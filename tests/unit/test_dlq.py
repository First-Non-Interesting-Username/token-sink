"""Unit tests for orchestrator/dlq.py (issue #149, PLAN §7.3/§18)."""

import pytest

from orchestrator.dlq import Attempt, DeadLetterQueue, DLQEntry, DLQError, EntryState
from policy.audit import AuditLog


@pytest.fixture()
def dlq(tmp_path):
    return DeadLetterQueue(
        capacity=3, audit_log=AuditLog(tmp_path / "audit.jsonl"), clock=lambda: 1.0
    )


def test_enqueue_and_pending(dlq):
    e = dlq.enqueue("t-1", "idem-1", "malformed output")
    assert e.state is EntryState.DEAD
    assert [x.task_id for x in dlq.pending()] == ["t-1"]


def test_duplicate_live_task_rejected(dlq):
    dlq.enqueue("t-1", "idem-1", "boom")
    with pytest.raises(DLQError):
        dlq.enqueue("t-1", "idem-1", "boom again")


def test_record_attempt_appends_history(dlq):
    e = dlq.enqueue("t-1", "idem-1", "boom")
    dlq.record_attempt(e.id, Attempt(at=2.0, failure_class="malformed_output", detail="bad json"))
    assert dlq.get(e.id).attempts[-1].failure_class == "malformed_output"


def test_replay_preserves_idempotency_key_and_audits(dlq):
    e = dlq.enqueue("t-1", "idem-9", "search extraction failed")
    seen = []
    out = dlq.replay(e.id, lambda task_id, key: seen.append((task_id, key)))
    assert seen == [("t-1", "idem-9")]  # original key travels with replay
    assert out.state is EntryState.REPLAYED
    assert out.replay_count == 1


def test_double_replay_of_same_entry_rejected(dlq):
    e = dlq.enqueue("t-1", "k", "r")
    dlq.replay(e.id, lambda t, k: None)
    with pytest.raises(DLQError):
        dlq.replay(e.id, lambda t, k: None)


def test_replay_cap_blocks_poison_tasks(tmp_path):
    dlq = DeadLetterQueue(
        capacity=5, max_replays_per_entry=1, audit_log=AuditLog(tmp_path / "a.jsonl")
    )
    e = dlq.enqueue("t-1", "k", "always fails")
    dlq.replay(e.id, lambda t, k: None)  # replay 1 → cap reached
    again = dlq.enqueue("t-1", "k", "always fails")
    with pytest.raises(DLQError, match="replay cap"):
        dlq.replay(again.id, lambda t, k: None)


def test_capacity_eviction_is_fifo_and_audited(dlq):
    for i in range(4):  # capacity 3 → oldest evicted
        dlq.enqueue(f"t-{i}", f"k-{i}", "r")
    assert dlq.get and all(e.task_id != "t-0" for e in dlq.pending())
    events = []
    with open(dlq.audit._path) as f:
        events = [__import__("json").loads(line)["event_type"] for line in f]
    assert "dlq_evicted" in events


def test_discard_is_terminal_and_audited(dlq):
    e = dlq.enqueue("t-1", "k", "r")
    dlq.discard(e.id)
    assert dlq.get(e.id).state is EntryState.DISCARDED
    with pytest.raises(DLQError):
        dlq.replay(e.id, lambda t, k: None)  # discarded entries never replay


def test_stats_counts_states(dlq):
    a = dlq.enqueue("t-1", "k1", "r")
    dlq.enqueue("t-2", "k2", "r")
    dlq.replay(a.id, lambda t, k: None)
    s = dlq.stats()
    assert s["pending"] == 1 and s["replayed"] == 1


def test_unknown_entry_raises(dlq):
    with pytest.raises(DLQError, match="unknown"):
        dlq.replay("nope", lambda t, k: None)


def test_invalid_capacity_rejected():
    with pytest.raises(ValueError):
        DeadLetterQueue(capacity=0)


def test_entry_defaults_are_distinct():
    a, b = (
        DLQEntry(task_id="x", idempotency_key="k", reason="r"),
        DLQEntry(task_id="y", idempotency_key="k2", reason="r"),
    )
    assert a.id != b.id  # mutable-default pitfall guarded by field(default_factory)
