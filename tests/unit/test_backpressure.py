"""Unit tests for back-pressure governance (issue #179, PLAN §2.2/§7.1/§19.5)."""

from __future__ import annotations

import pytest

from orchestrator.backpressure import (
    BackPressureGovernor,
    ClassPolicy,
    OverflowPolicy,
    QueueFull,
)


class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture()
def clock():
    return FakeClock()


def _governor(clock, *, bulk_max=10, crit_max=5):
    return BackPressureGovernor(
        [
            ClassPolicy(
                name="discovery",
                max_size=bulk_max,
                high_water=int(bulk_max * 0.8),
                policy=OverflowPolicy.REJECT_REQUEUE,
                weight=1.0,
            ),
            ClassPolicy(
                name="approvals",
                max_size=crit_max,
                high_water=crit_max,
                policy=OverflowPolicy.BLOCK_PRODUCER,
                sla_seconds=2.0,
                weight=10.0,
            ),
        ],
        clock=clock,
    )


def test_queue_never_exceeds_hard_bound(clock):
    g = _governor(clock)
    accepted = 0
    for i in range(12):  # more than high_water=8
        r = g.offer("discovery", f"t{i}")
        if r is None:
            accepted += 1
    stats = g.stats()["queues"]["discovery"]
    # Bound holds; admission stops at the high-water mark with feedback.
    assert stats["depth"] == accepted <= 10
    assert stats["rejections"] == 4
    assert stats["drained"] == 0


def test_high_water_produces_structured_feedback_not_silent_buffering(clock):
    g = _governor(clock)
    rejections = []
    for i in range(9):  # crosses high_water=8 at i==8
        r = g.offer("discovery", f"t{i}")
        if r is not None:
            rejections.append(r.as_dict())
    assert rejections, "crossing the high-water mark must produce feedback events"
    assert all(r["reason"] == "high_water_mark" for r in rejections)
    assert all(set(r) >= {"queue", "reason", "task_id", "retry_after"} for r in rejections)


def test_subagent_spawns_throttled_first_at_high_water(clock):
    """Discovery floods must not starve review: spawns bounce before their queue."""
    g = _governor(clock)
    for i in range(8):
        assert g.offer("discovery", f"d{i}") is None  # discovery at high water
    # A subagent spawn into a NON-crowded queue still gets throttled while any
    # queue sits at its high-water mark.
    r = g.offer("approvals", "spawn-1", is_subagent_spawn=True)
    assert r is not None and r.reason == "high_water_mark"
    # Non-spawn traffic to that same non-crowded queue is unaffected.
    assert g.offer("approvals", "approval-1") is None


def test_saturation_reaches_steady_state_not_unbounded_growth(clock):
    """Simulated provider slowdown: producers back off, depth stabilizes."""
    g = _governor(clock, bulk_max=6)
    offered = rejected = drained = 0
    for tick in range(200):
        clock.t = tick * 1.0
        r = g.offer("discovery", f"task-{tick}")
        if r is None:
            offered += 1
        else:
            rejected += 1
        # Drain capacity slower than production (slow providers).
        if tick % 3 == 0 and g.take("discovery"):
            drained += 1
        depth = g.stats()["queues"]["discovery"]["depth"]
        assert depth <= 6, "bound must hold under sustained overload"
    # System reached steady state: work was both drained and refused.
    assert drained > 0 and rejected > 0
    final = g.stats()["queues"]["discovery"]
    assert final["drained"] == drained
    assert final["rejections"] == rejected


def test_approval_never_starves_behind_bulk_discovery(clock):
    """SLA aging: an overdue approval class always drains first."""
    g = _governor(clock)
    for i in range(10):
        g.offer("discovery", f"bulk-{i}")
    clock.advance(0.5)
    g.offer("approvals", "approval-urgent")
    clock.advance(5)  # approval now 5s old vs SLA 2s; bulk items are older though
    # Bulk head is ~5.5s old with NO sla → overdue=0; approval is overdue by 3.
    picked = None
    results = [g.take_any() for _ in range(11)]
    picked = [r for r in results if r and r[0] == "approvals"]
    assert len(picked) == 1
    assert picked[0][1] == "approval-urgent"
    # The approval was among the FIRST items taken despite bulk being older.
    first_three = [r for r in results if r][:3]
    assert "approvals" in {r[0] for r in first_three}


def test_weight_breaks_ties_among_non_overdue_classes(clock):
    g = BackPressureGovernor(
        [
            ClassPolicy(
                name="a", max_size=5, high_water=5, policy=OverflowPolicy.REJECT_REQUEUE, weight=1.0
            ),
            ClassPolicy(
                name="b", max_size=5, high_water=5, policy=OverflowPolicy.REJECT_REQUEUE, weight=9.0
            ),
        ],
        clock=clock,
    )
    g.offer("a", "task-a")
    g.offer("b", "task-b")
    first = g.take_any()
    assert first[0] == "b"  # higher weight wins when neither is overdue


def test_block_producer_policy_for_critical_class(clock):
    g = _governor(clock, crit_max=1)
    assert g.offer("approvals", "c1") is None
    # Full + BLOCK_PRODUCER: raises after timeout rather than dropping.
    with pytest.raises(QueueFull):
        g.offer("approvals", "c2", timeout=0.05)


def test_slow_consumer_detection_and_bounded_lag(clock):
    g = _governor(clock)
    assert g.record_consumer_lag("ui-1", 50) == "healthy"
    assert g.consumer_state("ui-1") == "healthy"
    # Consumer falls behind badly: flagged slow so event stream coalesces.
    assert g.record_consumer_lag("ui-1", 1500) == "slow"
    assert g.consumer_state("ui-1") == "slow"
    # Recovery path: lag drops back under threshold.
    assert g.record_consumer_lag("ui-1", 100) == "healthy"


def test_stats_export_metrics_shape(clock):
    g = _governor(clock)
    g.offer("discovery", "t1")
    clock.advance(2)
    s = g.stats()
    d = s["queues"]["discovery"]
    assert set(d) == {"depth", "oldest_task_age", "high_water", "max_size", "rejections", "drained"}
    assert d["depth"] == 1
    assert d["oldest_task_age"] == pytest.approx(2.0)
    assert "total_rejections" in s and "consumers" in s


def test_unknown_queue_and_empty_policies_rejected():
    clock = FakeClock()
    g = _governor(clock)
    with pytest.raises(KeyError):
        g.offer("nope", "t")
    with pytest.raises(ValueError):
        BackPressureGovernor([], clock=clock)
