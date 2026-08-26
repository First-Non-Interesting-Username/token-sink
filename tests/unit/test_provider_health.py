"""Tests for provider health checks (issue #102, PLAN §8.1)."""

import pytest

from observability.event_store import EventStore
from providers.health import (
    EVENT_TYPE,
    STATE_COOLING_DOWN,
    STATE_DEGRADED,
    STATE_EXCLUDED,
    STATE_HEALTHY,
    KillSwitchActive,
    ProviderHealthMonitor,
    QuotaSnapshot,
)


class FakeProbe:
    """Scripted probe: pops responses; a callable response is invoked."""

    def __init__(self, script):
        self.script = list(script)

    def check(self):
        item = self.script.pop(0) if self.script else (False, 9.9, None)
        if callable(item):
            return item()
        return item


@pytest.fixture()
def events():
    return EventStore()


def _monitor(probes, events, **kw):
    # Deterministic clock: each _now() call advances 0.1s.
    t = {"v": 1000.0}

    def now():
        t["v"] += 0.1
        return t["v"]

    return ProviderHealthMonitor(probes, events, now=now, **kw)


def test_new_provider_starts_healthy(events):
    m = _monitor({"p": FakeProbe([])}, events)
    assert m.snapshot("p").state == STATE_HEALTHY
    assert m.routable("p")


def test_failed_probe_excludes_after_threshold(events):
    m = _monitor(
        {"p": FakeProbe([(False, 1.0, None)] * 5)},
        events,
        degraded_after_failures=1,
        exclude_after_failures=3,
    )
    m.run_probe("p")  # failure 1 -> cooling_down
    assert m.snapshot("p").state == STATE_COOLING_DOWN
    assert not m.routable("p")
    m.run_probe("p")  # failure 2
    m.run_probe("p")  # failure 3 -> excluded
    assert m.snapshot("p").state == STATE_EXCLUDED
    assert not m.routable("p")


def test_recovery_requires_consecutive_successes(events):
    m = _monitor(
        {
            "p": FakeProbe(
                [
                    (False, 1.0, None),  # -> cooling_down
                    (True, 0.2, None),  # success 1: still cooling down
                    (True, 0.2, None),  # success 2: recovers
                ]
            )
        },
        events,
        cooldown_successes_to_recover=2,
    )
    m.run_probe("p")
    assert m.snapshot("p").state == STATE_COOLING_DOWN
    m.run_probe("p")
    assert m.snapshot("p").state == STATE_COOLING_DOWN  # not yet
    m.run_probe("p")
    assert m.snapshot("p").state == STATE_HEALTHY


def test_slow_success_degrades_but_stays_routable(events):
    m = _monitor(
        {"p": FakeProbe([(True, 6.0, None), (True, 0.1, None)])}, events, latency_degrade_ms=5000
    )
    m.run_probe("p")
    assert m.snapshot("p").state == STATE_DEGRADED
    assert m.routable("p")  # degraded is still routable
    m.run_probe("p")
    assert m.snapshot("p").state == STATE_HEALTHY


def test_state_changes_emit_events(events):
    m = _monitor({"p": FakeProbe([(True, 0.1, None), (False, 1.0, None)])}, events)
    m.run_probe("p")  # healthy -> healthy: no event expected
    before = len(events.replay_after(0).events)
    m.run_probe("p")  # -> cooling_down: event expected
    result = events.replay_after(0)
    health_events = [e for e in result.events if e.type == EVENT_TYPE]
    assert len(health_events) >= before + 1 - before  # at least one exists
    last = health_events[-1]
    assert last.payload["provider"] == "p"
    assert last.payload["from"] == STATE_HEALTHY
    assert last.payload["to"] == STATE_COOLING_DOWN


def test_quota_snapshot_recorded_and_exposed(events):
    quota = QuotaSnapshot(provider="p", requests_used=7, requests_limit=10, reset_at=123.0)
    probe = FakeProbe([(True, 0.3, quota)])
    m = _monitor({"p": probe}, events)
    r = m.run_probe("p")
    assert r.quota is quota
    assert m.snapshot("p").quota.requests_limit == 10
    assert m.snapshot("p").quota.remaining_requests == 3
    page = m.status_page()
    assert page[0]["quota"]["requests_used"] == 7


def test_kill_switch_blocks_probes(events):
    m = _monitor({"p": FakeProbe([])}, events)
    with pytest.raises(KillSwitchActive):
        m.run_probe("p", kill_switch_active=True)
    # No state change or events happened while blocked.
    assert m.snapshot("p").last_probe_ts == 0.0


def test_probe_exception_treated_as_failure(events):
    def boom():
        raise RuntimeError("dns broken")

    m = _monitor({"p": FakeProbe([boom])}, events)
    m.run_probe("p")
    h = m.snapshot("p")
    assert h.state == STATE_COOLING_DOWN
    assert "RuntimeError" in h.last_error


def test_unknown_provider_rejected(events):
    m = _monitor({}, events)
    with pytest.raises(KeyError):
        m.run_probe("nope")


def test_status_page_shape(events):
    m = _monitor({"a": FakeProbe([(True, 0.4, None)])}, events)
    m.run_probe("a")
    rows = m.status_page()
    assert rows[0]["provider"] == "a"
    for key in ("state", "latency", "last_probe_ts", "consecutive_failures"):
        assert key in rows[0]


def test_history_bounded(events):
    m = _monitor({"p": FakeProbe([(True, 0.1, None)] * 30)}, events)
    for _ in range(30):
        m.run_probe("p")
    assert len(m.snapshot("p").history) <= 20


def test_invalid_thresholds_rejected(events):
    with pytest.raises(ValueError):
        ProviderHealthMonitor({}, events, degraded_after_failures=3, exclude_after_failures=2)
