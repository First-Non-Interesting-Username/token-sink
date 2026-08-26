"""Tests for per-target health & politeness tracking (issue #116)."""

from __future__ import annotations

import pytest

from policy.engine import PolicyEngine, ScopeStatus, ToolCallRequest
from policy.scope import ScopePolicy, TargetSpec
from policy.ssrf import SSRFGuard
from policy.target_health import (
    DEGRADED_COOLDOWN_SECONDS,
    SUSPEND_AFTER_CONSECUTIVE,
    TargetHealthState,
    TargetHealthTracker,
)


class FakeClock:
    """Deterministic clock so cooldown/backoff tests don't sleep."""

    def __init__(self) -> None:
        self.t = 1_000_000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def make_scope() -> ScopePolicy:
    return ScopePolicy(
        campaign_uuid="camp-1",
        authorization_reference="https://example.test/authz/1",
        in_scope=[TargetSpec(value="https://target.example.test")],
        active_testing_enabled=True,
        allowed_test_classes={"vulnerability_scanning"},
        allowed_methods={"GET", "POST"},
    )


def active_request(target: str = "https://target.example.test/app") -> ToolCallRequest:
    return ToolCallRequest(
        tool="http_probe",
        agent_uuid="agent-1",
        campaign_uuid="camp-1",
        target=target,
        method="GET",
        test_class="vulnerability_scanning",
    )


def feed_hard_signals(tracker: TargetHealthTracker, n: int = SUSPEND_AFTER_CONSECUTIVE):
    for _ in range(n):
        tracker.record_result("https://target.example.test", ok=False, status_code=429)


def test_healthy_target_allows_active_calls():
    tracker = TargetHealthTracker()
    assert tracker.check_active_allowed("https://t.example")[0] is True


def test_consecutive_429s_suspend_target():
    tracker = TargetHealthTracker()
    key = "https://target.example.test"
    state = TargetHealthState.HEALTHY
    for _ in range(SUSPEND_AFTER_CONSECUTIVE - 1):
        state = tracker.record_result(key, ok=False, status_code=429)
    # Below threshold: still healthy (a couple of 429s alone isn't distress).
    assert state is TargetHealthState.HEALTHY
    state = tracker.record_result(key, ok=False, status_code=429)
    assert state is TargetHealthState.SUSPENDED
    allowed, reason = tracker.check_active_allowed(key)
    assert allowed is False
    assert "SUSPENDED" in reason


def test_connection_reset_counts_as_hard_signal():
    tracker = TargetHealthTracker()
    key = "k"
    for _ in range(SUSPEND_AFTER_CONSECUTIVE):
        tracker.record_result(key, ok=False, connection_reset=True)
    assert tracker.stats(key).state is TargetHealthState.SUSPENDED


def test_error_spike_degrades_then_auto_recovers_after_cooldown():
    clock = FakeClock()
    tracker = TargetHealthTracker(clock=clock)
    key = "https://t.example"
    # 9 errors / 10 requests inside the window -> error-rate distress.
    for i in range(10):
        clock.advance(0.1)
        tracker.record_result(key, ok=(i == 0), status_code=500 if i else 200)
    st = tracker.stats(key)
    assert st.state is TargetHealthState.DEGRADED
    allowed, reason = tracker.check_active_allowed(key)
    assert allowed is False
    assert "DEGRADED" in reason

    clock.advance(DEGRADED_COOLDOWN_SECONDS + 1)
    allowed, reason = tracker.check_active_allowed(key)
    assert allowed is True
    assert "recovered" in reason


def test_isolated_errors_do_not_trigger_distress():
    tracker = TargetHealthTracker()
    key = "https://t.example"
    for i in range(20):
        tracker.record_result(key, ok=(i % 5 != 0), status_code=404 if i % 5 == 0 else 200)
    assert tracker.stats(key).state is TargetHealthState.HEALTHY


def test_success_resets_consecutive_hard_signal_counter():
    clock = FakeClock()
    tracker = TargetHealthTracker(clock=clock)
    key = "https://t.example"
    tracker.record_result(key, ok=False, status_code=429)
    tracker.record_result(key, ok=False, status_code=429)
    clock.advance(61)  # window rolls over; then a success resets the streak
    tracker.record_result(key, ok=True, status_code=200)
    assert tracker.stats(key).consecutive_hard_signals == 0


def test_suspended_requires_human_resume():
    tracker = TargetHealthTracker()
    key = "https://target.example.test"
    feed_hard_signals(tracker)
    # Time passing must NOT auto-recover a suspended target.
    allowed, _ = tracker.check_active_allowed(key)
    assert allowed is False
    state = tracker.resume(key, approved_by="operator-1")
    assert state is TargetHealthState.HEALTHY
    allowed, _ = tracker.check_active_allowed(key)
    assert allowed is True


def test_state_transitions_emit_events():
    events: list[tuple[str | None, str, dict]] = []
    tracker = TargetHealthTracker(event_sink=lambda c, t, p: events.append((c, t, p)))
    feed_hard_signals(tracker)
    transitions = [e for e in events if e[1] == "target_health.transition"]
    assert len(transitions) == 1
    _, _, payload = transitions[0]
    assert payload["to"] == "suspended"
    assert payload["target"] == "https://target.example.test"


def test_summary_shape():
    tracker = TargetHealthTracker()
    tracker.record_result("https://t.example", ok=True, status_code=200)
    s = tracker.summary()["https://t.example"]
    assert s["state"] == "healthy"
    assert s["window_requests"] == 1
    assert s["total_requests"] == 1


# --- robots.txt politeness hooks (#116) -------------------------------


def test_robots_policy_recording_and_lookup():
    tracker = TargetHealthTracker()
    key = "https://t.example"
    tracker.set_robots_policy(key, disallow=["/admin", "/private"])
    assert tracker.robots_disallows("/admin/panel", key) is True
    assert tracker.robots_disallows("/adminX", key) is False  # prefix must be path-honest
    assert tracker.robots_disallows("/public", key) is False
    assert tracker.summary()[key]["robots_checked"] is True


def test_unchecked_robots_never_blocks():
    tracker = TargetHealthTracker()
    assert tracker.robots_disallows("/anything", "https://x.example") is False


# --- Safety: suspended target blocks ACTIVE calls at the policy layer --


def make_engine() -> PolicyEngine:
    # Hermetic SSRF guard: no real DNS in tests.
    return PolicyEngine(
        scope=make_scope(),
        ssrf_guard=SSRFGuard(resolver=lambda host: ["93.184.216.34"]),
    )


@pytest.mark.safety
def test_suspended_target_rejects_active_calls_despite_matching_scope():
    """The #116 safety invariant: even with a fully matching allowlist, a
    suspended target rejects every active tool call."""
    engine = make_engine()
    request = active_request()
    # Baseline: allowed while healthy.
    decision = engine.evaluate(request)
    assert decision.allowed is True

    # Distress the target to suspension.
    key = "https://target.example.test"
    feed_hard_signals(engine.target_health)

    decision = engine.evaluate(request)
    assert decision.allowed is False
    assert "target_health_blocked" in decision.violations
    assert "SUSPENDED" in decision.explanation

    # Human resume restores access.
    engine.target_health.resume(key, approved_by="op")
    assert engine.evaluate(request).allowed is True


@pytest.mark.safety
def test_degraded_target_rejects_active_but_readonly_recon_stays_available():
    engine = make_engine()
    key = "https://target.example.test"
    for i in range(10):
        engine.target_health.record_result(key, ok=(i == 0), status_code=503 if i else 200)
    assert engine.target_health.stats(key).state is TargetHealthState.DEGRADED

    blocked = engine.evaluate(active_request())
    assert blocked.allowed is False

    recon = ToolCallRequest(
        tool="fetch_page",
        agent_uuid="agent-1",
        campaign_uuid="camp-1",
        target=key + "/status",
        method="GET",
        test_class="reconnaissance",
    )
    assert engine.evaluate(recon).allowed is True


def test_engine_works_without_explicit_tracker():
    """Backward compatibility: no tracker passed -> one is created internally."""
    engine = PolicyEngine(scope=None)
    assert isinstance(engine.target_health, TargetHealthTracker)
    assert engine.scope_status is ScopeStatus.MISSING
