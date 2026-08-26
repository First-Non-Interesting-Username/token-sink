"""Unit tests for provider circuit breakers (issue #83, PLAN §7.3/§8.1)."""

from __future__ import annotations

import pytest

from providers.breakers import (
    BreakerConfig,
    BreakerState,
    CircuitBreaker,
    cooldown_from_retry_after,
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, s: float) -> None:
        self.now += s


def breaker(**cfg) -> tuple[CircuitBreaker, FakeClock]:
    clock = FakeClock()
    b = CircuitBreaker("prov", "model", BreakerConfig(**cfg), clock)
    return b, clock


# ------------------------------------------------------------ transitions --


def test_starts_closed_and_available():
    b, _ = breaker()
    assert b.effective_state() is BreakerState.CLOSED
    ok, _ = b.availability()
    assert ok


def test_trips_after_consecutive_failures():
    b, _ = breaker(failure_threshold=3)
    for _ in range(2):
        assert b.record_failure() == 0.0
    assert b.record_failure() > 0.0  # trips with a positive cooldown
    assert b.effective_state() is BreakerState.OPEN
    ok, reason = b.availability()
    assert not ok and "breaker open" in reason


def test_success_resets_consecutive_counter():
    b, _ = breaker(failure_threshold=3)
    b.record_failure()
    b.record_failure()
    b.record_success()
    b.record_failure()
    b.record_failure()
    # only 2 consecutive failures since the success: still closed
    assert b.effective_state() is BreakerState.CLOSED


def test_error_rate_trips_independent_of_consecutive():
    # failures interleaved with successes never hit the consecutive threshold,
    # but the rolling ERROR rate exceeds 50% after enough samples.
    b, _ = breaker(failure_threshold=99, min_samples=4, error_rate_threshold=0.5, window_size=20)
    for _ in range(10):
        b.record_failure()
        b.record_failure()  # 2 failures per 3 samples → error rate ≈ 67% > threshold
    assert b.record_failure() > 0.0
    assert b.effective_state() is BreakerState.OPEN


def test_exactly_at_error_rate_threshold_does_not_trip():
    # 50% errors with threshold 0.5 must NOT trip: threshold is exclusive.
    b, _ = breaker(failure_threshold=99, min_samples=4, error_rate_threshold=0.5, window_size=20)
    for _ in range(10):
        b.record_success()
        b.record_failure()  # window: exactly half failures, never more
    assert b.effective_state() is BreakerState.CLOSED
    # and one more failure pushes strictly past the threshold:
    assert b.record_failure() > 0.0
    assert b.effective_state() is BreakerState.OPEN


def test_low_sample_count_does_not_trip_on_error_rate():
    b, _ = breaker(failure_threshold=99, min_samples=10, error_rate_threshold=0.5)
    for _ in range(4):
        b.record_failure()
    assert b.effective_state() is BreakerState.CLOSED


def test_open_becomes_half_open_after_cooldown_expires():
    b, clock = breaker(open_cooldown=30.0, failure_threshold=1)
    b.record_failure()
    clock.advance(10)
    ok, _ = b.availability()
    assert not ok  # still cooling down
    clock.advance(21)  # past cooldown_until
    assert b.effective_state() is BreakerState.HALF_OPEN
    ok, reason = b.availability()
    assert ok and "probe" in reason


def test_half_open_success_closes_breaker():
    b, clock = breaker(open_cooldown=30.0, failure_threshold=1)
    b.record_failure()
    clock.advance(31)
    b.allow_probe()
    b.record_success()
    assert b.effective_state() is BreakerState.CLOSED
    ok, _ = b.availability()
    assert ok


def test_half_open_failure_reopens_with_fresh_cooldown():
    from providers.breakers import BreakerRegistry

    clock = FakeClock()
    reg = BreakerRegistry(
        config=BreakerConfig(open_cooldown=30.0, failure_threshold=1), clock=clock
    )
    reg.record_failure("p", "m")
    first_until = reg.breakers["p/m"].snapshot().cooldown_until
    clock.advance(31)
    reg.breakers["p/m"].allow_probe()
    cd = reg.record_failure("p", "m")  # failed probe re-opens
    assert cd == 30.0
    fresh_state = reg.breakers["p/m"]
    assert fresh_state.effective_state() is BreakerState.OPEN
    assert fresh_state.snapshot().cooldown_until >= first_until + 30.0


def test_half_open_probe_budget_is_enforced():
    b, clock = breaker(open_cooldown=30.0, failure_threshold=1, half_open_max_probes=1)
    b.record_failure()
    clock.advance(31)
    assert b.allow_probe() is True
    ok, reason = b.availability()
    assert not ok and "probe budget" in reason
    assert b.allow_probe() is False


# ------------------------------------------------------------- failover ----


def test_failover_into_open_breaker_is_excluded():
    """§7.3: candidates over an open breaker are excluded, not retried."""
    from providers.breakers import BreakerRegistry
    from routers.decision_log import CandidatePlan

    reg = BreakerRegistry(clock=FakeClock(), config=BreakerConfig(failure_threshold=1))
    reg.record_failure("provA", "m1")  # trips provA/m1

    plans = [
        CandidatePlan(
            router_id="r",
            provider="provA",
            model="m1",
            rationale="",
            confidence=0.9,
            expected_cost=0.0,
            fallbacks=[{"provider": "provB", "model": "m2"}],
        ),
        CandidatePlan(
            router_id="r",
            provider="provB",
            model="m2",
            rationale="",
            confidence=0.8,
            expected_cost=0.0,
        ),
    ]
    routable, blocked = reg.filter_plans(plans)
    assert [p.model for p in routable] == ["m2"]
    assert len(blocked) == 1 and blocked[0][0] == "provA"
    assert any(e.provider == "provA" for e in reg.events), "exclusion must be recorded"


# ---------------------------------------------------------------- quota ----


def test_retry_after_derives_quota_cooldown():
    cfg = BreakerConfig(quota_cooldown=60.0)
    assert cooldown_from_retry_after(None, cfg) == 60.0
    assert cooldown_from_retry_after(0, cfg) == 60.0
    assert cooldown_from_retry_after(12.0, cfg) == 12.0


def test_quota_failure_uses_retry_after_for_cooldown():
    b, clock = breaker(failure_threshold=1, open_cooldown=30.0, quota_cooldown=60.0)
    cd = b.record_failure(retry_after=45.0)
    assert cd == 45.0
    clock.advance(46)
    assert b.effective_state() is BreakerState.HALF_OPEN


# ------------------------------------------------------- health / restart --


def test_unhealthy_health_flag_excludes_even_with_closed_breaker():
    from providers.breakers import BreakerRegistry
    from routers.decision_log import CandidatePlan

    reg = BreakerRegistry()
    reg.mark_unhealthy("p", "m")
    plan = CandidatePlan(
        router_id="r",
        provider="p",
        model="m",
        rationale="",
        confidence=0.9,
        expected_cost=0.0,
    )
    routable, blocked = reg.filter_plans([plan])
    assert not routable
    assert "health" in blocked[0][2]


def test_mark_healthy_restores_eligibility():
    from providers.breakers import BreakerRegistry

    reg = BreakerRegistry()
    reg.mark_unhealthy("p", "m")
    ok, _ = reg.eligibility("p", "m")
    assert not ok
    reg.mark_healthy("p", "m")
    ok, _ = reg.eligibility("p", "m")
    assert ok


def test_persisted_state_survives_restart():
    """Restart must NOT slam a failing provider: open state restores as open."""
    from providers.breakers import BreakerRegistry

    clock = FakeClock()
    reg = BreakerRegistry(
        config=BreakerConfig(failure_threshold=1, open_cooldown=120.0), clock=clock
    )
    reg.record_failure("p", "m")
    dumped = reg.dump_state()

    fresh = BreakerRegistry(config=BreakerConfig(failure_threshold=1), clock=FakeClock())
    assert fresh.restore_state(dumped) == 1
    ok, reason = fresh.eligibility("p", "m")
    assert not ok and "cooldown" in reason


def test_storage_roundtrip_via_sqlite(tmp_path):
    from providers.breakers import RECORD_KIND, BreakerRegistry
    from storage.sqlite import SQLiteStorage

    st = SQLiteStorage(tmp_path / "db.sqlite", tmp_path / "artifacts")
    st.migrate()

    clock = FakeClock()
    reg = BreakerRegistry(
        config=BreakerConfig(failure_threshold=1, open_cooldown=90.0), clock=clock
    )
    reg.record_failure("p", "m")
    reg.save(st)

    fresh = BreakerRegistry(clock=FakeClock())
    assert fresh.load(st) >= 1
    ok, reason = fresh.eligibility("p", "m")
    assert not ok and "cooldown" in reason

    rec = st.get_record(RECORD_KIND, "p:m")
    assert rec is not None and rec["data"]["state"] == "open"


@pytest.mark.parametrize("bad", [{}, {"state": "bogus"}, {"provider": "x"}, "not-a-dict"])
def test_restore_skips_malformed_entries(bad):
    """Corrupt entries are skipped; valid entries still restore."""
    from providers.breakers import BreakerRegistry

    reg = BreakerRegistry()
    saved = {"p/m": {"provider": "p", "model": "m"}, "malformed-key-no-slash": bad}
    assert reg.restore_state(saved) == 1
    ok, reason = reg.eligibility("p", "m")
    assert ok
