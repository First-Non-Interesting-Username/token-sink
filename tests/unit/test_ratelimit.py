"""Tests for the rate-limiting subsystem (issue #80, PLAN §2, §5, §7.3)."""

from __future__ import annotations

import threading
import time

import pytest

from policy.engine import PolicyEngine, ToolCallRequest
from policy.ratelimit import LimitSpec, RateLimiter
from policy.scope import RateLimit, ScopePolicy, TargetSpec


def make_scope(**kw) -> ScopePolicy:
    defaults: dict = dict(
        campaign_uuid="camp-1",
        authorization_reference="https://example.com/auth",
        in_scope=[TargetSpec(value="example.com")],
    )
    defaults.update(kw)
    return ScopePolicy(**defaults)


def req(campaign="camp-1", target="https://example.com/x", **kw) -> ToolCallRequest:
    return ToolCallRequest(
        tool="http_get",
        agent_uuid="agent-1",
        campaign_uuid=campaign,
        target=target,
        **kw,
    )


# ---------------------------------------------------------------- limiter --


def test_burst_over_limit_is_refused_with_dimension():
    rl = RateLimiter()
    rl.set_limit("target", "example.com", LimitSpec(max_requests=3, per_seconds=60))
    for _ in range(3):
        assert rl.acquire(target="https://example.com/a").allowed
    refused = rl.acquire(target="https://example.com/b")
    assert not refused.allowed
    assert refused.limiting_dimension == "target"
    assert refused.retry_after_seconds > 0


def test_window_slides():
    rl = RateLimiter()
    rl.set_limit("endpoint", "api://x", LimitSpec(max_requests=1, per_seconds=0.2))
    assert rl.acquire(endpoint="api://x").allowed
    assert not rl.acquire(endpoint="api://x").allowed
    time.sleep(0.25)
    assert rl.acquire(endpoint="api://x").allowed


def test_per_dimension_isolation_hot_campaign_cannot_starve_another():
    """A hot campaign exhausts its own campaign budget but NOT another
    campaign's — the refusing dimension must be 'campaign'."""
    rl = RateLimiter()
    rl.set_limit("campaign", "hot", LimitSpec(max_requests=2, per_seconds=60))
    rl.set_limit("campaign", "quiet", LimitSpec(max_requests=2, per_seconds=60))
    rl.set_limit("global", "global", LimitSpec(max_requests=100, per_seconds=60))
    for _ in range(2):
        assert rl.acquire(campaign_uuid="hot").allowed
    refused = rl.acquire(campaign_uuid="hot")
    assert not refused.allowed and refused.limiting_dimension == "campaign"
    # The other campaign still has room.
    assert rl.acquire(campaign_uuid="quiet").allowed


def test_global_budget_shared_across_campaigns():
    rl = RateLimiter()
    rl.set_limit("global", "global", LimitSpec(max_requests=2, per_seconds=60))
    assert rl.acquire(campaign_uuid="a").allowed
    assert rl.acquire(campaign_uuid="b").allowed
    refused = rl.acquire(campaign_uuid="c")
    assert not refused.allowed and refused.limiting_dimension == "global"


def test_unlimited_when_no_configured_limits():
    rl = RateLimiter()
    for _ in range(50):
        assert rl.acquire(target="https://anywhere.example/").allowed


def test_usage_snapshot_reports_used_vs_limit():
    rl = RateLimiter()
    rl.set_limit("target", "example.com", LimitSpec(max_requests=5, per_seconds=60))
    rl.acquire(target="https://example.com/")
    rl.acquire(target="https://example.com/other")
    snap = rl.usage()
    entry = snap["target"]["example.com"]
    assert entry["used"] == 2
    assert entry["limit"] == 5


def test_wait_blocks_until_slot_frees():
    rl = RateLimiter()
    rl.set_limit("target", "example.com", LimitSpec(max_requests=1, per_seconds=0.15))
    assert rl.acquire(target="https://example.com/").allowed
    start = time.monotonic()
    assert rl.wait(target="https://example.com/", timeout=2)
    assert time.monotonic() - start >= 0.1
    # Timeout path degrades instead of exceeding.
    assert not rl.wait(target="https://example.com/", timeout=0)


def test_concurrent_callers_never_exceed_limit():
    rl = RateLimiter()
    limit = 10
    rl.set_limit("global", "global", LimitSpec(max_requests=limit, per_seconds=60))

    admitted = []
    lock = threading.Lock()

    def worker():
        res = rl.acquire(campaign_uuid=f"c{threading.get_ident()}")
        if res.allowed:
            with lock:
                admitted.append(1)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(admitted) == limit  # never more than the budget admits


# ------------------------------------------------------------ engine gate --


def test_engine_blocks_at_target_rate_limit_from_scope_config():
    scope = make_scope(
        rate_limits={"target:example.com": RateLimit(max_requests=2, per_seconds=60)}
    )
    engine = PolicyEngine(scope)
    assert engine.evaluate(req()).allowed
    assert engine.evaluate(req(target="https://example.com/y")).allowed
    decision = engine.evaluate(req(target="https://example.com/z"))
    assert not decision.allowed
    assert "rate_limited:target" in decision.violations
    # Blocked events carry the limiting dimension for observability (§14).
    events = engine.blocked_events()
    assert any("rate limit exceeded" in e.reason for e in events.values())


def test_engine_gate_runs_after_safety_checks():
    """Rate limiting consumes budget, so a request that would be blocked for
    scope reasons must NOT consume a rate-limit slot."""
    scope = make_scope(
        rate_limits={"target:example.com": RateLimit(max_requests=1, per_seconds=60)}
    )
    engine = PolicyEngine(scope)
    # Out-of-scope request is refused on scope grounds...
    out = engine.evaluate(req(target="https://elsewhere.org/"))
    assert not out.allowed
    assert "target_unlisted" in out.violations
    # ...and the single target slot is still available for an in-scope one.
    assert engine.evaluate(req()).allowed


def test_engine_endpoint_dimension_via_metadata():
    scope = make_scope(
        rate_limits={"endpoint:llm://prov": RateLimit(max_requests=1, per_seconds=60)}
    )
    engine = PolicyEngine(scope)
    r1 = req()
    r1.metadata["endpoint"] = "llm://prov"
    r2 = req()
    r2.metadata["endpoint"] = "llm://prov"
    assert engine.evaluate(r1).allowed
    d = engine.evaluate(r2)
    assert not d.allowed
    assert "rate_limited:endpoint" in d.violations


def test_shared_limiter_across_engines_counts_together():
    """Two engines sharing one limiter instance (process-wide authority) see
    each other's consumption — limits hold even across engine instances."""
    shared = RateLimiter()
    scope = make_scope(rate_limits={"campaign:camp-1": RateLimit(max_requests=2, per_seconds=60)})
    e1 = PolicyEngine(scope, rate_limiter=shared)
    e2 = PolicyEngine(scope, rate_limiter=shared)
    assert e1.evaluate(req()).allowed
    assert e2.evaluate(req()).allowed
    d = e1.evaluate(req())
    assert not d.allowed
    assert "rate_limited:campaign" in d.violations


@pytest.mark.parametrize(
    "cfg,key",
    [
        ({"target:example.com": RateLimit(1, 60)}, "rate_limited:target"),
        ({"campaign:camp-1": RateLimit(1, 60)}, "rate_limited:campaign"),
    ],
)
def test_scope_config_keys_map_to_dimensions(cfg, key):
    engine = PolicyEngine(make_scope(rate_limits=cfg))
    assert engine.evaluate(req()).allowed
    assert key in engine.evaluate(req()).violations
