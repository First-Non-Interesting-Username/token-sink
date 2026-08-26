"""Load-test harness (PLAN §19.5, issue #251).

Drives concurrency/throughput pressure the unit suites never exercise:

- Many parallel router workers making routing decisions against mock
  providers.
- Concurrent agents claiming findings under lease contention.
- The shared rate limiter under sustained pressure near its budget —
  verifying limits HOLD (no over-admission) and backoff engages.
- Event-store write/read throughput.

Run explicitly, never in default CI::

    uv run pytest -m load tests/load/ -q

Each scenario returns a summary dict (throughput, latency quantiles,
error/admission counts) that the pytest assertions check for *correctness
under load* (limits hold, no lost events), not raw speed.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

import pytest

from findings.lifecycle import FindingLifecycle, RecordStore
from observability.event_store import EventStore
from policy.ratelimit import LimitSpec, RateLimiter

pytestmark = pytest.mark.load


@dataclass
class LoadSummary:
    """Result metrics of one load scenario."""

    name: str
    workers: int
    operations: int
    wall_seconds: float
    errors: int = 0
    rejected: int = 0
    latencies_ms: list[float] = field(default_factory=list)

    @property
    def throughput(self) -> float:
        return self.operations / self.wall_seconds if self.wall_seconds else 0.0

    def p(self, q: float) -> float:
        if not self.latencies_ms:
            return 0.0
        vs = sorted(self.latencies_ms)
        import math

        return vs[max(math.ceil(q * len(vs)) - 1, 0)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "workers": self.workers,
            "operations": self.operations,
            "throughput_per_s": round(self.throughput, 1),
            "errors": self.errors,
            "rejected": self.rejected,
            "p50_ms": round(self.p(0.50), 2),
            "p95_ms": round(self.p(0.95), 2),
        }


def _run_parallel(
    workers: int,
    per_worker: int,
    fn: Callable[[int, int], None],
) -> tuple[int, list[float], int]:
    """Run fn(worker_id, op_id) in parallel; return (errors, latencies, rejects)."""
    errors = 0
    rejected = 0
    latencies: list[float] = []
    lock = threading.Lock()

    def one(worker_id: int) -> None:
        nonlocal errors, rejected
        for op in range(per_worker):
            t0 = time.perf_counter()
            try:
                outcome = fn(worker_id, op)
            except Exception:  # noqa: BLE001 — any failure counts as a load error
                with lock:
                    errors += 1
                continue
            dt_ms = (time.perf_counter() - t0) * 1000
            with lock:
                latencies.append(dt_ms)
                if outcome is False:  # convention: False == admission rejected
                    rejected += 1

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(one, range(workers)))
    return errors, latencies, rejected


def scenario_router_workers(workers: int = 8, per_worker: int = 25) -> LoadSummary:
    """Parallel routing decisions against a mock provider decision path."""
    from routers.decision_log import CandidatePlan, DecisionLog

    log = DecisionLog()

    def decide(worker_id: int, op: int) -> bool:
        plan = CandidatePlan(
            router_id=f"router-{worker_id}",
            provider="mock",
            model="mock-1",
            rationale="loadtest",
            confidence=0.5,
            expected_cost=0.0,
        )
        log.record(
            task_snapshot={"task": f"t-{op}"},
            task_ref=f"t-{worker_id}-{op}",
            model_catalog_version="loadtest",
            input_signals={},
            candidate_plans=[plan],
            merge_policy="fastest",
            final_selection={"provider": "mock", "model": "mock-1"},
        )
        return True

    t0 = time.perf_counter()
    errors, latencies, rejected = _run_parallel(workers, per_worker, decide)
    return LoadSummary(
        "router_workers",
        workers,
        workers * per_worker,
        time.perf_counter() - t0,
        errors,
        rejected,
        latencies,
    )


def scenario_lease_contention(workers: int = 8, per_worker: int = 10) -> LoadSummary:
    """Concurrent agents competing to claim findings under lease contention."""
    lifecycle = FindingLifecycle(RecordStore())
    finding_uuids = []
    # Submit a fixed pool of findings to contend over.
    for i in range(workers):
        r = lifecycle.submit_finding("camp-load", "discoverer", {"title": f"finding-{i}"})
        finding_uuids.append(r.finding.finding_uuid)
    expires = "2099-01-01T00:00:00+00:00"
    claimed: set[str] = set()
    lock = threading.Lock()
    double_claims = 0

    def claim(worker_id: int, op: int) -> bool:
        nonlocal double_claims
        target = finding_uuids[(worker_id + op) % len(finding_uuids)]
        try:
            lifecycle.claim_for_review(target, f"agent-{worker_id}", expires)
        except Exception:  # noqa: BLE001 — already-leased is the expected loss
            return False
        with lock:
            if target in claimed:
                double_claims += 1
            claimed.add(target)
        return True

    t0 = time.perf_counter()
    errors, latencies, rejected = _run_parallel(workers, per_worker, claim)
    assert double_claims == 0, "lease invariant broken under contention"
    return LoadSummary(
        "lease_contention",
        workers,
        workers * per_worker,
        time.perf_counter() - t0,
        errors,
        rejected,
        latencies,
    )


def scenario_rate_limit_pressure(
    rate: int = 20, workers: int = 8, per_worker: int = 30
) -> LoadSummary:
    """Sustained pressure near the budget: limits must HOLD, backoff engage."""
    limiter = RateLimiter()
    spec = LimitSpec(max_requests=rate, per_seconds=1.0)
    limiter.configure_from_scope(type("S", (), {"rate_limits": {"campaign:camp-load": spec}})())

    def hammer(worker_id: int, op: int) -> bool:
        return limiter.acquire(campaign_uuid="camp-load").allowed

    t0 = time.perf_counter()
    errors, latencies, rejected = _run_parallel(workers, per_worker, hammer)
    elapsed = max(time.perf_counter() - t0, 1e-6)
    total_admitted = workers * per_worker - rejected
    # Correctness under load: admitted count must never exceed capacity×time.
    capacity = rate * elapsed + rate  # one window of slack
    assert total_admitted <= capacity, f"over-admission: {total_admitted} > {capacity:.0f}"
    assert rejected > 0, "backoff never engaged under sustained over-budget pressure"
    return LoadSummary(
        "rate_limit_pressure", workers, workers * per_worker, elapsed, errors, rejected, latencies
    )


def scenario_event_throughput(workers: int = 6, per_worker: int = 100) -> LoadSummary:
    """Event-store append/replay throughput with a no-lost-events check."""
    store = EventStore()

    def emit(worker_id: int, op: int) -> bool:
        store.append("load", {"w": worker_id, "op": op})
        return True

    t0 = time.perf_counter()
    errors, latencies, rejected = _run_parallel(workers, per_worker, emit)
    replayed = store.replay_after(-1)
    total = len(replayed.events)
    assert total == workers * per_worker, "lost events under concurrent append"
    return LoadSummary(
        "event_throughput",
        workers,
        workers * per_worker,
        time.perf_counter() - t0,
        errors,
        rejected,
        latencies,
    )


SCENARIOS = {
    "router_workers": scenario_router_workers,
    "lease_contention": scenario_lease_contention,
    "rate_limit_pressure": scenario_rate_limit_pressure,
    "event_throughput": scenario_event_throughput,
}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_load_scenario(name: str) -> None:
    summary = SCENARIOS[name]()
    print(f"\nLOAD {summary.to_dict()}")  # visible with -ra/-s
    assert summary.errors == 0, f"{name}: {summary.errors} operation errors under load"


if __name__ == "__main__":
    for fn in SCENARIOS.values():
        print(fn().to_dict())
