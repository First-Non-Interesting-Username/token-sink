"""Tests for the router pool: failover, dead-letter, usage attribution."""
from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from mavr.providers.model_catalog.scores import ModelScoreStore
from mavr.providers.registry import ProviderRegistry
from mavr.routers.circuit_breaker import BreakerConfig, CircuitBreakerStore
from mavr.routers.dead_letter import DeadLetterQueue
from mavr.routers.pool import RouterPool
from mavr.routers.usage import UsageAccountant
from mavr.schemas.routing import (
    ChatMessage,
    ChatRequest,
    RoutingPolicy,
    RoutingTask,
    TaskCategory,
)
from mavr.storage.database import Database, apply_migrations
from mavr.tests._fakes import FlakyAdapter, MockAdapter


def _new_task_id() -> str:
    return str(uuid4())


def _make_task(provider_id: str | None = None, **kwargs) -> RoutingTask:
    return RoutingTask(
        task_id=_new_task_id(),
        category=kwargs.pop("category", TaskCategory.GENERIC),
        policy=kwargs.pop("policy", RoutingPolicy.BEST_SCORE),
        request=kwargs.pop(
            "request",
            ChatRequest(messages=[ChatMessage(role="user", content="hi")]),
        ),
        free_only=kwargs.pop("free_only", True),
        **kwargs,
    )


@pytest.mark.asyncio
async def test_router_pool_picks_top_scoring_model(tmp_path) -> None:
    db = Database(tmp_path / "phase4.db")
    await apply_migrations(db, "up")
    scores = ModelScoreStore(db)
    await scores.upsert(
        await _score_for("mock", "mock-review", TaskCategory.GENERIC, 0.9)
    )
    reg = ProviderRegistry([MockAdapter()])
    pool = RouterPool(
        registry=reg,
        scores=scores,
        breakers=CircuitBreakerStore(db, BreakerConfig()),
        usage=UsageAccountant(db),
        dead_letter=DeadLetterQueue(db),
        db=db,
    )
    task = _make_task()
    outcome = await pool.route_and_run(task)
    assert outcome.error is None
    assert outcome.response is not None
    assert outcome.response.content
    assert outcome.candidate_provider == "mock"
    assert outcome.decision.chosen is not None


@pytest.mark.asyncio
async def test_router_pool_dead_letters_when_no_candidates(tmp_path) -> None:
    """A free-only task with no free candidates must end up in dead-letter."""
    db = Database(tmp_path / "phase4.db")
    await apply_migrations(db, "up")
    reg = ProviderRegistry()  # empty registry
    pool = RouterPool(
        registry=reg,
        scores=ModelScoreStore(db),
        breakers=CircuitBreakerStore(db),
        usage=UsageAccountant(db),
        dead_letter=DeadLetterQueue(db),
        db=db,
    )
    task = _make_task()
    outcome = await pool.route_and_run(task)
    assert outcome.dead_lettered is True
    assert outcome.response is None
    rows = await db.fetchall("SELECT reason FROM dead_letter")
    assert rows and rows[0]["reason"] in {"no_candidates", "unroutable"}


@pytest.mark.asyncio
async def test_router_pool_records_provider_error_and_dead_letters(tmp_path) -> None:
    db = Database(tmp_path / "phase4.db")
    await apply_migrations(db, "up")
    reg = ProviderRegistry(
        [MockAdapter(responses={}, fail_on={"mock-review", "mock-discovery", "mock-polish"})]
    )
    pool = RouterPool(
        registry=reg,
        scores=ModelScoreStore(db),
        breakers=CircuitBreakerStore(db, BreakerConfig(failure_threshold=1)),
        usage=UsageAccountant(db),
        dead_letter=DeadLetterQueue(db),
        db=db,
    )
    task = _make_task()
    outcome = await pool.route_and_run(task)
    assert outcome.error is not None
    assert outcome.dead_lettered is True
    breaker_rows = await db.fetchall("SELECT state FROM circuit_breakers WHERE state='open'")
    assert breaker_rows, "expected an open circuit breaker after failure"


@pytest.mark.asyncio
async def test_router_pool_circuit_open_dead_letters(tmp_path) -> None:
    db = Database(tmp_path / "phase4.db")
    await apply_migrations(db, "up")
    reg = ProviderRegistry([MockAdapter()])
    breakers = CircuitBreakerStore(db, BreakerConfig(failure_threshold=1, cooldown_seconds=10))
    # pre-open the breaker for the only model
    await breakers.record_failure("mock", "mock-review", "synthetic")
    pool = RouterPool(
        registry=reg,
        scores=ModelScoreStore(db),
        breakers=breakers,
        usage=UsageAccountant(db),
        dead_letter=DeadLetterQueue(db),
        db=db,
    )
    task = _make_task()
    outcome = await pool.route_and_run(task)
    assert outcome.dead_lettered is True
    rows = await db.fetchall("SELECT reason FROM dead_letter WHERE reason='circuit_open'")
    assert rows


@pytest.mark.asyncio
async def test_router_pool_falls_back_after_flaky_failure(tmp_path) -> None:
    """A flaky adapter recovers; the breaker should let the call through.

    With a single flaky adapter and no fallback, the first call is a
    provider error and gets dead-lettered; the second call succeeds.
    """
    db = Database(tmp_path / "phase4.db")
    await apply_migrations(db, "up")
    reg = ProviderRegistry([FlakyAdapter(fail_first=1)])
    pool = RouterPool(
        registry=reg,
        scores=ModelScoreStore(db),
        breakers=CircuitBreakerStore(db, BreakerConfig(failure_threshold=1, cooldown_seconds=10)),
        usage=UsageAccountant(db),
        dead_letter=DeadLetterQueue(db),
        db=db,
    )
    # first call: flaky fails, dead-lettered
    out1 = await pool.route_and_run(_make_task())
    assert out1.dead_lettered is True
    # second call: flaky succeeds (no breaker should remain open for the
    # only model — but with threshold 1 the breaker opened on the first
    # failure, so we have to wait or override cooldown)
    # the breaker logic should now allow the call once cooldown has elapsed
    # simulate cooldown elapsed by resetting the breaker
    await db.execute(
        "UPDATE circuit_breakers SET state='half_open' WHERE provider_id='flaky'"
    )
    out2 = await pool.route_and_run(_make_task())
    # The flaky adapter returns success on the second call; the breaker
    # transitions to closed.
    assert out2.error is None
    assert out2.response is not None


@pytest.mark.asyncio
async def test_router_pool_records_usage(tmp_path) -> None:
    db = Database(tmp_path / "phase4.db")
    await apply_migrations(db, "up")
    reg = ProviderRegistry([MockAdapter()])
    pool = RouterPool(
        registry=reg,
        scores=ModelScoreStore(db),
        breakers=CircuitBreakerStore(db),
        usage=UsageAccountant(db),
        dead_letter=DeadLetterQueue(db),
        db=db,
    )
    out = await pool.route_and_run(_make_task())
    assert out.response is not None
    totals = await UsageAccountant(db).totals()
    assert totals["n"] >= 1
    assert totals["free_count"] >= 1
    assert totals["paid_count"] == 0
    # is_paid = False for free events
    rows = await db.fetchall("SELECT is_free, is_paid FROM usage_events")
    assert all(bool(r["is_free"]) and not bool(r["is_paid"]) for r in rows)


@pytest.mark.asyncio
async def test_router_pool_persists_decision(tmp_path) -> None:
    db = Database(tmp_path / "phase4.db")
    await apply_migrations(db, "up")
    reg = ProviderRegistry([MockAdapter()])
    pool = RouterPool(
        registry=reg,
        scores=ModelScoreStore(db),
        breakers=CircuitBreakerStore(db),
        usage=UsageAccountant(db),
        dead_letter=DeadLetterQueue(db),
        db=db,
    )
    # create a real task row so the FK is satisfied
    campaign_id = str(uuid4())
    task_id = _new_task_id()
    now = datetime.now(UTC).isoformat()
    import json

    await db.execute(
        "INSERT INTO campaigns(id, schema_version, name, target_spec, state, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (campaign_id, "1.0.0", "phase4-test", json.dumps({}), "active", now, now),
    )
    await db.execute(
        "INSERT INTO tasks(id, schema_version, campaign_id, kind, status, "
        "payload, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            task_id,
            "1.0.0",
            campaign_id,
            "generic",
            "pending",
            "{}",
            now,
            now,
        ),
    )
    task = _make_task()
    # override the task's id to match the real one
    task = task.model_copy(update={"task_id": task_id, "campaign_id": campaign_id})
    await pool.route_and_run(task)
    rows = await db.fetchall("SELECT task_id, router_id FROM router_decisions")
    assert rows
    assert rows[0]["task_id"] == task_id


@pytest.mark.asyncio
async def test_router_pool_consensus_policy(tmp_path) -> None:
    db = Database(tmp_path / "phase4.db")
    await apply_migrations(db, "up")
    reg = ProviderRegistry([MockAdapter()])
    pool = RouterPool(
        registry=reg,
        scores=ModelScoreStore(db),
        breakers=CircuitBreakerStore(db),
        usage=UsageAccountant(db),
        dead_letter=DeadLetterQueue(db),
        db=db,
    )
    task = _make_task(policy=RoutingPolicy.CONSENSUS)
    decision = await pool.decide(task)
    # with 3 routers, consensus is "votes >= 2"
    assert decision.policy.value == RoutingPolicy.CONSENSUS.value


@pytest.mark.asyncio
async def test_router_pool_diversity_policy(tmp_path) -> None:
    db = Database(tmp_path / "phase4.db")
    await apply_migrations(db, "up")
    reg = ProviderRegistry([MockAdapter()])
    pool = RouterPool(
        registry=reg,
        scores=ModelScoreStore(db),
        breakers=CircuitBreakerStore(db),
        usage=UsageAccountant(db),
        dead_letter=DeadLetterQueue(db),
        db=db,
    )
    task = _make_task(policy=RoutingPolicy.DIVERSITY)
    decision = await pool.decide(task)
    # diversity produces 1 chosen + a fallback chain of distinct providers
    assert decision.chosen is not None
    # the chosen provider is one of the mock providers
    assert decision.chosen.provider_id == "mock"


# ---- helpers ------------------------------------------------------------


async def _score_for(provider_id: str, model_key: str, category: TaskCategory, score: float):
    from mavr.schemas.routing import ModelScore

    return ModelScore(
        provider_id=provider_id,
        model_key=model_key,
        category=category,
        score=score,
        sample_count=1,
        confidence_low=max(0.0, score - 0.1),
        confidence_high=min(1.0, score + 0.1),
    )
