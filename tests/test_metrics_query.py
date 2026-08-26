"""Tests for the §14 metrics query backend (campaign/time-range)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from mavr.observability.metrics import MetricsStore
from mavr.observability.metrics_query import (
    aggregate,
    prune_older_than,
    query_range,
)


@pytest.fixture()
def store(migrated_db) -> MetricsStore:
    return MetricsStore(migrated_db)


async def _seed(store: MetricsStore, campaign: str | None) -> None:
    await store.inc_counter("tokens", amount=10.0, campaign_id=campaign)
    await store.inc_counter("tokens", amount=5.0, campaign_id=campaign)
    await store.set_gauge("queue_depth", 3.0, campaign_id=campaign)
    await store.observe_histogram(
        "latency", 0.25, bucket="0-1s", campaign_id=campaign
    )


@pytest.mark.asyncio
async def test_query_range_filters_by_campaign(store: MetricsStore, campaign_id: str) -> None:
    await _seed(store, campaign_id)
    await store.inc_counter("tokens", amount=99.0, campaign_id="33333333-3333-4333-8333-333333333333")
    rows = await query_range(store, campaign_id=campaign_id)
    assert len(rows) == 4
    assert all(r.campaign_id == campaign_id for r in rows)
    names = {r.name for r in rows}
    assert names == {"tokens", "queue_depth", "latency"}


@pytest.mark.asyncio
async def test_query_range_time_window(store: MetricsStore) -> None:
    now = datetime.now(UTC)
    early = (now - timedelta(hours=2)).isoformat()
    await store.inc_counter("hits", amount=1.0)
    # Backdate the first point by rewriting its timestamp.
    await store._db.execute(
        "UPDATE metric_points SET created_at = ? WHERE name = 'hits'", (early,)
    )
    mid = datetime.now(UTC).isoformat()
    await store.inc_counter("hits", amount=1.0)
    end = (datetime.now(UTC) + timedelta(seconds=5)).isoformat()
    in_window = await query_range(store, start=mid, end=end)
    assert len(in_window) == 1
    all_rows = await query_range(store, start=early, end=end)
    assert len(all_rows) == 2


@pytest.mark.asyncio
async def test_query_range_kind_filter_and_validation(store: MetricsStore) -> None:
    await _seed(store, None)
    gauges = await query_range(store, kind="gauge")
    assert [g.name for g in gauges] == ["queue_depth"]
    with pytest.raises(ValueError):
        await query_range(store, kind="bogus")


@pytest.mark.asyncio
async def test_aggregate_sums_counters(store: MetricsStore, campaign_id: str) -> None:
    await _seed(store, campaign_id)
    agg = await aggregate(store, campaign_id=campaign_id)
    assert agg["tokens"].total == 15.0
    assert agg["tokens"].count == 2
    assert agg["tokens"].avg == 7.5
    assert agg["tokens"].kind == "counter"
    # Gauges/histograms excluded by default kinds.
    assert "queue_depth" not in agg and "latency" not in agg


@pytest.mark.asyncio
async def test_aggregate_includes_gauges_when_asked(store: MetricsStore) -> None:
    await store.set_gauge("depth", 4.0)
    agg = await aggregate(store, kinds=("counter", "gauge"))
    assert agg["depth"].total == 4.0


@pytest.mark.asyncio
async def test_prune_older_than_removes_old_points(store: MetricsStore) -> None:
    await store.inc_counter("old", amount=1.0)
    now = datetime.now(UTC)
    old_ts = (now - timedelta(days=30, minutes=5)).isoformat()
    await store._db.execute(
        "UPDATE metric_points SET created_at = ? WHERE name = 'old'", (old_ts,)
    )
    await store.inc_counter("new", amount=1.0)
    removed = await prune_older_than(store, 7, now_iso=now.isoformat())
    assert removed == 1
    remaining = await query_range(store)
    assert [r.name for r in remaining] == ["new"]


@pytest.mark.asyncio
async def test_prune_zero_disables_retention(store: MetricsStore) -> None:
    await store.inc_counter("keep", amount=1.0)
    assert await prune_older_than(store, 0) == 0
    assert len(await query_range(store)) == 1
