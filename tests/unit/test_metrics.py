"""Unit tests for the time-series metrics store (issue #156, PLAN §14/§16)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from observability.metrics import FAMILIES, MetricQuery, MetricsStore, aggregate


def make_store(tmp_path: Path) -> MetricsStore:
    return MetricsStore(path=tmp_path / "metrics.jsonl")


def test_record_and_query_by_campaign_and_range(tmp_path: Path) -> None:
    s = make_store(tmp_path)
    s.record("agent", "tokens_used", 100, campaign_id="c1", ts=1000)
    s.record("agent", "tokens_used", 200, campaign_id="c1", ts=2000)
    s.record("agent", "tokens_used", 300, campaign_id="c2", ts=1500)
    got = s.query(MetricQuery(campaign_id="c1"))
    assert [p.value for p in got] == [100, 200]  # ordered by time


def test_all_four_families_accepted(tmp_path: Path) -> None:
    s = make_store(tmp_path)
    for fam in FAMILIES:
        s.record(fam, "metric", 1.0)
    assert len(s.points) == 4


def test_unknown_family_rejected(tmp_path: Path) -> None:
    s = make_store(tmp_path)
    with pytest.raises(ValueError):
        s.record("bogus", "m", 1)


def test_aggregations_sum_avg_min_max_count_pct() -> None:
    pts = []
    for i, v in enumerate([10, 20, 30]):
        pts.append(_pt(i * 10, v))
    assert aggregate(pts, "sum") == 60
    assert aggregate(pts, "avg") == 20
    assert aggregate(pts, "min") == 10
    assert aggregate(pts, "max") == 30
    assert aggregate(pts, "count") == 3
    with pytest.raises(ValueError):
        aggregate(pts, "median")
    with pytest.raises(ValueError):
        aggregate([], "nope")


def _pt(ts: float, v: float):
    from observability.metrics import MetricPoint

    return MetricPoint(ts=ts, family="system", name="x", value=v)


def test_time_range_filtering(tmp_path: Path) -> None:
    s = make_store(tmp_path)
    for t in (100, 200, 300):
        s.record("system", "cpu", t, ts=t)
    got = s.query(MetricQuery(since=150, until=250))
    assert [p.value for p in got] == [200]


def test_persistence_survives_restart_and_tolerates_torn_lines(
    tmp_path: Path,
) -> None:
    path = tmp_path / "metrics.jsonl"
    s1 = MetricsStore(path=path)
    s1.record("provider_model", "latency_ms", 42, tags={"model": "m"}, ts=5)
    # Simulate a crash mid-write.
    with path.open("a") as f:
        f.write('{"ts": 6, "family": "sys')
    s2 = MetricsStore(path=path)
    assert len(s2.points) == 1
    assert s2.points[0].tags == {"model": "m"}


def test_prune_drops_old_points_and_rewrites_file(tmp_path: Path) -> None:
    path = tmp_path / "metrics.jsonl"
    s = MetricsStore(path=path)
    s.record("system", "m", 1, ts=100)
    s.record("system", "m", 2, ts=200)
    removed = s.prune(older_than_ts=150)
    assert removed == 1
    assert [p.value for p in s.points] == [2]
    # File rewritten so pruning survives restart.
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(lines) == 1 and lines[0]["value"] == 2


def test_series_buckets_by_time_window(tmp_path: Path) -> None:
    s = make_store(tmp_path)
    for t, v in [(10, 1), (20, 3), (110, 10)]:
        s.record("research", "findings", v, ts=t)
    series = s.series(bucket_seconds=100, agg="sum")
    assert series[0][0] == 0 and series[0][1] == 4  # 10s and 20s share bucket 0
    assert series[1][0] == 100 and series[1][1] == 10


def test_agent_filter(tmp_path: Path) -> None:
    s = make_store(tmp_path)
    s.record("agent", "tool_calls", 5, agent_id="a1", ts=1)
    s.record("agent", "tool_calls", 7, agent_id="a2", ts=2)
    got = s.query(MetricQuery(agent_id="a1"))
    assert [p.value for p in got] == [5]


def test_aggregate_via_store_query(tmp_path: Path) -> None:
    s = make_store(tmp_path)
    s.record("agent", "tokens_used", 100, campaign_id="c1", ts=1)
    s.record("agent", "tokens_used", 50, campaign_id="c2", ts=2)
    total_c1 = s.aggregate("sum", MetricQuery(campaign_id="c1", name="tokens_used"))
    assert total_c1 == 100
