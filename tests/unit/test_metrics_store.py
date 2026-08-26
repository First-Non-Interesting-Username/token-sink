"""Unit tests for the time-series metrics store (issue #156, PLAN §14)."""

from __future__ import annotations

import pytest

from observability.metrics import FAMILIES, MetricsError, MetricsStore


def _store() -> MetricsStore:
    st = MetricsStore()
    # provider family: tokens per campaign/model
    st.record("provider", "tokens_used", 100, ts=1000, campaign_id="c1", tags={"model": "m-a"})
    st.record("provider", "tokens_used", 300, ts=1010, campaign_id="c1", tags={"model": "m-b"})
    st.record("provider", "tokens_used", 50, ts=1020, campaign_id="c2", tags={"model": "m-a"})
    # agent family with latency samples
    for i, ms in enumerate([10, 20, 30, 40, 100]):
        st.record(
            "agent", "request_latency_ms", ms, ts=1000 + i, campaign_id="c1", agent_id=f"a{i}"
        )
    # system-wide sample (no campaign)
    st.record("system", "queue_depth", 7, ts=1005)
    return st


def test_record_validates_family():
    st = MetricsStore()
    with pytest.raises(MetricsError, match="unknown metric family"):
        st.record("bogus", "x", 1)
    assert set(FAMILIES) == {"agent", "provider", "research", "system"}


def test_filter_by_campaign_and_time_range():
    st = _store()
    c1 = st.raw(family="provider", name="tokens_used", campaign_id="c1", since=1000, until=1015)
    assert [s.value for s in c1] == [100, 300]
    # until is inclusive
    wide = st.raw(family="provider", name="tokens_used", since=1009, until=1020)
    assert len(wide) == 2


def test_campaign_query_folds_in_global_by_default():
    st = _store()
    assert len(st.raw(name="queue_depth", campaign_id="c1")) == 1
    assert len(st.raw(name="queue_depth", campaign_id="c1", include_global=False)) == 0


def test_aggregations():
    st = _store()
    lat = dict(family="agent", name="request_latency_ms", campaign_id="c1")
    assert st.aggregate("count", **lat) == 5
    assert st.aggregate("sum", **lat) == 200
    assert st.aggregate("avg", **lat) == 40
    assert st.aggregate("min", **lat) == 10
    assert st.aggregate("max", **lat) == 100
    assert st.aggregate("p50", **lat) == 30
    assert st.aggregate("p95", **lat) == 100
    with pytest.raises(MetricsError):
        st.aggregate("median", **lat)
    # empty selection
    assert st.aggregate("sum", family="research", name="nothing") is None


def test_group_by_tag_and_campaign():
    st = _store()
    by_model = st.group_by("model", "sum", family="provider", name="tokens_used")
    assert by_model == {"m-a": 150, "m-b": 300}
    by_camp = st.group_by("campaign_id", "avg", family="provider", name="tokens_used")
    assert by_camp["c1"] == 200 and by_camp["c2"] == 50


def test_tag_equality_filter_and_agent_filter():
    st = _store()
    a_only = st.raw(tags={"model": "m-a"}, family="provider")
    assert {s.campaign_id for s in a_only} == {"c1", "c2"}
    assert len(st.raw(agent_id="a3", family="agent")) == 1


def test_prune_retention():
    st = _store()
    dropped = st.prune(older_than_ts=1005)
    # ts < 1005: latency samples 10,20,30,40 (ts 1000-1003) + tokens@1000
    assert dropped == 6
    assert all(s.ts >= 1005 for s in st.raw())
    # tokens@1000 pruned too; remaining: 300 + 50
    assert st.aggregate("sum", family="provider", name="tokens_used") == 350


def test_default_timestamp_is_now():
    st = MetricsStore()
    s = st.record("system", "heartbeat", 1)
    assert s.ts > 0
