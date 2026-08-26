"""Unit tests for the usage accounting backend (issue #204, PLAN §13.5)."""

from __future__ import annotations

import uuid

import pytest

from storage.sqlite import SQLiteStorage
from storage.usage import UsageEventError, UsageStore


@pytest.fixture()
def store(tmp_path):
    s = SQLiteStorage(tmp_path / "db.sqlite", tmp_path / "artifacts")
    s.migrate()
    yield UsageStore(s.conn)
    s.close()


def _event(**overrides):
    base = dict(
        campaign_uuid=str(uuid.uuid4()),
        agent_uuid=str(uuid.uuid4()),
        provider_id="openrouter",
        model_id="zephyr-7b",
        input_tokens=100,
        output_tokens=50,
        is_free_tier=True,
    )
    base.update(overrides)
    return UsageStore.new_event(**base)


def test_record_and_summarize_roundtrip(store):
    ev = _event(
        input_tokens=120,
        output_tokens=80,
        is_free_tier=False,
        estimated_cost_usd=0.02,
        latency_ms=350,
    )
    assert store.record_event(ev) == ev["event_uuid"]
    summary = store.summarize(campaign_uuid=ev["campaign_uuid"])
    assert summary.requests == 1
    assert summary.input_tokens == 120
    assert summary.output_tokens == 80
    assert summary.estimated_cost_usd == pytest.approx(0.02)
    assert summary.paid_requests == 1
    assert summary.free_requests == 0


def test_invalid_event_rejected(store):
    bad = _event()
    bad["request_status"] = "exploded"  # not in schema enum
    with pytest.raises(UsageEventError):
        store.record_event(bad)
    # Unknown field: schema has additionalProperties=false.
    extra = _event()
    extra["mystery_field"] = 1
    with pytest.raises(UsageEventError):
        store.record_event(extra)
    assert store.summarize().requests == 0


def test_duplicate_event_uuid_is_idempotent(store):
    ev = _event()
    store.record_event(ev)
    ev2 = dict(ev, input_tokens=999999)  # same uuid, different payload
    store.record_event(ev2)
    assert store.summarize(campaign_uuid=ev["campaign_uuid"]).input_tokens == 100


def test_attribution_dimensions_are_independent(store):
    a, b, c = _event(), _event(), _event()
    for e in (a, b, c):
        store.record_event(e)
    assert store.summarize(campaign_uuid=a["campaign_uuid"]).requests == 1
    assert store.summarize(agent_uuid=a["agent_uuid"]).requests == 1
    assert store.summarize(provider_id="openrouter").requests == 3
    assert store.summarize(model_id="nonexistent-model").requests == 0


def test_breakdown_by_provider_and_model(store):
    campaign = str(uuid.uuid4())
    e1 = _event(campaign_uuid=campaign, model_id="zephyr-7b", input_tokens=10, output_tokens=5)
    e2 = _event(campaign_uuid=campaign, model_id="llama-3-8b", input_tokens=1000, output_tokens=500)
    store.record_event(e1)
    store.record_event(e2)
    rows = store.breakdown("model_id", campaign_uuid=campaign, provider_id="openrouter")
    by_dim = {r["dimension"]: r for r in rows}
    assert set(by_dim) == {"zephyr-7b", "llama-3-8b"}
    # Ordered by total tokens descending.
    assert rows[0]["dimension"] == "llama-3-8b"
    assert by_dim["zephyr-7b"]["input_tokens"] == 10
    with pytest.raises(UsageEventError):
        store.breakdown("not_a_dimension")


def test_time_window_filters(store):
    early = _event(occurred_at="2026-01-01T00:00:00Z", input_tokens=1)
    late = _event(occurred_at="2026-06-01T00:00:00Z", input_tokens=2)
    store.record_event(early)
    store.record_event(late)
    assert store.summarize(since="2026-03-01T00:00:00Z").requests == 1
    assert store.summarize(until="2026-03-01T00:00:00Z").requests == 1
    assert store.summarize(since="2026-01-01T00:00:00Z", until="2026-12-31T00:00:00Z").requests == 2
    assert (
        store.summarize(since="2026-01-01T00:00:00Z", until="2026-12-31T00:00:00Z").input_tokens
        == 3
    )


def test_new_event_defaults_are_schema_valid(store):
    ev = UsageStore.new_event(
        campaign_uuid=str(uuid.uuid4()),
        agent_uuid=str(uuid.uuid4()),
        provider_id="p",
        model_id="m",
    )
    assert ev["schema_version"] == 1
    assert ev["record_type"] == "usage_event"
    assert ev["task_uuid"] is None
    assert ev["is_free_tier"] is False
    assert ev["request_status"] == "success"
    store.record_event(ev)  # must pass validation
