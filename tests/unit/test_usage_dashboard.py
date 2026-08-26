"""Tests for the usage & cost dashboard read-model (issue #148, PLAN §13.5)."""

from __future__ import annotations

import csv
import io
import json
import uuid

import pytest

from api.usage_dashboard import EXPORT_COLUMNS, UsageDashboard
from storage.sqlite import SQLiteStorage
from storage.usage import UsageStore


@pytest.fixture()
def usage(tmp_path):
    s = SQLiteStorage(tmp_path / "db.sqlite", tmp_path / "artifacts")
    s.migrate()
    yield UsageStore(s.conn)
    s.close()


@pytest.fixture()
def dash(usage):
    return UsageDashboard(usage)


CAMP_A, CAMP_B = str(uuid.uuid4()), str(uuid.uuid4())
AGENT_1, AGENT_2 = str(uuid.uuid4()), str(uuid.uuid4())


def _seed(usage: UsageStore):
    """Two campaigns: mostly free-tier on A, paid on B; one event w/o cost."""
    events = [
        # campaign A / agent 1: free tier, no cost recorded (unknown pricing)
        UsageStore.new_event(
            CAMP_A,
            AGENT_1,
            "openrouter",
            "zephyr-7b",
            input_tokens=100,
            output_tokens=50,
            is_free_tier=True,
            estimated_cost_usd=None,
        ),
        UsageStore.new_event(
            CAMP_A,
            AGENT_1,
            "openrouter",
            "zephyr-7b",
            input_tokens=200,
            output_tokens=100,
            is_free_tier=True,
            estimated_cost_usd=None,
        ),
        # campaign B / agent 2: paid with known cost
        UsageStore.new_event(
            CAMP_B,
            AGENT_2,
            "anthropic",
            "claude-x",
            input_tokens=10,
            output_tokens=5,
            is_free_tier=False,
            estimated_cost_usd=0.03,
        ),
        UsageStore.new_event(
            CAMP_B,
            AGENT_2,
            "anthropic",
            "claude-x",
            input_tokens=20,
            output_tokens=10,
            is_free_tier=False,
            estimated_cost_usd=0.06,
        ),
    ]
    for e in events:
        usage.record_event(e)
    return events


# ---- totals ------------------------------------------------------------------


def test_totals_sum_all_slices(dash, usage):
    _seed(usage)
    t = dash.totals()
    assert t["requests"] == 4
    assert t["input_tokens"] == 330
    assert t["output_tokens"] == 165
    assert abs(t["estimated_cost_usd"] - 0.09) < 1e-9
    assert t["free_requests"] == 2 and t["paid_requests"] == 2


def test_free_paid_separation_in_totals(dash, usage):
    """Free vs paid tokens and costs are separate numbers, not blended."""
    _seed(usage)
    t = dash.totals()
    assert t["input_tokens_free"] == 300 and t["input_tokens_paid"] == 30
    assert t["output_tokens_free"] == 150 and t["output_tokens_paid"] == 15
    assert abs(t["estimated_cost_usd_free"]) < 1e-9
    assert abs(t["estimated_cost_usd_paid"] - 0.09) < 1e-9


def test_unknown_pricing_flags_cost_known_false(dash, usage):
    """Events without a cost estimate → '—' in the UI via cost_known=False."""
    _seed(usage)
    assert dash.totals()["cost_known"] is False
    # Scoped to the fully-priced slice, every row has known cost.
    assert dash.totals(campaign_uuid=CAMP_B)["cost_known"] is True


def test_time_range_and_dimension_filters(dash, usage):
    events = _seed(usage)
    # Filter by campaign.
    assert dash.totals(campaign_uuid=CAMP_A)["requests"] == 2
    assert dash.totals(agent_uuid=AGENT_2)["paid_requests"] == 2
    # Time window excluding the last seeded event's occurred_at.
    early = dash.totals(until=events[0]["occurred_at"])
    assert early["requests"] >= 1


def test_unknown_filter_dimension_raises(dash, usage):
    with pytest.raises(ValueError, match="unknown filter dimension"):
        dash.totals(nonsense_id="x")


# ---- breakdowns --------------------------------------------------------------


def test_breakdown_by_provider_with_splits(dash, usage):
    _seed(usage)
    rows = {r["value"]: r for r in dash.breakdown("provider_id")}
    assert set(rows) == {"openrouter", "anthropic"}
    free_row = rows["openrouter"]
    assert free_row["free_requests"] == 2 and free_row["paid_requests"] == 0
    assert free_row["input_tokens_free"] == 300 and free_row["input_tokens_paid"] == 0
    paid_row = rows["anthropic"]
    assert paid_row["paid_requests"] == 2
    assert abs(paid_row["estimated_cost_usd_paid"] - 0.09) < 1e-9
    assert all(r["dimension"] == "provider_id" for r in rows.values())


def test_breakdown_ordered_by_total_tokens_desc(dash, usage):
    _seed(usage)
    rows = dash.breakdown("model_id")
    totals = [r["input_tokens"] + r["output_tokens"] for r in rows]
    assert totals == sorted(totals, reverse=True)


def test_breakdown_respects_filters(dash, usage):
    _seed(usage)
    rows = dash.breakdown("model_id", campaign_uuid=CAMP_B)
    assert [r["value"] for r in rows] == ["claude-x"]


def test_unknown_dashboard_dimension_raises(dash):
    with pytest.raises(ValueError, match="unknown dashboard dimension"):
        dash.breakdown("color")


def test_every_dashboard_dimension_works(dash, usage):
    _seed(usage)
    for dim in ("provider_id", "model_id", "campaign_uuid", "agent_uuid", "task_uuid"):
        rows = dash.breakdown(dim)
        assert rows, f"breakdown({dim}) returned nothing"


# ---- export ------------------------------------------------------------------


def test_export_json_roundtrip(dash, usage):
    _seed(usage)
    ctype, body = dash.export("json", by="provider_id")
    assert ctype == "application/json"
    rows = json.loads(body)
    assert len(rows) == 2


def test_export_csv_has_stable_columns_and_free_paid_split(dash, usage):
    _seed(usage)
    ctype, body = dash.export("csv", by="model_id")
    assert ctype == "text/csv"
    reader = csv.DictReader(io.StringIO(body))
    assert list(reader.fieldnames) == list(EXPORT_COLUMNS)
    data = list(reader)
    assert len(data) == 2
    zephyr = next(r for r in data if r["value"] == "zephyr-7b")
    assert zephyr["input_tokens_free"] == "300"


def test_export_totals_slice_without_dimension(dash, usage):
    _seed(usage)
    _, body = dash.export("json", since=None)
    rows = json.loads(body)
    assert len(rows) == 1 and rows[0]["requests"] == 4


def test_export_unknown_format_raises(dash, usage):
    _seed(usage)
    with pytest.raises(ValueError, match="unknown export format"):
        dash.export("parquet")
