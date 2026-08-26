"""Unit tests for the usage ledger (issue #28, PLAN §13.5/§14/§21)."""

import uuid

import pytest

from usage.ledger import (
    Budget,
    InvalidUsageEvent,
    LedgerQuery,
    UsageLedger,
)

CAMP = "44444444-4444-4444-4444-444444444444"
AGENT = "11111111-1111-1111-1111-111111111111"
TASK = "22222222-2222-2222-2222-222222222222"


def make_event(**overrides):
    ev = {
        "schema_version": 1,
        "record_type": "usage_event",
        "event_uuid": str(uuid.uuid4()),
        "campaign_uuid": CAMP,
        "task_uuid": TASK,
        "agent_uuid": AGENT,
        "provider_id": "openrouter",
        "model_id": "free/model-a",
        "input_tokens": 100,
        "output_tokens": 50,
        "cache_read_tokens": None,
        "cache_write_tokens": None,
        "is_free_tier": True,
        "estimated_cost_usd": None,
        "latency_ms": 800,
        "request_status": "success",
        "occurred_at": "2026-08-26T10:00:00Z",
    }
    ev.update(overrides)
    return ev


@pytest.fixture()
def ledger():
    return UsageLedger()


# --- recording --------------------------------------------------------------


def test_record_accepts_schema_valid_event(ledger):
    ev = make_event()
    assert ledger.record(ev) == ev["event_uuid"]
    assert len(ledger.events()) == 1


def test_record_rejects_schema_violations(ledger):
    # negative tokens violate the schema minimum
    with pytest.raises(InvalidUsageEvent):
        ledger.record(make_event(input_tokens=-5))
    # bad request_status enum
    with pytest.raises(InvalidUsageEvent):
        ledger.record(make_event(request_status="meh"))
    # rejected events must not be stored
    assert ledger.events() == []


# --- attribution queries ----------------------------------------------------


@pytest.fixture()
def populated(ledger):
    ledger.record(
        make_event(model_id="free/a", is_free_tier=True, input_tokens=100, output_tokens=10)
    )
    ledger.record(
        make_event(
            model_id="paid/b",
            is_free_tier=False,
            input_tokens=200,
            output_tokens=20,
            estimated_cost_usd=0.02,
        )
    )
    ledger.record(
        make_event(
            provider_id="opencode",
            occurred_at="2026-08-27T10:00:00Z",
            request_status="rate_limited",
        )
    )
    return ledger


def test_filter_by_provider(populated):
    evs = populated.events(LedgerQuery(provider_id="opencode"))
    assert len(evs) == 1
    assert evs[0]["provider_id"] == "opencode"


def test_filter_by_campaign_and_agent(populated):
    assert len(populated.events(LedgerQuery(campaign_uuid=CAMP))) == 3
    other = str(uuid.uuid4())
    assert populated.events(LedgerQuery(agent_uuid=other)) == []


def test_time_range_filters_inclusive(populated):
    q = LedgerQuery(since="2026-08-27T00:00:00Z")
    assert len(populated.events(q)) == 1
    q2 = LedgerQuery(until="2026-08-26T10:00:00Z")
    assert len(populated.events(q2)) >= 1


# --- totals & free/paid separation -------------------------------------------


def test_totals_split_free_from_paid(populated):
    t = populated.totals(LedgerQuery(campaign_uuid=CAMP))
    assert t.requests == 3
    assert t.input_tokens == 400
    assert t.free_requests == 2 and t.paid_requests == 1
    assert t.free_input_tokens == 200 and t.paid_input_tokens == 200
    assert t.free_output_tokens == 60 and t.paid_output_tokens == 20
    assert t.estimated_cost_usd == pytest.approx(0.02)


def test_totals_count_non_success_as_errors(populated):
    t = populated.totals(LedgerQuery(request_status="rate_limited"))
    assert t.requests == 1 and t.errors == 1


def test_totals_for_unknown_scope_are_zero(ledger):
    t = ledger.totals(LedgerQuery(campaign_uuid=str(uuid.uuid4())))
    assert t.requests == 0 and t.input_tokens == 0


# --- budgets ------------------------------------------------------------------


def test_budget_breach_on_input_tokens(populated):
    b = Budget(max_input_tokens=250)
    breach = populated.check_budget(b, LedgerQuery(campaign_uuid=CAMP))
    assert breach is not None
    assert breach.dimension == "input_tokens"
    assert breach.used == 400 and breach.limit == 250 and breach.overage == 150


def test_budget_ok_when_under_limit(populated):
    b = Budget(max_input_tokens=5000, max_requests=10)
    assert populated.check_budget(b, LedgerQuery(campaign_uuid=CAMP)) is None


def test_budget_none_means_unlimited(populated):
    b = Budget()  # no limits at all
    assert populated.check_budget(b) is None


def test_budget_scoped_to_one_agent():
    ledger = UsageLedger()
    ledger.record(make_event(agent_uuid=AGENT, input_tokens=1500))
    ledger.record(make_event(agent_uuid=TASK, input_tokens=10))
    b = Budget(max_input_tokens=1000)
    # Only agent AGENT's usage counts against its own budget.
    breach = ledger.check_budget(b, LedgerQuery(agent_uuid=AGENT))
    assert breach is not None and breach.used == 1500
    assert ledger.check_budget(b, LedgerQuery(agent_uuid=TASK)) is None
