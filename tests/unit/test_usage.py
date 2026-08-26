"""Unit tests for the usage accounting ledger (issue #273).

Table-driven over: attribution journaling (crash-safe order), reconciliation
alerts, dimension aggregation over time ranges, and validation.
"""

from __future__ import annotations

import pytest

from observability.usage import (
    RECONCILIATION_TOLERANCE,
    UsageError,
    UsageLedger,
    make_event,
)

T0, T1, T2 = 1000.0, 2000.0, 3000.0


def _event(**overrides):
    kwargs = dict(
        provider="prov-a",
        model="m-1",
        agent_uuid="agent-x",
        task_uuid="task-1",
        campaign_uuid="camp-1",
        input_tokens=100,
        output_tokens=50,
        cost_estimate=0.02,
        now=T0,
    )
    kwargs.update(overrides)
    return make_event(**kwargs)


def test_journal_records_attribution_dimensions() -> None:
    ledger = UsageLedger()
    e = _event()
    ledger.journal(e)
    assert ledger.aggregate("provider") == {"prov-a": 150.0}
    assert ledger.aggregate("model") == {"m-1": 150.0}
    assert ledger.aggregate("agent_uuid") == {"agent-x": 150.0}
    assert ledger.aggregate("campaign_uuid") == {"camp-1": 150.0}


@pytest.mark.parametrize(
    ("dimension", "metric", "expected"),
    [
        ("provider", "requests", {"prov-a": 2.0}),
        ("model", "input_tokens", {"m-1": 300.0}),
        ("provider", "output_tokens", {"prov-a": 150.0}),
        ("campaign_uuid", "cost_estimate", {"camp-1": 0.05}),
    ],
)
def test_aggregation_table(dimension: str, metric: str, expected: dict) -> None:
    ledger = UsageLedger()
    ledger.journal(_event(now=T0))
    ledger.journal(_event(input_tokens=200, output_tokens=100, cost_estimate=0.03, now=T1))
    assert ledger.aggregate(dimension, metric) == expected


def test_time_range_filtering() -> None:
    ledger = UsageLedger()
    ledger.journal(_event(input_tokens=10, now=T0))
    ledger.journal(_event(input_tokens=20, now=T1))
    ledger.journal(_event(input_tokens=40, now=T2))
    assert ledger.aggregate("campaign_uuid", "total_tokens", ts_from=1500) == {"camp-1": 160.0}
    assert ledger.aggregate("campaign_uuid", "total_tokens", ts_from=500, ts_to=2500) == {
        "camp-1": 130.0
    }


# -- reconciliation ------------------------------------------------------------------


def test_reconciliation_within_tolerance_passes_silently() -> None:
    ledger = UsageLedger()
    e = _event(input_tokens=100, output_tokens=0)
    assert ledger.reconcile(e, local_estimate_tokens=110) is True
    assert ledger.alerts == []


def test_reconciliation_beyond_tolerance_alerts_with_both_numbers() -> None:
    ledger = UsageLedger()
    e = _event(input_tokens=100, output_tokens=0)
    ok = ledger.reconcile(e, local_estimate_tokens=200)
    assert ok is False
    alert = ledger.alerts[0]
    assert alert["reported"] == 100
    assert alert["local_estimate"] == 200
    assert alert["drift"] > RECONCILIATION_TOLERANCE


def test_zero_reported_vs_nonzero_estimate_still_flags() -> None:
    ledger = UsageLedger()
    e = _event(input_tokens=0, output_tokens=0)
    assert ledger.reconcile(e, local_estimate_tokens=500) is False


# -- validation / crash-safe ordering ---------------------------------------------------


def test_negative_token_counts_rejected() -> None:
    ledger = UsageLedger()
    with pytest.raises(UsageError):
        ledger.journal(_event(input_tokens=-1))


def test_journal_appends_are_never_reordered_or_edited() -> None:
    ledger = UsageLedger()
    a, b = _event(now=T0), _event(model="m-2", now=T1)
    ledger.journal(a)
    ledger.journal(b)
    assert ledger._journal == [a, b]
