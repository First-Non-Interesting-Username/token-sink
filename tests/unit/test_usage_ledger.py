"""Unit tests for the usage accounting ledger service (issue #275, PLAN §14).

Covers the three deliverables the issue names that storage/usage.py (#204)
does not already provide:

- Crash-safe journaling: events are appended+fsynced to a JSONL journal
  BEFORE the SQLite insert, and pending journal entries are replayed
  idempotently after a simulated crash.
- Reconciliation: adapter-reported usage vs locally estimated usage, with
  discrepancy records raised past a configurable tolerance.
- Aggregation API: one query surface over every attribution dimension
  (provider/model/agent/task/campaign) plus time range, powering the
  usage/cost view breakdowns.
"""

from __future__ import annotations

import json
import uuid

import pytest

from observability.usage_ledger import (
    UsageLedger,
    UsageLedgerError,
)
from storage.sqlite import SQLiteStorage
from storage.usage import UsageStore


@pytest.fixture()
def env(tmp_path):
    s = SQLiteStorage(tmp_path / "db.sqlite", tmp_path / "artifacts")
    s.migrate()
    ledger = UsageLedger(
        UsageStore(s.conn),
        journal_path=tmp_path / "usage_journal.jsonl",
    )
    yield ledger, s
    s.close()


def _event(**overrides):
    from storage.usage import UsageStore

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


# --- journaling / crash safety ------------------------------------------------


def test_journal_written_before_store_commit(env, tmp_path):
    ledger, _ = env
    ev = _event()
    ledger.journal_event(ev)
    # Journal line exists on disk even though nothing was committed yet.
    lines = (tmp_path / "usage_journal.jsonl").read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["event_uuid"] == ev["event_uuid"]
    assert ledger.pending_count() == 1


def test_record_journals_then_commits_and_clears_pending(env, tmp_path):
    ledger, _ = env
    ev = _event()
    uuid_out = ledger.record(ev)
    assert uuid_out == ev["event_uuid"]
    assert ledger.pending_count() == 0
    # The journal still holds the line (audit trail); recovery is a no-op now.
    lines = (tmp_path / "usage_journal.jsonl").read_text().splitlines()
    assert len(lines) == 1


def test_crash_recovery_replays_uncommitted_events(env):
    ledger, _ = env
    ev = _event(input_tokens=77)
    ledger.journal_event(ev)  # crash happens here: journaled but not committed

    # Fresh process: same DB, same journal file.
    recovered = ledger.recover_uncommitted()
    assert [e["event_uuid"] for e in recovered] == [ev["event_uuid"]]
    assert ledger.query().summarize(agent_uuid=ev["agent_uuid"]).input_tokens == 77
    # Second recovery is a no-op (idempotent by event_uuid).
    assert ledger.recover_uncommitted() == []


def test_invalid_event_fails_without_touching_journal(env, tmp_path):
    ledger, _ = env
    bad = _event()
    bad["request_status"] = "bogus"
    with pytest.raises(UsageLedgerError):
        ledger.record(bad)
    assert not (tmp_path / "usage_journal.jsonl").exists()


# --- reconciliation -----------------------------------------------------------


def test_reconcile_within_tolerance_is_clean(env):
    ledger, _ = env
    d = ledger.reconcile(
        reported={"input_tokens": 105, "output_tokens": 50},
        estimated={"input_tokens": 100, "output_tokens": 50},
        tolerance_pct=10.0,
    )
    assert list(d.discrepancies) == []


def test_reconcile_flags_discrepancies_per_field(env):
    ledger, _ = env
    d = ledger.reconcile(
        reported={"input_tokens": 200, "output_tokens": 50},
        estimated={"input_tokens": 100, "output_tokens": 50},
        tolerance_pct=10.0,
    )
    assert [(x.field, x.reported, x.estimated) for x in d.discrepancies] == [
        ("input_tokens", 200, 100)
    ]
    assert d.discrepancies[0].delta_pct == pytest.approx(100.0)


def test_reconcile_zero_estimate_with_nonzero_reported_flags(env):
    ledger, _ = env
    d = ledger.reconcile(
        reported={"output_tokens": 40},
        estimated={"output_tokens": 0},
        tolerance_pct=10.0,
    )
    assert len(d.discrepancies) == 1


def test_reconcile_alerts_accumulate_and_are_queryable(env):
    ledger, _ = env
    ev = _event()
    ledger.record(ev)
    ledger.reconcile(
        reported={"input_tokens": 999, "output_tokens": 0},
        estimated={"input_tokens": 100, "output_tokens": 0},
        tolerance_pct=10.0,
        context={"event_uuid": ev["event_uuid"]},
    )
    alerts = ledger.discrepancy_alerts()
    assert len(alerts) == 1
    assert alerts[0]["context"]["event_uuid"] == ev["event_uuid"]
    assert alerts[0]["discrepancies"][0]["field"] == "input_tokens"


def test_reconcile_against_recorded_event_uses_stored_totals(env):
    ledger, _ = env
    ev = _event(input_tokens=100, output_tokens=50)
    ledger.record(ev)
    d = ledger.reconcile_event(
        ev["event_uuid"],
        reported={"input_tokens": 101, "output_tokens": 52, "cache_read_tokens": 0},
        tolerance_pct=5.0,
    )
    assert list(d.discrepancies) == []
    # Way off:
    d2 = ledger.reconcile_event(
        ev["event_uuid"],
        reported={"input_tokens": 300, "output_tokens": 500},
        tolerance_pct=5.0,
    )
    assert {x.field for x in d2.discrepancies} == {"input_tokens", "output_tokens"}


# --- aggregation API ----------------------------------------------------------


def test_query_facade_breaks_down_every_dimension(env):
    ledger, _ = env
    campaign = str(uuid.uuid4())
    agent = str(uuid.uuid4())
    task = str(uuid.uuid4())
    e1 = _event(
        campaign_uuid=campaign,
        agent_uuid=agent,
        task_uuid=task,
        provider_id="prov-a",
        model_id="m1",
        input_tokens=10,
        output_tokens=5,
        occurred_at="2026-01-01T00:00:00Z",
    )
    e2 = _event(
        campaign_uuid=campaign,
        agent_uuid=str(uuid.uuid4()),
        task_uuid=None,
        provider_id="prov-b",
        model_id="m2",
        input_tokens=1000,
        output_tokens=500,
        occurred_at="2026-06-01T00:00:00Z",
    )
    ledger.record(e1)
    ledger.record(e2)

    q = ledger.query()
    total = q.summarize()
    assert total.requests == 2

    # Every dimension supported, each filterable by every other dimension + time.
    for dim in ("provider_id", "model_id", "agent_uuid", "task_uuid", "campaign_uuid"):
        rows = q.breakdown(dim)
        assert rows, dim
    assert {r["dimension"] for r in q.breakdown("model_id")} == {"m1", "m2"}
    assert q.summarize(since="2026-03-01T00:00:00Z").requests == 1
    assert q.summarize(campaign_uuid=campaign, agent_uuid=agent).requests == 1
    assert q.summarize(provider_id="nope").requests == 0
    # Unknown dimension rejected loudly.
    with pytest.raises(UsageLedgerError):
        q.breakdown("color")


def test_direct_sql_writes_do_not_bypass_ledger_semantics(env):
    """Sanity: the ledger shares the storage connection (same WAL db)."""
    ledger, s = env
    ev = _event()
    ledger.record(ev)
    n = s.conn.execute("SELECT COUNT(*) FROM usage_events").fetchone()[0]
    assert n == 1
