# Usage accounting ledger (PLAN §14, issue #275)

The acceptance criterion this subsystem owns: *"usage is accurately
attributed by provider/model/agent/task."*

## Where things live

- `storage/usage.py` + `schemas/usage_event.schema.json` (+ migrations
  002/003) — the usage-event **record store** (issue #204): schema-validated,
  idempotent-per-`event_uuid`, indexed aggregation columns.
- `observability/usage_ledger.py` — the **ledger service** on top of the
  store (issue #275). Three responsibilities:

### 1. Crash-safe journaling

Every event is appended to a JSONL journal and fsynced **before** the SQLite
insert. A crash between journal and commit loses nothing: on startup,
`UsageLedger.recover_uncommitted()` replays journaled-but-unrecorded events.
Replay is idempotent because the store dedupes on `event_uuid`. The journal
is append-only and retained after successful commits, so it doubles as an
audit trail of accounting traffic; a torn final line (crash mid-write) is
skipped rather than poisoning recovery.

### 2. Reconciliation

`reconcile()` compares adapter-reported usage against local estimates
field-by-field (`input_tokens`, `output_tokens`, cache tokens) with a
percentage tolerance. Rules:

- Signed delta is computed per field; both over- and under-billing past the
  tolerance flag (both mean estimates diverge from reality).
- Zero estimate vs nonzero reported always flags regardless of tolerance —
  percentage math against a zero baseline would otherwise hide surprises.
- Divergent comparisons accumulate in `discrepancy_alerts()` with optional
  context (e.g. `event_uuid`) for surfacing in observability views.

`reconcile_event(uuid, reported=...)` is a convenience wrapper that pulls
the stored totals of a recorded event as the estimate side.

### 3. Aggregation API

`UsageLedger.query()` returns a `UsageQuery` facade supporting `summarize()`
and `breakdown(by)` filtered by any combination of campaign / agent / task /
provider / model plus `since`/`until` time bounds. Unknown dimensions or
filters raise `UsageLedgerError` — callers never write SQL.

## Testing

`tests/unit/test_usage_ledger.py` covers journal-before-commit ordering,
crash replay idempotency, invalid-payload rejection without journal writes,
tolerance edge cases (zero baseline), alert accumulation, stored-event
reconciliation, and the full dimension × time-range filter matrix.
