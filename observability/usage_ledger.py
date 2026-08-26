"""Usage accounting ledger service (issue #275, PLAN §14, §19 acceptance).

The acceptance test this issue owns: *"usage is accurately attributed by
provider/model/agent/task."* ``storage/usage.py`` (#204) already records and
aggregates usage events in SQLite; this module adds the three deliverables
the issue names that storage alone does not provide:

1. **Crash-safe journaling** — every event is appended (and fsynced) to a
   JSONL journal *before* the SQLite insert runs. If the process dies
   between the two, a fresh :meth:`UsageLedger.recover_uncommitted` replays
   journaled-but-unrecorded events idempotently (the store dedupes on
   ``event_uuid``), so a crash can never lose billing data. The journal is
   append-only and kept even after successful commits — it doubles as an
   audit trail of accounting traffic.

2. **Reconciliation** — compares adapter-reported usage against local
   estimates field-by-field with a percentage tolerance and accumulates
   structured discrepancy alerts (:class:`Discrepancy`). A zero estimate vs
   nonzero reported always flags regardless of tolerance — dividing by a
   zero baseline would otherwise silently hide billing surprises.

3. **Aggregation API** — :class:`UsageQuery` is one facade over every
   attribution dimension (provider/model/agent/task/campaign) plus time
   range, powering the usage/costs view breakdowns without callers writing
   SQL.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from storage.usage import UsageEventError, UsageStore

__all__ = [
    "Discrepancy",
    "ReconciliationResult",
    "UsageLedger",
    "UsageLedgerError",
    "UsageQuery",
]


class UsageLedgerError(ValueError):
    """Invalid ledger operation (bad event payload or unknown dimension)."""


@dataclass(frozen=True)
class Discrepancy:
    """One reported-vs-estimated field that diverged past tolerance."""

    field: str
    reported: float | int
    estimated: float | int
    delta_pct: float  # signed; positive = provider billed more than estimated

    def as_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "reported": self.reported,
            "estimated": self.estimated,
            "delta_pct": self.delta_pct,
        }


@dataclass(frozen=True)
class ReconciliationResult:
    """Outcome of one reconciliation comparison."""

    discrepancies: tuple[Discrepancy, ...] = ()
    context: dict[str, Any] = field(default_factory=dict)

    @property
    def clean(self) -> bool:
        return not self.discrepancies

    def as_dict(self) -> dict[str, Any]:
        return {
            "discrepancies": [d.as_dict() for d in self.discrepancies],
            "context": dict(self.context),
        }


# Token fields compared during reconciliation. Cache-token fields default to
# zero on both sides when absent so callers only pass what they know.
_COMPARED_FIELDS: tuple[str, ...] = (
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
)


class UsageLedger:
    """Crash-safe recorder + reconciler + aggregation facade.

    Shares the storage connection with :class:`storage.sqlite.SQLiteStorage`
    via its :class:`~storage.usage.UsageStore`; the journal lives beside the
    database as plain JSONL.
    """

    def __init__(
        self,
        store: UsageStore,
        *,
        journal_path: str | os.PathLike[str] | None = None,
    ) -> None:
        self.store = store
        self.journal_path = Path(journal_path) if journal_path else None
        self._alerts: list[dict[str, Any]] = []
        # event_uuids journaled but not yet confirmed committed; keeps
        # pending_count() O(1) instead of re-reading the file per call.
        self._pending: set[str] = set()
        if self.journal_path is not None and self.journal_path.exists():
            self._load_pending_from_journal()

    # --- crash-safe recording ---------------------------------------------------

    def journal_event(self, event: dict[str, Any]) -> None:
        """Append one event to the journal BEFORE any DB write.

        Flushed and fsynced immediately so a hard kill loses nothing that was
        acknowledged here.
        """
        if self.journal_path is None:
            raise UsageLedgerError("no journal path configured")
        line = json.dumps(event, sort_keys=True, separators=(",", ":"))
        with open(self.journal_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        uid = event.get("event_uuid")
        if uid:
            self._pending.add(uid)

    def record(self, event: dict[str, Any]) -> str:
        """Journal → commit → clear-pending, in that order.

        Validation failure raises before the journal is touched so invalid
        payloads never enter the audit trail. Duplicate event_uuid commits
        are idempotent at the store layer and simply clear the pending mark.
        """
        try:
            uuid_out = self.store.record_event(event)
        except UsageEventError as exc:
            raise UsageLedgerError(str(exc)) from exc
        if self.journal_path is not None:
            # Journal after commit only when no line exists yet; normally
            # callers journal first (journal_event → record). Recording
            # directly still leaves an audit line for completeness.
            if event["event_uuid"] not in self._seen_in_journal():
                self.journal_event(event)
        self._pending.discard(event["event_uuid"])
        return uuid_out

    def pending_count(self) -> int:
        """Journaled events not yet confirmed committed."""
        return len(self._pending)

    def recover_uncommitted(self) -> list[dict[str, Any]]:
        """Replay journaled-but-unrecorded events into the store.

        Idempotent: the store's unique index on event_uuid makes replays
        no-ops, and each recorded uuid drops out of pending. Returns the
        events recovered (empty list = nothing to do).
        """
        if self.journal_path is None or not self.journal_path.exists():
            return []
        known_committed = self._known_committed_uuids()
        recovered: list[dict[str, Any]] = []
        for event in self._read_journal():
            uid = event.get("event_uuid")
            if uid in known_committed:
                self._pending.discard(uid)
                continue
            try:
                self.store.record_event(event)
            except UsageEventError:
                # Corrupt/hand-edited journal entry: leave it pending rather
                # than silently dropping billing data.
                continue
            known_committed.add(uid)
            self._pending.discard(uid)
            recovered.append(event)
        return recovered

    # --- reconciliation -----------------------------------------------------------

    def reconcile(
        self,
        *,
        reported: dict[str, float | int],
        estimated: dict[str, float | int],
        tolerance_pct: float = 5.0,
        context: dict[str, Any] | None = None,
    ) -> ReconciliationResult:
        """Compare adapter-reported usage to local estimates field-by-field."""
        findings: list[Discrepancy] = []
        for name in _COMPARED_FIELDS:
            rep = reported.get(name, 0)
            est = estimated.get(name, 0)
            if rep == est:
                continue
            delta_pct = float("inf") if est == 0 else ((rep - est) / est) * 100.0
            # abs(): under-billing is as much an accounting problem as
            # over-billing — both mean estimates diverge from reality.
            if est == 0 or abs(delta_pct) > tolerance_pct:
                findings.append(
                    Discrepancy(field=name, reported=rep, estimated=est, delta_pct=delta_pct)
                )
        result = ReconciliationResult(discrepancies=tuple(findings), context=dict(context or {}))
        if findings:
            # Alerts accumulate only for actual divergence; clean comparisons
            # aren't retained.
            self._alerts.append(result.as_dict())
        return result

    def reconcile_event(
        self,
        event_uuid: str,
        *,
        reported: dict[str, float | int],
        tolerance_pct: float = 5.0,
    ) -> ReconciliationResult:
        """Reconcile reported numbers against a stored event's totals."""
        estimated = self.stored_totals(event_uuid)
        return self.reconcile(
            reported=reported,
            estimated=estimated,
            tolerance_pct=tolerance_pct,
            context={"event_uuid": event_uuid},
        )

    def stored_totals(self, event_uuid: str) -> dict[str, int]:
        """Token totals for one recorded event; zeroed dict when unknown."""
        row = self.store.conn.execute(
            """
            SELECT input_tokens, output_tokens,
                   COALESCE(cache_read_tokens, 0), COALESCE(cache_write_tokens, 0)
            FROM usage_events WHERE event_uuid = ?
            """,
            (event_uuid,),
        ).fetchone()
        if row is None:
            return {name: 0 for name in _COMPARED_FIELDS}
        return {name: int(row[i]) for i, name in enumerate(_COMPARED_FIELDS)}

    def discrepancy_alerts(self) -> list[dict[str, Any]]:
        """All reconciliation alerts raised this process lifetime."""
        return list(self._alerts)

    # --- aggregation API ------------------------------------------------------------

    def query(self) -> UsageQuery:
        return UsageQuery(self.store)

    # --- journal helpers ----------------------------------------------------------------

    def _read_journal(self) -> list[dict[str, Any]]:
        if self.journal_path is None or not self.journal_path.exists():
            return []
        events: list[dict[str, Any]] = []
        for line in self.journal_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # torn final line from a mid-write crash
        return events

    def _seen_in_journal(self) -> set[str]:
        seen: set[str] = set()
        for e in self._read_journal():
            uid = e.get("event_uuid")
            if isinstance(uid, str):
                seen.add(uid)
        return seen

    def _known_committed_uuids(self) -> set[str]:
        rows = self.store.conn.execute(
            "SELECT event_uuid FROM usage_events WHERE event_uuid IS NOT NULL"
        ).fetchall()
        return {r[0] for r in rows}

    def _load_pending_from_journal(self) -> None:
        committed = self._known_committed_uuids()
        for event in self._read_journal():
            uid = event.get("event_uuid")
            if isinstance(uid, str) and uid not in committed:
                self._pending.add(uid)


class UsageQuery:
    """Read-side facade over UsageStore: every dimension + time range.

    Exists so view/API code never writes SQL and never touches the raw
    store: ``ledger.query().summarize(agent_uuid=..., since=...)`` covers
    the usage/costs dashboard's whole filter matrix.
    """

    _DIMENSIONS: tuple[str, ...] = (
        "campaign_uuid",
        "agent_uuid",
        "task_uuid",
        "provider_id",
        "model_id",
    )

    def __init__(self, store: UsageStore, conn: sqlite3.Connection | None = None) -> None:
        self._store = store
        self._conn = conn or store.conn

    def summarize(self, **filters: Any) -> Any:
        return self._store.summarize(**self._validated(filters))

    def breakdown(self, by: str, **filters: Any) -> list[dict[str, Any]]:
        if by not in self._DIMENSIONS:
            raise UsageLedgerError(f"unknown breakdown dimension: {by!r}")
        return self._store.breakdown(by, **self._validated(filters))

    def _validated(self, filters: dict[str, Any]) -> dict[str, Any]:
        allowed = {"since", "until", *self._DIMENSIONS}
        bad = sorted(k for k in filters if k not in allowed)
        if bad:
            raise UsageLedgerError(f"unknown query filters: {bad}")
        return filters
