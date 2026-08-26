"""UI usage & cost dashboard read-model (issue #148, PLAN §13.5 view 5).

Sits on top of :class:`storage.usage.UsageStore` (the accounting backend from
#204/#28) and shapes its data for the dashboard UI:

- **Time-range selector + dimension filters** → totals
  (:meth:`UsageDashboard.totals`) and per-breakdown tables
  (:meth:`UsageDashboard.breakdown`) over provider / model / campaign /
  agent / task.
- **Free/paid separation** — every row carries free vs paid request counts
  and free vs paid token/cost splits so free-tier usage is visually and
  numerically separated from paid, per the issue's acceptance criteria.
  Splits are computed by conditional aggregation in SQL (one extra query per
  call) rather than changing UsageStore's public query surface.
- **Unknown pricing** — events recorded without an estimated cost surface as
  ``cost_known=False``; the UI renders "—" instead of inventing a number.
- **Export** — :meth:`UsageDashboard.export` renders any displayed slice as
  CSV or JSON with a stable column order so scheduled exports diff cleanly.

This is a *read model*: it never writes usage events. Recording stays in
``storage/usage.py`` so schema-validation and idempotency guarantees live in
exactly one place.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from storage.usage import UsageEventError, UsageStore

# Breakdown dimensions the dashboard exposes, in display order.
DASHBOARD_DIMENSIONS = ("provider_id", "model_id", "campaign_uuid", "agent_uuid", "task_uuid")

# Stable CSV/JSON export columns; free/paid splits get separate columns so a
# spreadsheet consumer can filter without parsing.
EXPORT_COLUMNS = (
    "dimension",
    "value",
    "requests",
    "free_requests",
    "paid_requests",
    "input_tokens",
    "output_tokens",
    "input_tokens_free",
    "input_tokens_paid",
    "output_tokens_free",
    "output_tokens_paid",
    "estimated_cost_usd",
    "estimated_cost_usd_free",
    "estimated_cost_usd_paid",
    "cost_known",
)

# Column name → usage_events column, for the GROUP BY dimension. Mirrors
# storage.usage._DIMENSION_COLUMNS; kept here so this module owns its API.
_DIMENSIONS = {
    "provider_id": "provider",
    "model_id": "model",
    "campaign_uuid": "campaign_uuid",
    "agent_uuid": "agent_uuid",
    "task_uuid": "task_uuid",
}

# Conditional-aggregation fragments shared by totals and breakdown queries.
_SPLITS_SELECT = """
    COALESCE(SUM(CASE WHEN is_free_tier THEN input_tokens ELSE 0 END), 0)
        AS input_tokens_free,
    COALESCE(SUM(CASE WHEN NOT is_free_tier THEN input_tokens ELSE 0 END), 0)
        AS input_tokens_paid,
    COALESCE(SUM(CASE WHEN is_free_tier THEN output_tokens ELSE 0 END), 0)
        AS output_tokens_free,
    COALESCE(SUM(CASE WHEN NOT is_free_tier THEN output_tokens ELSE 0 END), 0)
        AS output_tokens_paid,
    COALESCE(SUM(CASE WHEN is_free_tier THEN estimated_cost_usd ELSE 0 END), 0.0)
        AS estimated_cost_usd_free,
    COALESCE(SUM(CASE WHEN NOT is_free_tier THEN estimated_cost_usd ELSE 0 END), 0.0)
        AS estimated_cost_usd_paid
"""


class UsageDashboard:
    """Read-model queries backing the §13.5 cost dashboard."""

    def __init__(self, usage_store: UsageStore):
        self.store = usage_store

    # -- window building ------------------------------------------------------

    def _window(
        self,
        since: str | None,
        until: str | None,
        filters: dict[str, str | None],
    ) -> tuple[str, list[Any]]:
        """WHERE clause + params from time range and dimension filters.

        Built only from fixed column names — caller-supplied values are bound
        parameters, never string-interpolated (same posture as UsageStore).
        Unknown filter keys raise instead of silently matching nothing.
        """
        clauses: list[str] = []
        params: list[Any] = []
        for key, value in filters.items():
            if value is None:
                continue
            if key not in _DIMENSIONS:
                raise ValueError(f"unknown filter dimension: {key!r}")
            clauses.append(f"{_DIMENSIONS[key]} = ?")
            params.append(value)
        if since is not None:
            clauses.append("occurred_at >= ?")
            params.append(since)
        if until is not None:
            clauses.append("occurred_at <= ?")
            params.append(until)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def _cond(self, where: str, extra: str) -> str:
        """Join a WHERE clause with an extra condition, handling empty WHERE."""
        if len(where) > 6:  # non-empty "WHERE ..."
            return f"{where} AND {extra}"
        return f"WHERE {extra}"

    @staticmethod
    def _known(filters: dict) -> dict:
        """Drop unknown filter keys after validation raised for them in _window.

        Kept as a tiny helper so totals() validates first, then forwards only
        dimensions UsageStore understands.
        """
        return {k: v for k, v in filters.items() if v is not None}

    # -- public API ------------------------------------------------------------

    def totals(
        self, *, since: str | None = None, until: str | None = None, **filters
    ) -> dict[str, Any]:
        """Overall totals for the selected time range and dimension filters."""
        where, params = self._window(since, until, filters)  # validates filters first
        base = self.store.summarize(since=since, until=until, **self._known(filters)).as_dict()
        unknown = self._cond(where, "estimated_cost_usd IS NULL")
        splits = self.store.conn.execute(
            f"""
            SELECT {_SPLITS_SELECT},
                   EXISTS(SELECT 1 FROM usage_events {unknown}) AS has_unknown_cost
            FROM usage_events {where}
            """,
            params + params,
        ).fetchone()
        row = dict(base)
        row.update(dict(zip(tuple(splits.keys()), tuple(splits), strict=True)))
        row["cost_known"] = not splits["has_unknown_cost"]
        del row["has_unknown_cost"]
        return row

    def breakdown(
        self,
        by: str,
        *,
        since: str | None = None,
        until: str | None = None,
        **filters,
    ) -> list[dict[str, Any]]:
        """Per-value table for one dashboard dimension, ordered by total tokens."""
        if by not in _DIMENSIONS:
            raise ValueError(
                f"unknown dashboard dimension: {by!r} (expected one of {DASHBOARD_DIMENSIONS})"
            )
        group_col = _DIMENSIONS[by]
        where, params = self._window(since, until, filters)
        inner_unknown = self._cond(where, "e2.estimated_cost_usd IS NULL")
        rows = self.store.conn.execute(
            f"""
            SELECT {group_col} AS value,
                   COUNT(*) AS requests,
                   SUM(is_free_tier) AS free_requests,
                   COUNT(*) - SUM(is_free_tier) AS paid_requests,
                   COALESCE(SUM(input_tokens), 0) AS input_tokens,
                   COALESCE(SUM(output_tokens), 0) AS output_tokens,
                   {_SPLITS_SELECT},
                   EXISTS(SELECT 1 FROM usage_events e2
                          WHERE e2.{group_col} = usage_events.{group_col}
                            AND {inner_unknown[6:]}) AS has_unknown_cost
            FROM usage_events {where}
            GROUP BY {group_col}
            ORDER BY (COALESCE(SUM(input_tokens), 0) + COALESCE(SUM(output_tokens), 0)) DESC
            """,
            params + params,
        ).fetchall()
        out = []
        for r in rows:
            item = dict(r)
            item["cost_known"] = not item.pop("has_unknown_cost")
            item["dimension"] = by
            out.append(item)
        return out

    def export(
        self,
        fmt: str,
        by: str | None = None,
        *,
        since: str | None = None,
        until: str | None = None,
        **filters,
    ) -> tuple[str, str]:
        """Export a slice as ``(content_type, body)``; fmt is 'csv' or 'json'.

        With ``by`` set, exports that breakdown table; otherwise exports a
        single-row totals slice. Column order follows EXPORT_COLUMNS.
        """
        rows = (
            self.breakdown(by, since=since, until=until, **filters)
            if by
            else [self.totals(since=since, until=until, **filters)]
        )
        if fmt == "json":
            return "application/json", json.dumps(rows, indent=2)
        if fmt == "csv":
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=list(EXPORT_COLUMNS), extrasaction="ignore")
            writer.writeheader()
            for r in rows:
                writer.writerow({k: r.get(k) for k in EXPORT_COLUMNS})
            return "text/csv", buf.getvalue()
        raise ValueError(f"unknown export format: {fmt!r}")


# UsageEventError re-exported so API layers can map it to HTTP 400 without
# importing from storage directly.
__all__ = ["DASHBOARD_DIMENSIONS", "EXPORT_COLUMNS", "UsageDashboard", "UsageEventError"]
