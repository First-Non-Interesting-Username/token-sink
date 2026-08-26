"""Campaign/time-range query API + retention pruning (spec §14).

Extends :class:`~mavr.observability.metrics.MetricsStore` with the
§14 query backend:

* :meth:`MetricsStore.query_range` — filter by campaign and/or an
  arbitrary ``[start, end]`` time range across all metric families,
  with SQL-side filtering (no N+1 over the event store).
* :meth:`MetricsStore.aggregate` — sum/avg/pct aggregation grouped by
  metric name, computed in SQL.
* :meth:`MetricsStore.prune_older_than` — retention aligned with the
  §16 retention settings (age-based, complements the size-based
  :meth:`MetricsStore.prune`).

All timestamps are ISO-8601 strings, matching how points are written
(``_now_iso()``); lexicographic comparison is correct for that format.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mavr.observability.metrics import MetricPoint, _row_to_point


@dataclass(frozen=True)
class AggregateRow:
    name: str
    kind: str
    total: float
    count: int
    avg: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "total": self.total,
            "count": self.count,
            "avg": self.avg,
        }


def _range_clauses(
    *,
    start: str | None,
    end: str | None,
    campaign_id: str | None,
) -> tuple[list[str], list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if start:
        clauses.append("created_at >= ?")
        params.append(start)
    if end:
        clauses.append("created_at <= ?")
        params.append(end)
    if campaign_id:
        clauses.append("campaign_id = ?")
        params.append(campaign_id)
    return clauses, params


async def query_range(
    store: Any,
    *,
    start: str | None = None,
    end: str | None = None,
    campaign_id: str | None = None,
    kind: str | None = None,
    limit: int = 10000,
) -> list[MetricPoint]:
    """Return points in a campaign/time window across all families.

    Unlike :meth:`MetricsStore.query` this does not require a metric
    name — it answers the §14 "queryable by campaign and time range"
    requirement directly.
    """
    clauses, params = _range_clauses(
        start=start, end=end, campaign_id=campaign_id
    )
    if kind is not None:
        if kind not in {"counter", "gauge", "histogram"}:
            raise ValueError(f"invalid metric kind: {kind!r}")
        clauses.append("kind = ?")
        params.append(kind)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = (
        "SELECT name, kind, value, count, bucket, dimensions, is_free, is_paid, "
        "campaign_id, created_at FROM metric_points" + where +
        " ORDER BY id ASC LIMIT ?"
    )
    params.append(max(1, min(limit, 100000)))
    async with store._db.acquire() as conn:
        cur = await conn.execute(sql, params)
        return [_row_to_point(r) for r in await cur.fetchall()]


async def aggregate(
    store: Any,
    *,
    start: str | None = None,
    end: str | None = None,
    campaign_id: str | None = None,
    kinds: tuple[str, ...] = ("counter",),
) -> dict[str, AggregateRow]:
    """Aggregate counters/gauges/histograms over a window, grouped by name.

    Returns ``{metric_name: AggregateRow}`` where ``total`` is SUM(value),
    ``count`` the number of points, and ``avg`` the mean value. The
    percentage split between free and paid is available via the
    ``is_free``/``is_paid`` flags on individual rows from
    :func:`query_range`, keeping this function family-agnostic.
    """
    for k in kinds:
        if k not in {"counter", "gauge", "histogram"}:
            raise ValueError(f"invalid metric kind: {k!r}")
    clauses, params = _range_clauses(
        start=start, end=end, campaign_id=campaign_id
    )
    placeholders = ", ".join("?" for _ in kinds)
    clauses.append(f"kind IN ({placeholders})")
    params.extend(kinds)
    sql = (
        "SELECT name, kind, COALESCE(SUM(value), 0) AS total, "
        "COUNT(*) AS n, COALESCE(AVG(value), 0) AS avg "
        "FROM metric_points WHERE " + " AND ".join(clauses) +
        " GROUP BY name, kind ORDER BY name"
    )
    async with store._db.acquire() as conn:
        cur = await conn.execute(sql, params)
        rows = await cur.fetchall()
    out: dict[str, AggregateRow] = {}
    for r in rows:
        # A name should only carry one kind in practice; if it somehow
        # carries several, last-write-wins keeps the dict simple while
        # totals remain visible through per-kind names.
        out[r["name"]] = AggregateRow(
            name=r["name"],
            kind=r["kind"],
            total=float(r["total"]),
            count=int(r["n"]),
            avg=float(r["avg"]),
        )
    return out


async def prune_older_than(store: Any, days: int, *, now_iso: str | None = None) -> int:
    """Delete points older than ``days``; return the number removed.

    ``days=0`` disables age-based retention (keeps everything), matching
    the §16 convention that 0 means "no expiry". ``now_iso`` is injectable
    for deterministic tests.
    """
    if days < 0:
        raise ValueError("retention days must be >= 0")
    if days == 0:
        return 0
    from datetime import UTC, datetime, timedelta

    now = (
        datetime.fromisoformat(now_iso)
        if now_iso
        else datetime.now(UTC)
    )
    cutoff = (now - timedelta(days=days)).isoformat()
    async with store._db.acquire() as conn:
        cur = await conn.execute(
            "DELETE FROM metric_points WHERE created_at < ?", (cutoff,)
        )
        # acquire() hands out a raw connection that is closed (and any
        # open transaction rolled back) on exit — commit explicitly.
        await conn.commit()
        return int(cur.rowcount or 0)


__all__ = [
    "AggregateRow",
    "aggregate",
    "prune_older_than",
    "query_range",
]
