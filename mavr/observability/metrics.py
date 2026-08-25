"""In-process metrics store (spec §14).

Counters, gauges, and histograms are persisted as rows in the
``metric_points`` table (migration 0006). The store exposes small
helpers for the router pool, providers, orchestrator, and the UI.

Free vs paid is always tracked separately: any metric that has a
``provider_id`` dimension must call :meth:`inc_counter` with the
``is_free`` flag, and the free/paid totals are queryable through
:meth:`usage_breakdown`.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from mavr.observability.logging import get_logger
from mavr.storage.database import Database

log = get_logger(__name__)

_VALID_KINDS: frozenset[str] = frozenset({"counter", "gauge", "histogram"})


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _dims_hash(dims: dict[str, Any]) -> str:
    raw = json.dumps(dims, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class MetricPoint:
    name: str
    kind: str
    value: float
    count: int
    bucket: str | None
    dimensions: dict[str, Any]
    is_free: bool
    is_paid: bool
    campaign_id: str | None
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "value": self.value,
            "count": self.count,
            "bucket": self.bucket,
            "dimensions": self.dimensions,
            "is_free": self.is_free,
            "is_paid": self.is_paid,
            "campaign_id": self.campaign_id,
            "created_at": self.created_at,
        }


def _row_to_point(row: Any) -> MetricPoint:
    try:
        dims = json.loads(row["dimensions"]) if row["dimensions"] else {}
    except (TypeError, ValueError):
        dims = {}
    return MetricPoint(
        name=row["name"],
        kind=row["kind"],
        value=float(row["value"]),
        count=int(row["count"]),
        bucket=row["bucket"],
        dimensions=dims if isinstance(dims, dict) else {},
        is_free=bool(row["is_free"]),
        is_paid=bool(row["is_paid"]),
        campaign_id=row["campaign_id"],
        created_at=row["created_at"],
    )


class MetricsStore:
    def __init__(self, db: Database) -> None:
        self._db = db

    async def _insert(
        self,
        *,
        name: str,
        kind: str,
        value: float,
        count: int = 0,
        bucket: str | None = None,
        dimensions: dict[str, Any] | None = None,
        is_free: bool = True,
        is_paid: bool = False,
        campaign_id: str | None = None,
        agent_id: str | None = None,
        task_id: str | None = None,
    ) -> None:
        if kind not in _VALID_KINDS:
            raise ValueError(f"invalid metric kind: {kind!r}")
        from mavr.schemas import entities as schema

        await self._db.execute(
            "INSERT INTO metric_points("
            "schema_version, name, kind, value, count, bucket, dimensions, "
            "is_free, is_paid, campaign_id, agent_id, task_id, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                schema.SCHEMA_VERSION,
                name,
                kind,
                float(value),
                int(count),
                bucket,
                json.dumps(dimensions or {}, separators=(",", ":"), ensure_ascii=False),
                1 if is_free else 0,
                1 if is_paid else 0,
                campaign_id,
                agent_id,
                task_id,
                _now_iso(),
            ),
        )

    async def inc_counter(
        self,
        name: str,
        *,
        amount: float = 1.0,
        dimensions: dict[str, Any] | None = None,
        is_free: bool = True,
        is_paid: bool = False,
        campaign_id: str | None = None,
        agent_id: str | None = None,
        task_id: str | None = None,
    ) -> None:
        await self._insert(
            name=name,
            kind="counter",
            value=float(amount),
            dimensions=dimensions,
            is_free=is_free,
            is_paid=is_paid,
            campaign_id=campaign_id,
            agent_id=agent_id,
            task_id=task_id,
        )

    async def set_gauge(
        self,
        name: str,
        value: float,
        *,
        dimensions: dict[str, Any] | None = None,
        campaign_id: str | None = None,
    ) -> None:
        await self._insert(
            name=name,
            kind="gauge",
            value=float(value),
            dimensions=dimensions,
            campaign_id=campaign_id,
        )

    async def observe_histogram(
        self,
        name: str,
        value: float,
        *,
        bucket: str,
        dimensions: dict[str, Any] | None = None,
        is_free: bool = True,
        is_paid: bool = False,
        campaign_id: str | None = None,
    ) -> None:
        await self._insert(
            name=name,
            kind="histogram",
            value=float(value),
            count=1,
            bucket=bucket,
            dimensions=dimensions,
            is_free=is_free,
            is_paid=is_paid,
            campaign_id=campaign_id,
        )

    async def query(
        self,
        name: str,
        *,
        since: str | None = None,
        until: str | None = None,
        campaign_id: str | None = None,
        limit: int = 1000,
    ) -> list[MetricPoint]:
        clauses = ["name = ?"]
        params: list[Any] = [name]
        if since:
            clauses.append("created_at >= ?")
            params.append(since)
        if until:
            clauses.append("created_at <= ?")
            params.append(until)
        if campaign_id:
            clauses.append("campaign_id = ?")
            params.append(campaign_id)
        params.append(max(1, min(limit, 10000)))
        sql = (
            "SELECT name, kind, value, count, bucket, dimensions, is_free, is_paid, "
            "campaign_id, created_at FROM metric_points WHERE "
            + " AND ".join(clauses)
            + " ORDER BY id DESC LIMIT ?"
        )
        async with self._db.acquire() as conn:
            cur = await conn.execute(sql, params)
            return [_row_to_point(r) for r in await cur.fetchall()]

    async def count(
        self,
        name: str,
        *,
        since: str | None = None,
        until: str | None = None,
        campaign_id: str | None = None,
    ) -> float:
        clauses = ["name = ?", "kind = 'counter'"]
        params: list[Any] = [name]
        if since:
            clauses.append("created_at >= ?")
            params.append(since)
        if until:
            clauses.append("created_at <= ?")
            params.append(until)
        if campaign_id:
            clauses.append("campaign_id = ?")
            params.append(campaign_id)
        sql = (
            "SELECT COALESCE(SUM(value), 0) AS s FROM metric_points WHERE "
            + " AND ".join(clauses)
        )
        async with self._db.acquire() as conn:
            cur = await conn.execute(sql, params)
            row = await cur.fetchone()
            return float(row["s"] if row else 0.0)

    async def gauge_latest(
        self,
        name: str,
        *,
        campaign_id: str | None = None,
    ) -> float | None:
        clauses = ["name = ?", "kind = 'gauge'"]
        params: list[Any] = [name]
        if campaign_id:
            clauses.append("campaign_id = ?")
            params.append(campaign_id)
        sql = (
            "SELECT value FROM metric_points WHERE "
            + " AND ".join(clauses)
            + " ORDER BY id DESC LIMIT 1"
        )
        async with self._db.acquire() as conn:
            cur = await conn.execute(sql, params)
            row = await cur.fetchone()
            return float(row["value"]) if row else None

    async def usage_breakdown(
        self,
        *,
        since: str | None = None,
        until: str | None = None,
        campaign_id: str | None = None,
    ) -> dict[str, Any]:
        """Return per-(provider, model) totals split by free/paid.

        Joins the persisted ``usage_events`` table (the source of truth
        for billing) so the UI can render a consistent picture. If the
        usage_events table is empty, we still report zero rows.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if since:
            clauses.append("created_at >= ?")
            params.append(since)
        if until:
            clauses.append("created_at <= ?")
            params.append(until)
        if campaign_id:
            clauses.append("campaign_id = ?")
            params.append(campaign_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (
            "SELECT provider_id, model_key, "
            "SUM(CASE WHEN is_free THEN 1 ELSE 0 END) AS free_calls, "
            "SUM(CASE WHEN is_paid THEN 1 ELSE 0 END) AS paid_calls, "
            "COALESCE(SUM(input_tokens), 0) AS input_tokens, "
            "COALESCE(SUM(output_tokens), 0) AS output_tokens, "
            "COALESCE(SUM(cache_read_tokens), 0) AS cache_read_tokens, "
            "COALESCE(SUM(cache_write_tokens), 0) AS cache_write_tokens, "
            "COALESCE(SUM(estimated_cost), 0.0) AS cost, "
            "COALESCE(AVG(latency_ms), 0) AS avg_latency "
            "FROM usage_events" + where + " GROUP BY provider_id, model_key"
        )
        async with self._db.acquire() as conn:
            cur = await conn.execute(sql, params)
            rows = list(await cur.fetchall())
        free_total = 0.0
        paid_total = 0.0
        cost_total = 0.0
        items: list[dict[str, Any]] = []
        for r in rows:
            free_calls = int(r["free_calls"] or 0)
            paid_calls = int(r["paid_calls"] or 0)
            cost = float(r["cost"] or 0.0)
            free_total += free_calls
            paid_total += paid_calls
            cost_total += cost
            items.append(
                {
                    "provider_id": r["provider_id"],
                    "model_key": r["model_key"],
                    "free_calls": free_calls,
                    "paid_calls": paid_calls,
                    "input_tokens": int(r["input_tokens"] or 0),
                    "output_tokens": int(r["output_tokens"] or 0),
                    "cache_read_tokens": int(r["cache_read_tokens"] or 0),
                    "cache_write_tokens": int(r["cache_write_tokens"] or 0),
                    "estimated_cost": cost,
                    "avg_latency_ms": float(r["avg_latency"] or 0.0),
                }
            )
        return {
            "free_calls_total": free_total,
            "paid_calls_total": paid_total,
            "estimated_cost_total": cost_total,
            "by_provider_model": items,
        }

    async def prune(self, keep_last: int = 50000) -> int:
        if keep_last <= 0:
            raise ValueError("keep_last must be positive")
        async with self._db.acquire() as conn:
            cur = await conn.execute(
                "DELETE FROM metric_points WHERE id <= ("
                "  SELECT COALESCE(MAX(id), 0) - ? FROM metric_points"
                ")",
                (keep_last,),
            )
            return int(cur.rowcount or 0)


def merge_breakdowns(items: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate usage breakdown items across campaigns or agents."""
    free_total = 0
    paid_total = 0
    cost_total = 0.0
    out: list[dict[str, Any]] = []
    for it in items:
        free_total += int(it.get("free_calls", 0))
        paid_total += int(it.get("paid_calls", 0))
        cost_total += float(it.get("estimated_cost", 0.0))
        out.append(it)
    return {
        "free_calls_total": free_total,
        "paid_calls_total": paid_total,
        "estimated_cost_total": cost_total,
        "items": out,
    }


__all__ = [
    "MetricPoint",
    "MetricsStore",
    "merge_breakdowns",
]
