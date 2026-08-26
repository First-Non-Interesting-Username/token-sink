"""Usage accounting storage backend (issue #204, PLAN §13.5).

Records token/request usage events with attribution dimensions (campaign,
agent, task, provider, model, free/paid split) and provides aggregation
queries backing the UI cost dashboard (§13.5) and budget enforcement (§14).

Design decisions:

- **Schema-validated on write**: every event must validate against
  ``schemas/usage_event.schema.json`` before it is persisted — the same
  binary acceptance rule ``schemas/validate.py`` applies to agent output.
  Invalid events raise :class:`UsageEventError` rather than being coerced.
- **Dedicated columns, not a JSON blob**: attribution dimensions get real
  columns (migration 003) so aggregation is index-backed SQL instead of a
  table scan over JSON payloads.
- **Idempotent per event_uuid**: re-recording the same event (provider retry,
  crash between request and accounting) is a no-op, mirroring the records
  store's idempotency semantics.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from schemas.validate import SchemaRegistry


class UsageEventError(ValueError):
    """A usage event failed schema validation or has an invalid window."""


@dataclass(frozen=True)
class UsageSummary:
    """Aggregated usage over one query window."""

    requests: int
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    estimated_cost_usd: float
    free_requests: int
    paid_requests: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "estimated_cost_usd": self.estimated_cost_usd,
            "free_requests": self.free_requests,
            "paid_requests": self.paid_requests,
        }


_VALID_STATUSES = {"success", "error", "timeout", "rate_limited"}

# Aggregation dimensions map to their column names; the WHERE clause is built
# only from these fixed keys so no caller-supplied string ever reaches SQL.
_DIMENSION_COLUMNS = {
    "campaign_uuid": "campaign_uuid",
    "agent_uuid": "agent_uuid",
    "task_uuid": "task_uuid",
    "provider_id": "provider",
    "model_id": "model",
}


def _utcnow() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class UsageStore:
    """SQLite-backed usage-event recorder + aggregator.

    Shares the database connection with :class:`storage.sqlite.SQLiteStorage`
    so accounting commits participate in the same WAL database and the same
    forward-only migration history (table created by migrations 002/003).
    """

    def __init__(self, conn: sqlite3.Connection, registry: SchemaRegistry | None = None):
        self.conn = conn
        self._registry = registry if registry is not None else SchemaRegistry()

    # --- recording ---

    def record_event(self, event: dict[str, Any]) -> str:
        """Validate and persist one usage event; returns its event_uuid.

        Raises UsageEventError when the payload does not match
        schemas/usage_event.schema.json. Recording the same event_uuid twice
        is an idempotent no-op (returns the existing uuid).
        """
        result = self._registry.validate("usage_event", event)
        if not result.valid:
            raise UsageEventError(f"invalid usage event: {result.errors}")

        event_uuid = event["event_uuid"]
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO usage_events (
                    event_uuid, campaign_uuid, agent_uuid, task_uuid,
                    provider, model,
                    input_tokens, output_tokens,
                    cache_read_tokens, cache_write_tokens,
                    is_free_tier, estimated_cost_usd, latency_ms,
                    request_status, recorded_at, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          COALESCE(?, strftime('%Y-%m-%dT%H:%M:%fZ','now')), ?)
                ON CONFLICT(event_uuid) DO NOTHING
                """,
                (
                    event_uuid,
                    event.get("campaign_uuid"),
                    event.get("agent_uuid"),
                    event.get("task_uuid"),
                    event["provider_id"],
                    event["model_id"],
                    event["input_tokens"],
                    event["output_tokens"],
                    event.get("cache_read_tokens"),
                    event.get("cache_write_tokens"),
                    1 if event["is_free_tier"] else 0,
                    event.get("estimated_cost_usd"),
                    event.get("latency_ms"),
                    event["request_status"],
                    event.get("recorded_at"),
                    event["occurred_at"],
                ),
            )
        return event_uuid

    @staticmethod
    def new_event(
        campaign_uuid: str,
        agent_uuid: str,
        provider_id: str,
        model_id: str,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        task_uuid: str | None = None,
        is_free_tier: bool = False,
        estimated_cost_usd: float | None = None,
        latency_ms: int | None = None,
        request_status: str = "success",
        occurred_at: str | None = None,
    ) -> dict[str, Any]:
        """Build a schema-valid usage event with sane defaults."""
        if request_status not in _VALID_STATUSES:
            raise UsageEventError(f"unknown request_status: {request_status!r}")
        return {
            "schema_version": 1,
            "record_type": "usage_event",
            "event_uuid": str(uuid.uuid4()),
            "campaign_uuid": campaign_uuid,
            "agent_uuid": agent_uuid,
            "task_uuid": task_uuid,
            "provider_id": provider_id,
            "model_id": model_id,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "is_free_tier": is_free_tier,
            "estimated_cost_usd": estimated_cost_usd,
            "latency_ms": latency_ms,
            "request_status": request_status,
            "occurred_at": occurred_at or _utcnow(),
        }

    # --- aggregation ---

    def _window_clause(
        self,
        dimensions: dict[str, str | None],
        since: str | None,
        until: str | None,
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        for key, column in _DIMENSION_COLUMNS.items():
            value = dimensions.get(key)
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        if since is not None:
            clauses.append("occurred_at >= ?")
            params.append(since)
        if until is not None:
            clauses.append("occurred_at <= ?")
            params.append(until)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def summarize(
        self,
        *,
        campaign_uuid: str | None = None,
        agent_uuid: str | None = None,
        task_uuid: str | None = None,
        provider_id: str | None = None,
        model_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> UsageSummary:
        """Aggregate totals over the given attribution window."""
        where, params = self._window_clause(
            {
                "campaign_uuid": campaign_uuid,
                "agent_uuid": agent_uuid,
                "task_uuid": task_uuid,
                "provider_id": provider_id,
                "model_id": model_id,
            },
            since,
            until,
        )
        row = self.conn.execute(
            f"""
            SELECT COUNT(*) AS requests,
                   COALESCE(SUM(input_tokens), 0) AS input_tokens,
                   COALESCE(SUM(output_tokens), 0) AS output_tokens,
                   COALESCE(SUM(cache_read_tokens), 0) AS cache_read_tokens,
                   COALESCE(SUM(cache_write_tokens), 0) AS cache_write_tokens,
                   COALESCE(SUM(estimated_cost_usd), 0.0) AS estimated_cost_usd,
                   COALESCE(SUM(is_free_tier), 0) AS free_requests
            FROM usage_events {where}
            """,
            params,
        ).fetchone()
        return UsageSummary(
            requests=row["requests"],
            input_tokens=row["input_tokens"],
            output_tokens=row["output_tokens"],
            cache_read_tokens=row["cache_read_tokens"],
            cache_write_tokens=row["cache_write_tokens"],
            estimated_cost_usd=row["estimated_cost_usd"],
            free_requests=row["free_requests"],
            paid_requests=row["requests"] - row["free_requests"],
        )

    def breakdown(
        self,
        by: str,
        *,
        campaign_uuid: str | None = None,
        agent_uuid: str | None = None,
        task_uuid: str | None = None,
        provider_id: str | None = None,
        model_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> list[dict[str, Any]]:
        """Per-value usage totals grouped by one dimension.

        `by` accepts campaign_uuid / agent_uuid / task_uuid /
        provider_id / model_id. Returns rows ordered by total tokens
        (input+output), descending.
        """
        if by not in _DIMENSION_COLUMNS:
            raise UsageEventError(f"unknown breakdown dimension: {by!r}")
        group_col = _DIMENSION_COLUMNS[by]
        where, params = self._window_clause(
            {
                "campaign_uuid": campaign_uuid,
                "agent_uuid": agent_uuid,
                "task_uuid": task_uuid,
                "provider_id": provider_id,
                "model_id": model_id,
            },
            since,
            until,
        )
        rows = self.conn.execute(
            f"""
            SELECT {group_col} AS dimension,
                   COUNT(*) AS requests,
                   COALESCE(SUM(input_tokens), 0) AS input_tokens,
                   COALESCE(SUM(output_tokens), 0) AS output_tokens,
                   COALESCE(SUM(estimated_cost_usd), 0.0) AS estimated_cost_usd,
                   COALESCE(SUM(is_free_tier), 0) AS free_requests
            FROM usage_events {where}
            GROUP BY {group_col}
            ORDER BY (COALESCE(SUM(input_tokens), 0) + COALESCE(SUM(output_tokens), 0)) DESC
            """,
            params,
        ).fetchall()
        out = []
        for r in rows:
            item = dict(r)
            item["paid_requests"] = item.pop("requests") - item.pop("free_requests")
            item["free_requests"] = r["free_requests"]
            out.append(item)
        return out
