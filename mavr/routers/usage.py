"""Usage accounting.

Every adapter call (or skipped-dead-letter) emits a
:class:`mavr.schemas.entities.UsageEvent` row. The writer enforces the
free/paid separation: an event with ``is_paid=True`` MUST have
``is_free=False``, and the writer derives the cost from the model's
declared pricing when available.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from mavr.observability.logging import get_logger
from mavr.schemas.routing import UsageInfo
from mavr.storage.database import Database

log = get_logger(__name__)


class UsageAccountant:
    def __init__(self, db: Database) -> None:
        self._db = db

    async def record(
        self,
        *,
        provider_id: str,
        model_key: str,
        usage: UsageInfo,
        latency_ms: int,
        is_free: bool,
        agent_id: str | None = None,
        task_id: str | None = None,
        campaign_id: str | None = None,
    ) -> str:
        # free/paid invariant: paid -> not free
        if not is_free:
            is_free_eff = False
            is_paid = True
        else:
            is_free_eff = True
            is_paid = False

        cost = float(usage.estimated_cost or 0.0)
        if cost == 0.0 and (not is_free_eff):
            # best-effort derivation from pricing metadata if cost not set
            cost = await self._estimate_cost_from_pricing(
                provider_id, model_key, usage
            )

        # Validate FK targets. If the task_id or agent_id or campaign_id
        # don't exist in the DB (e.g. synthetic ids in unit tests),
        # drop the FK to keep the usage event itself (the event is the
        # source of truth for billing/usage).
        if task_id is not None:
            row = await self._db.fetchone("SELECT id FROM tasks WHERE id = ?", (task_id,))
            if row is None:
                task_id = None
        if campaign_id is not None:
            row = await self._db.fetchone("SELECT id FROM campaigns WHERE id = ?", (campaign_id,))
            if row is None:
                campaign_id = None
        if agent_id is not None:
            row = await self._db.fetchone("SELECT id FROM agents WHERE id = ?", (agent_id,))
            if row is None:
                agent_id = None

        event_id = f"{provider_id}:{model_key}:{task_id or 'task'}:{int(datetime.now(UTC).timestamp() * 1000)}"
        row_id = str(uuid4())
        await self._db.execute(
            """
            INSERT INTO usage_events(
                id, event_id, schema_version, campaign_id, agent_id, task_id,
                provider_id, model_key, input_tokens, output_tokens,
                cache_read_tokens, cache_write_tokens, latency_ms,
                is_free, is_paid, estimated_cost, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row_id,
                event_id,
                "1.0.0",
                campaign_id,
                agent_id,
                task_id,
                provider_id,
                model_key,
                int(usage.input_tokens),
                int(usage.output_tokens),
                int(usage.cache_read_tokens),
                int(usage.cache_write_tokens),
                int(latency_ms),
                1 if is_free_eff else 0,
                1 if is_paid else 0,
                float(cost),
                datetime.now(UTC).isoformat(),
            ),
        )
        return event_id

    async def totals(self, *, campaign_id: str | None = None) -> dict[str, Any]:
        if campaign_id is None:
            row = await self._db.fetchone(
                """
                SELECT
                    COALESCE(SUM(input_tokens), 0) AS in_t,
                    COALESCE(SUM(output_tokens), 0) AS out_t,
                    COALESCE(SUM(cache_read_tokens), 0) AS cache_in,
                    COALESCE(SUM(cache_write_tokens), 0) AS cache_out,
                    COALESCE(SUM(estimated_cost), 0.0) AS cost,
                    COALESCE(SUM(CASE WHEN is_free=1 THEN 1 ELSE 0 END), 0) AS free_count,
                    COALESCE(SUM(CASE WHEN is_paid=1 THEN 1 ELSE 0 END), 0) AS paid_count,
                    COALESCE(SUM(latency_ms), 0) AS latency_total,
                    COUNT(*) AS n
                FROM usage_events
                """
            )
        else:
            row = await self._db.fetchone(
                """
                SELECT
                    COALESCE(SUM(input_tokens), 0) AS in_t,
                    COALESCE(SUM(output_tokens), 0) AS out_t,
                    COALESCE(SUM(cache_read_tokens), 0) AS cache_in,
                    COALESCE(SUM(cache_write_tokens), 0) AS cache_out,
                    COALESCE(SUM(estimated_cost), 0.0) AS cost,
                    COALESCE(SUM(CASE WHEN is_free=1 THEN 1 ELSE 0 END), 0) AS free_count,
                    COALESCE(SUM(CASE WHEN is_paid=1 THEN 1 ELSE 0 END), 0) AS paid_count,
                    COALESCE(SUM(latency_ms), 0) AS latency_total,
                    COUNT(*) AS n
                FROM usage_events
                WHERE campaign_id = ?
                """,
                (campaign_id,),
            )
        return dict(row) if row else {}

    async def _estimate_cost_from_pricing(
        self, provider_id: str, model_key: str, usage: UsageInfo
    ) -> float:
        row = await self._db.fetchone(
            """
            SELECT m.pricing_input_per_mtok, m.pricing_output_per_mtok
            FROM models m JOIN providers p ON m.provider_id = p.id
            WHERE p.provider_id = ? AND m.model_key = ?
            """,
            (provider_id, model_key),
        )
        if row is None:
            return 0.0
        in_per = row["pricing_input_per_mtok"]
        out_per = row["pricing_output_per_mtok"]
        cost = 0.0
        if in_per is not None:
            cost += (usage.input_tokens / 1_000_000) * float(in_per)
        if out_per is not None:
            cost += (usage.output_tokens / 1_000_000) * float(out_per)
        return float(cost)
