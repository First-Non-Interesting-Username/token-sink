"""Model score store (spec §8.3).

Each ``(provider_id, model_key, category)`` triple carries a score
between 0 and 1, a sample count, a confidence interval, and a recency
weight. The live writer updates scores as real tasks complete; the
offline benchmark populates them on cold start.
"""
from __future__ import annotations

import math
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from mavr.observability.logging import get_logger
from mavr.schemas.routing import ModelScore, TaskCategory
from mavr.storage.database import Database

log = get_logger(__name__)


class ModelScoreStore:
    """Persistent score store backed by the ``model_scores`` table."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def upsert(self, score: ModelScore) -> None:
        now = _now_iso(score.last_updated)
        await self._db.execute(
            """
            INSERT INTO model_scores(
                id, schema_version, provider_id, model_key, category,
                score, sample_count, confidence_low, confidence_high,
                recency_weight, source, last_updated
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider_id, model_key, category) DO UPDATE SET
                score = excluded.score,
                sample_count = excluded.sample_count,
                confidence_low = excluded.confidence_low,
                confidence_high = excluded.confidence_high,
                recency_weight = excluded.recency_weight,
                source = excluded.source,
                last_updated = excluded.last_updated
            """,
            (
                str(uuid4()),
                "1.0.0",
                score.provider_id,
                score.model_key,
                score.category.value,
                float(score.score),
                int(score.sample_count),
                float(score.confidence_low),
                float(score.confidence_high),
                float(score.recency_weight),
                score.source,
                now,
            ),
        )

    async def get(
        self,
        provider_id: str,
        model_key: str,
        category: TaskCategory,
    ) -> ModelScore | None:
        row = await self._db.fetchone(
            """
            SELECT provider_id, model_key, category, score, sample_count,
                   confidence_low, confidence_high, recency_weight, source, last_updated
            FROM model_scores
            WHERE provider_id = ? AND model_key = ? AND category = ?
            """,
            (provider_id, model_key, category.value),
        )
        if row is None:
            return None
        return _row_to_score(row)

    async def for_category(self, category: TaskCategory) -> list[ModelScore]:
        rows = await self._db.fetchall(
            """
            SELECT provider_id, model_key, category, score, sample_count,
                   confidence_low, confidence_high, recency_weight, source, last_updated
            FROM model_scores
            WHERE category = ?
            ORDER BY score DESC, provider_id ASC, model_key ASC
            """,
            (category.value,),
        )
        return [_row_to_score(r) for r in rows]

    async def all(self) -> list[ModelScore]:
        rows = await self._db.fetchall(
            """
            SELECT provider_id, model_key, category, score, sample_count,
                   confidence_low, confidence_high, recency_weight, source, last_updated
            FROM model_scores
            """
        )
        return [_row_to_score(r) for r in rows]

    async def update_from_samples(
        self,
        provider_id: str,
        model_key: str,
        category: TaskCategory,
        samples: Iterable[float],
        *,
        source: Literal['benchmark', 'live', 'manual'] = "live",
    ) -> ModelScore:
        """Recompute score from a fresh batch of samples.

        Uses a Wilson-style lower-bound on the success rate as
        ``confidence_low`` and the upper bound as ``confidence_high``.
        Recency weight decays exponentially with the number of samples
        since the last update.
        """
        vals = [float(s) for s in samples]
        n = len(vals)
        if n == 0:
            raise ValueError("at least one sample required")
        m = sum(vals) / n
        low, high = _wilson_bounds(successes=sum(1 for v in vals if v > 0.5), n=n)
        existing = await self.get(provider_id, model_key, category)
        if existing is not None and existing.sample_count > 0:
            # exponential decay of the prior estimate
            decay = 0.5 ** (n / max(existing.sample_count, 1))
            new_score = decay * existing.score + (1 - decay) * m
            n_total = existing.sample_count + n
        else:
            new_score = m
            n_total = n
        new_score = max(0.0, min(1.0, new_score))
        score = ModelScore(
            provider_id=provider_id,
            model_key=model_key,
            category=category,
            score=new_score,
            sample_count=n_total,
            confidence_low=low,
            confidence_high=high,
            recency_weight=_recency_weight(n_total),
            source=source,
        )
        await self.upsert(score)
        return score


# ---- helpers -----------------------------------------------------------


def _wilson_bounds(*, successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson interval for a Bernoulli proportion. Returns (low, high) in [0, 1]."""
    if n == 0:
        return 0.0, 0.0
    p = successes / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n) / denom
    low = max(0.0, center - margin)
    high = min(1.0, center + margin)
    return low, high


def _recency_weight(sample_count: int) -> float:
    # weight approaches 1 as sample_count grows; older models with few
    # samples are deweighted in default-policy scoring.
    return min(1.0, sample_count / 10.0)


def _now_iso(dt: datetime | None = None) -> str:
    return (dt or datetime.now(UTC)).isoformat()


def _row_to_score(row: Any) -> ModelScore:
    return ModelScore(
        provider_id=row["provider_id"],
        model_key=row["model_key"],
        category=TaskCategory(row["category"]),
        score=float(row["score"]),
        sample_count=int(row["sample_count"]),
        confidence_low=float(row["confidence_low"]),
        confidence_high=float(row["confidence_high"]),
        recency_weight=float(row["recency_weight"]),
        source=row["source"],
        last_updated=datetime.fromisoformat(row["last_updated"]),
    )
