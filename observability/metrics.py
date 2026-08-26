"""Time-series metrics store (issue #156, PLAN §14).

Design decisions (per AGENTS.md):

- Local-first in-memory store of timestamped metric samples. The four §14
  families (agent, provider/model, research, system) are just a validated
  ``family`` tag — the query API is uniform across them.
- Every sample carries campaign_id (nullable for system-wide metrics), a
  metric name, a numeric value, and free-form tags (e.g. provider/model).
  Queries filter by family, campaign, name, tag equality and an arbitrary
  time range — PLAN §14 requires "queryable by campaign and time range".
- Aggregations (sum / avg / min / max / count / p50 / p95) computed on
  demand; group_by lets UI pages get per-provider/per-model breakdowns in a
  single call instead of N+1 scans.
- Retention: ``prune(older_than_ts)`` drops expired samples so operators can
  wire it to the §16 retention settings; pruning is explicit, not automatic,
  because retention cadence is config, not code.
- Privacy-preserving by default: samples hold only numbers and opaque tag
  strings — no prompt content, no target data ever enters this store.

The in-memory backend is the reference implementation; a SQLite backend
(#53) can persist the same sample shape behind the same interface.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

# The four PLAN §14 metric families. Kept as a closed set so typos fail fast
# at record() time instead of silently creating an unusable slice.
FAMILIES = ("agent", "provider", "research", "system")


class MetricsError(ValueError):
    """Invalid family, aggregation, or sample."""


@dataclass(frozen=True)
class Sample:
    """One metric observation."""

    ts: float
    family: str  # one of FAMILIES
    name: str  # e.g. "tokens_used", "request_latency_ms"
    value: float
    campaign_id: str | None = None  # None = system-wide
    agent_id: str | None = None
    tags: dict[str, str] = field(default_factory=dict)  # e.g. provider/model


class MetricsStore:
    """In-memory time-series store with campaign/time-range queries."""

    def __init__(self) -> None:
        # One flat append-only list: queries scan it linearly, which is fine
        # at local-first scale and keeps prune() trivially correct.
        self._samples: list[Sample] = []

    def record(
        self,
        family: str,
        name: str,
        value: float,
        *,
        ts: float | None = None,
        campaign_id: str | None = None,
        agent_id: str | None = None,
        tags: dict[str, str] | None = None,
    ) -> Sample:
        if family not in FAMILIES:
            raise MetricsError(f"unknown metric family '{family}' (expected one of {FAMILIES})")
        s = Sample(
            ts=time.time() if ts is None else ts,
            family=family,
            name=name,
            value=float(value),
            campaign_id=campaign_id,
            agent_id=agent_id,
            tags=dict(tags or {}),
        )
        self._samples.append(s)
        return s

    def _select(
        self,
        family: str | None = None,
        name: str | None = None,
        campaign_id: str | None = None,
        include_global: bool = True,
        since: float | None = None,
        until: float | None = None,
        tags: dict[str, str] | None = None,
        agent_id: str | None = None,
    ) -> list[Sample]:
        """Shared filter used by both aggregate() and raw()."""
        out = []
        for s in self._samples:
            if family and s.family != family:
                continue
            if name and s.name != name:
                continue
            if agent_id and s.agent_id != agent_id:
                continue
            if campaign_id is not None:
                # Campaign-scoped query optionally folds in global (None)
                # samples — e.g. system health alongside per-campaign usage.
                if s.campaign_id is not None:
                    if s.campaign_id != campaign_id:
                        continue
                elif not include_global:
                    continue
            if since is not None and s.ts < since:
                continue
            if until is not None and s.ts > until:
                continue
            if tags:
                if any(s.tags.get(k) != v for k, v in tags.items()):
                    continue
            out.append(s)
        return out

    def raw(self, **kw: Any) -> list[Sample]:
        """Matching samples in insertion order (time-ascending by contract)."""
        return self._select(**kw)

    def aggregate(
        self,
        agg: str,
        **filters: Any,
    ) -> float | int | None:
        """Aggregate matching samples: sum/avg/min/max/count/p50/p95."""
        values = [s.value for s in self._select(**filters)]
        if agg == "count":
            return len(values)
        if not values:
            return None
        vs = sorted(values)
        if agg == "sum":
            return sum(values)
        if agg == "avg":
            return sum(values) / len(values)
        if agg == "min":
            return vs[0]
        if agg == "max":
            return vs[-1]
        if agg in ("p50", "p95"):
            # Nearest-rank percentile; deterministic, no interpolation.
            import math

            rank = math.ceil((0.5 if agg == "p50" else 0.95) * len(vs))
            return vs[max(rank - 1, 0)]
        raise MetricsError(f"unknown aggregation '{agg}'")

    def group_by(
        self,
        key: str,
        agg: str,
        **filters: Any,
    ) -> dict[str, float | int]:
        """Aggregate grouped by a tag (or 'campaign_id'/'agent_id').

        Powers the usage/cost pages' breakdowns without N+1 queries.
        """
        out: dict[str, list[float]] = {}
        for s in self._select(**filters):
            k = getattr(s, key, None) if hasattr(Sample, key) else s.tags.get(key)
            out.setdefault(str(k), []).append(s.value)
        result: dict[str, float | int] = {}
        for g, vals in out.items():
            vs = sorted(vals)
            if agg == "count":
                result[g] = len(vs)
            elif agg == "sum":
                result[g] = sum(vs)
            elif agg == "avg":
                result[g] = sum(vs) / len(vs)
            elif agg == "min":
                result[g] = vs[0]
            elif agg == "max":
                result[g] = vs[-1]
            else:
                raise MetricsError(f"unknown aggregation '{agg}'")
        return result

    def prune(self, older_than_ts: float) -> int:
        """Drop samples older than the cutoff (§16 retention wiring)."""
        keep = [s for s in self._samples if s.ts >= older_than_ts]
        dropped = len(self._samples) - len(keep)
        self._samples = keep
        return dropped

    def __len__(self) -> int:
        return len(self._samples)
