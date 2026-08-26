"""Time-series metrics store (issue #156, PLAN §14/§16).

Design decisions (per AGENTS.md):

- Local-first, dependency-free: an in-process store with a JSONL persistence
  file. The four §14 metric families (agent, provider/model, research,
  system) are just a ``family`` tag — adding one needs no schema migration.
  A SQLite backend can wrap the same interface later without callers
  changing.
- Records are points: ``(ts, family, name, campaign_id, agent_id, value,
  unit, tags)``. Query API filters by family/name/campaign/agent + arbitrary
  time range, then aggregates with sum / avg / min / max / count / pct.
  Aggregation runs in Python over the filtered slice — small enough locally,
  and it avoids N+1 scans over the event store (#42), which stays the
  tamper-evident event log rather than a metrics backend.
- Retention aligns with §16 retention settings: ``prune(older_than_ts)``
  drops stale points; privacy-preserving by default — no target data in
  tags, only IDs and counts.
- Writes are cheap appends; reads snapshot under a lock so a concurrent
  writer can never produce a torn aggregation.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# The four PLAN §14 metric families.
FAMILIES = ("agent", "provider_model", "research", "system")

AGGREGATIONS = ("sum", "avg", "min", "max", "count", "pct")


@dataclass(frozen=True)
class MetricPoint:
    """One measured value at a moment in time."""

    ts: float
    family: str  # one of FAMILIES
    name: str  # e.g. "tokens_used", "request_latency_ms", "findings_open"
    value: float
    unit: str = ""  # "tokens", "ms", "count", "usd", …
    campaign_id: str | None = None
    agent_id: str | None = None
    tags: dict[str, str] = field(default_factory=dict)  # e.g. {"model": "m1"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "family": self.family,
            "name": self.name,
            "value": self.value,
            "unit": self.unit,
            "campaign_id": self.campaign_id,
            "agent_id": self.agent_id,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> MetricPoint:
        return cls(
            ts=d["ts"],
            family=d["family"],
            name=d["name"],
            value=d["value"],
            unit=d.get("unit", ""),
            campaign_id=d.get("campaign_id"),
            agent_id=d.get("agent_id"),
            tags=d.get("tags") or {},
        )


@dataclass
class MetricQuery:
    """Filter criteria for ``MetricsStore.query`` — all AND-combined."""

    family: str | None = None
    name: str | None = None
    campaign_id: str | None = None
    agent_id: str | None = None
    since: float | None = None
    until: float | None = None

    def matches(self, p: MetricPoint) -> bool:
        if self.family is not None and p.family != self.family:
            return False
        if self.name is not None and p.name != self.name:
            return False
        if self.campaign_id is not None and p.campaign_id != self.campaign_id:
            return False
        if self.agent_id is not None and p.agent_id != self.agent_id:
            return False
        if self.since is not None and p.ts < self.since:
            return False
        if self.until is not None and p.ts > self.until:
            return False
        return True


def aggregate(points: list[MetricPoint], agg: str) -> float:
    """Aggregate a point list. ``pct`` returns the average as a percentage
    (0-100 scale assumed for the underlying values)."""
    if agg not in AGGREGATIONS:
        raise ValueError(f"unknown aggregation '{agg}'")
    if agg == "count":
        return float(len(points))
    if not points:
        return 0.0
    values = [p.value for p in points]
    if agg == "sum":
        return sum(values)
    if agg == "avg":
        return sum(values) / len(values)
    if agg == "min":
        return min(values)
    if agg == "max":
        return max(values)
    if agg == "pct":
        return sum(values) / len(values)
    raise ValueError(f"unknown aggregation '{agg}'")


class MetricsStore:
    """Append-only local time-series store with a query/aggregation API."""

    def __init__(self, path: str | Path | None = None) -> None:
        # JSONL replay on init keeps startup O(file) with zero dependencies;
        # torn final lines (crash mid-write) are tolerated like logs.py.
        self.path = Path(path) if path else None
        self.points: list[MetricPoint] = []
        self._lock = threading.Lock()
        if self.path and self.path.exists():
            with self.path.open(encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        self.points.append(MetricPoint.from_dict(json.loads(line)))
                    except (json.JSONDecodeError, KeyError):
                        continue

    def record(
        self,
        family: str,
        name: str,
        value: float,
        *,
        unit: str = "",
        campaign_id: str | None = None,
        agent_id: str | None = None,
        tags: dict[str, str] | None = None,
        ts: float | None = None,
    ) -> MetricPoint:
        """Append one metric point (persisted before returning when a file
        is configured — same persist-before-deliver rule as the event store)."""
        if family not in FAMILIES:
            raise ValueError(f"unknown metric family '{family}' (expected one of {FAMILIES})")
        pt = MetricPoint(
            ts=ts if ts is not None else time.time(),
            family=family,
            name=name,
            value=float(value),
            unit=unit,
            campaign_id=campaign_id,
            agent_id=agent_id,
            tags=tags or {},
        )
        with self._lock:
            self.points.append(pt)
            if self.path is not None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(pt.to_dict(), sort_keys=True) + "\n")
        return pt

    def query(self, flt: MetricQuery | None = None) -> list[MetricPoint]:
        """Snapshot of matching points ordered by time."""
        flt = flt or MetricQuery()
        with self._lock:
            pts = [p for p in self.points if flt.matches(p)]
        return sorted(pts, key=lambda p: p.ts)

    def aggregate(
        self,
        agg: str,
        flt: MetricQuery | None = None,
    ) -> float:
        """Aggregate matching points in one locked pass."""
        if agg not in AGGREGATIONS:
            raise ValueError(f"unknown aggregation '{agg}'")
        return aggregate(self.query(flt), agg)

    def series(
        self,
        bucket_seconds: float,
        agg: str,
        flt: MetricQuery | None = None,
    ) -> list[tuple[float, float]]:
        """Bucketed time series [(bucket_start_ts, aggregated_value)] for UI
        charts. Empty buckets are omitted."""
        pts = self.query(flt)
        if not pts:
            return []
        buckets: dict[int, list[MetricPoint]] = {}
        for p in pts:
            buckets.setdefault(int(p.ts // bucket_seconds) * int(bucket_seconds), []).append(p)
        return sorted((start, aggregate(group, agg)) for start, group in buckets.items())

    def prune(self, older_than_ts: float) -> int:
        """Drop points older than the cutoff (§16 retention alignment).
        Returns the number removed. Rewrites the file so pruning survives
        restarts."""
        removed = 0
        with self._lock:
            keep = [p for p in self.points if p.ts >= older_than_ts]
            removed = len(self.points) - len(keep)
            self.points = keep
            if self.path is not None and removed:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("w", encoding="utf-8") as f:
                    for p in keep:
                        f.write(json.dumps(p.to_dict(), sort_keys=True) + "\n")
        return removed
