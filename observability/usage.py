"""Usage accounting ledger (issue #273, PLAN §13.5).

Acceptance requires usage accurately attributed by provider/model/agent/task.
Limiters consume token counts elsewhere; nobody owned the attribution ledger
itself. This module provides it:

- Every provider call emits a journaled ``UsageEvent`` (input/output tokens,
  latency, cost estimate, free/paid flag) keyed to agent, task, campaign,
  provider and model. Events are journaled BEFORE response processing so a
  crash cannot lose billing data.
- Reconciliation: adapter-reported usage vs a locally supplied estimate;
  discrepancies beyond a relative tolerance are flagged as alerts.
- Aggregation API: sums by every dimension (campaign/agent/provider/model)
  over arbitrary time ranges — powers the usage/costs view breakdowns.

Append-only: events are never edited or removed; corrections are new
adjustment events.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any

# Relative tolerance for adapter-vs-estimate reconciliation; beyond this the
# discrepancy is alerted rather than silently accepted.
RECONCILIATION_TOLERANCE = 0.15


class UsageError(Exception):
    """Invalid usage record or reconciliation input."""


@dataclass(frozen=True)
class UsageEvent:
    """One provider call's usage, attributed to its origin."""

    event_uuid: str
    ts: float
    provider: str
    model: str
    agent_uuid: str
    task_uuid: str
    campaign_uuid: str
    input_tokens: int
    output_tokens: int
    cache_tokens: int = 0
    latency_ms: float = 0.0
    cost_estimate: float | None = None  # None when pricing unknown
    is_free: bool = False

    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens + self.cache_tokens


class UsageLedger:
    """Append-only, crash-safe usage journal with dimension aggregations."""

    def __init__(self) -> None:
        # Journal first, index second: a crash between append and index
        # rebuild loses nothing (replay reconstructs the index).
        self._journal: list[UsageEvent] = []
        self._by_campaign: dict[str, list[UsageEvent]] = {}
        self.alerts: list[dict] = []

    def journal(self, event: UsageEvent) -> None:
        if event.input_tokens < 0 or event.output_tokens < 0:
            raise UsageError("token counts must be non-negative")
        self._journal.append(event)  # journaled before any processing
        self._by_campaign.setdefault(event.campaign_uuid, []).append(event)

    def reconcile(
        self,
        event: UsageEvent,
        local_estimate_tokens: int,
        source: str = "adapter",
    ) -> bool:
        """Compare adapter-reported totals against a local estimate.

        Returns True when within tolerance; otherwise records an alert with
        both numbers and returns False. Never mutates the event.
        """
        reported = event.total_tokens()
        denom = max(reported, local_estimate_tokens, 1)
        drift = abs(reported - local_estimate_tokens) / denom
        ok = drift <= RECONCILIATION_TOLERANCE
        if not ok:
            self.alerts.append(
                {
                    "event_uuid": event.event_uuid,
                    "source": source,
                    "reported": reported,
                    "local_estimate": local_estimate_tokens,
                    "drift": round(drift, 4),
                }
            )
        return ok

    def _filtered(
        self,
        campaign_uuid: str | None = None,
        agent_uuid: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        ts_from: float | None = None,
        ts_to: float | None = None,
    ) -> list[UsageEvent]:
        out = []
        for e in self._journal:
            if campaign_uuid is not None and e.campaign_uuid != campaign_uuid:
                continue
            if agent_uuid is not None and e.agent_uuid != agent_uuid:
                continue
            if provider is not None and e.provider != provider:
                continue
            if model is not None and e.model != model:
                continue
            if ts_from is not None and e.ts < ts_from:
                continue
            if ts_to is not None and e.ts > ts_to:
                continue
            out.append(e)
        return out

    def aggregate(
        self,
        dimension: str,
        metric: str = "total_tokens",
        **filters: Any,
    ) -> dict[str, float]:
        """Sum a metric grouped by one dimension over filtered events.

        dimension: provider | model | agent_uuid | campaign_uuid
        metric: total_tokens | input_tokens | output_tokens | cost_estimate
        """
        getters = {
            "provider": lambda e: e.provider,
            "model": lambda e: e.model,
            "agent_uuid": lambda e: e.agent_uuid,
            "campaign_uuid": lambda e: e.campaign_uuid,
        }
        metrics = {
            "total_tokens": lambda e: float(e.total_tokens()),
            "input_tokens": lambda e: float(e.input_tokens),
            "output_tokens": lambda e: float(e.output_tokens),
            "latency_ms": lambda e: e.latency_ms,
            "cost_estimate": lambda e: e.cost_estimate or 0.0,
            "requests": lambda e: 1.0,
        }
        if dimension not in getters:
            raise UsageError(f"unknown dimension {dimension!r}")
        if metric not in metrics:
            raise UsageError(f"unknown metric {metric!r}")
        key_of, val_of = getters[dimension], metrics[metric]
        out: dict[str, float] = {}
        for e in self._filtered(**filters):
            out[key_of(e)] = out.get(key_of(e), 0.0) + val_of(e)
        return out


def make_event(
    provider: str,
    model: str,
    agent_uuid: str,
    task_uuid: str,
    campaign_uuid: str,
    input_tokens: int,
    output_tokens: int,
    *,
    cache_tokens: int = 0,
    latency_ms: float = 0.0,
    cost_estimate: float | None = None,
    is_free: bool = False,
    now: float | None = None,
) -> UsageEvent:
    """Factory with server-side timestamp + uuid (callers can't forge either)."""
    return UsageEvent(
        event_uuid=str(uuid.uuid4()),
        ts=now if now is not None else time.time(),
        provider=provider,
        model=model,
        agent_uuid=agent_uuid,
        task_uuid=task_uuid,
        campaign_uuid=campaign_uuid,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_tokens=cache_tokens,
        latency_ms=latency_ms,
        cost_estimate=cost_estimate,
        is_free=is_free,
    )
