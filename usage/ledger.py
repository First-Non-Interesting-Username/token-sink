"""Usage ledger: record + aggregate usage events (PLAN §13.5, §14, §21).

Every model call becomes a ``usage_event`` matching
``schemas/usage_event.schema.json``. The ledger validates each event on
write (binary accept/reject, mirroring schemas/validate.py's philosophy) and
answers aggregation queries by any attribution dimension with time-range
filters. Free-tier vs paid separation is built into every aggregate rather
than bolted on later — the PLAN requires it "everywhere it's displayed or
exported".

Storage-agnostic: the in-memory list backs tests and Phase 1; a SQLite
backend can implement the same ``record``/``events`` surface later.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from schemas.validate import SchemaRegistry


class InvalidUsageEvent(ValueError):
    """A usage event failed schema validation; it is never stored."""


@dataclass(frozen=True)
class LedgerQuery:
    """Attribution filter. ``None`` means "any". Time range is inclusive on
    both ends and compares against ``occurred_at``."""

    provider_id: str | None = None
    model_id: str | None = None
    campaign_uuid: str | None = None
    agent_uuid: str | None = None
    task_uuid: str | None = None
    is_free_tier: bool | None = None
    request_status: str | None = None
    since: str | None = None  # ISO timestamp
    until: str | None = None

    def matches(self, ev: dict[str, Any]) -> bool:
        for dim, key in (
            ("provider_id", "provider_id"),
            ("model_id", "model_id"),
            ("campaign_uuid", "campaign_uuid"),
            ("agent_uuid", "agent_uuid"),
            ("task_uuid", "task_uuid"),
            ("is_free_tier", "is_free_tier"),
            ("request_status", "request_status"),
        ):
            want = getattr(self, dim)
            if want is not None and ev.get(key) != want:
                return False
        ts = ev.get("occurred_at", "")
        if self.since is not None and ts < self.since:
            return False
        if self.until is not None and ts > self.until:
            return False
        return True


@dataclass(frozen=True)
class UsageTotals:
    """Aggregated totals for one query. Free/paid split is always present so
    no caller can accidentally merge the two (issue #28 requirement)."""

    requests: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    free_requests: int = 0
    paid_requests: int = 0
    free_input_tokens: int = 0
    paid_input_tokens: int = 0
    free_output_tokens: int = 0
    paid_output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    errors: int = 0  # error/timeout/rate_limited requests

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


class _TotalsAccumulator:
    """Internal accumulator; builds a UsageTotals incrementally."""

    def __init__(self) -> None:
        self.totals = UsageTotals()

    def add(self, ev: dict[str, Any]) -> None:
        t = self.totals
        # dataclasses are immutable; rebuild via replace-like construction
        d = t.as_dict()
        d["requests"] += 1
        free = bool(ev.get("is_free_tier"))
        inp = int(ev.get("input_tokens") or 0)
        outp = int(ev.get("output_tokens") or 0)
        d["input_tokens"] += inp
        d["output_tokens"] += outp
        d["cache_read_tokens"] += int(ev.get("cache_read_tokens") or 0)
        d["cache_write_tokens"] += int(ev.get("cache_write_tokens") or 0)
        if free:
            d["free_requests"] += 1
            d["free_input_tokens"] += inp
            d["free_output_tokens"] += outp
        else:
            d["paid_requests"] += 1
            d["paid_input_tokens"] += inp
            d["paid_output_tokens"] += outp
        cost = ev.get("estimated_cost_usd")
        if cost is not None:
            d["estimated_cost_usd"] += float(cost)
        if ev.get("request_status") != "success":
            d["errors"] += 1
        object.__setattr__(t, "__dict__", d)

    def result(self) -> UsageTotals:
        return self.totals


@dataclass
class Budget:
    """Token/request budget for one scope (per-agent or per-campaign).
    ``None`` means unlimited for that dimension."""

    max_input_tokens: int | None = None
    max_output_tokens: int | None = None
    max_requests: int | None = None

    def breach(self, totals: UsageTotals) -> BudgetBreach | None:
        """Return a BudgetBreach describing the first exceeded limit, or None."""
        checks = (
            ("input_tokens", self.max_input_tokens),
            ("output_tokens", self.max_output_tokens),
            ("requests", self.max_requests),
        )
        for name, limit in checks:
            if limit is None:
                continue
            used = getattr(totals, name)
            if used > limit:
                return BudgetBreach(
                    dimension=name,
                    used=used,
                    limit=limit,
                    overage=used - limit,
                )
        return None


@dataclass(frozen=True)
class BudgetBreach(Exception):
    """A budget was exceeded; observable via the ledger API (issue #28)."""

    dimension: str
    used: int
    limit: int
    overage: int

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"budget breached on {self.dimension}: {self.used}/{self.limit} (+{self.overage})"


class UsageLedger:
    """Records usage events and answers attribution queries."""

    def __init__(self, registry: SchemaRegistry | None = None) -> None:
        self._events: list[dict[str, Any]] = []
        # One shared registry instance caches parsed schemas across events.
        self._registry = registry or SchemaRegistry()

    def record(self, event: dict[str, Any], *, validate: bool = True) -> str:
        """Validate and store one usage_event; returns its event_uuid.

        Raises InvalidUsageEvent on schema violations — bad accounting data
        is worse than no data, so acceptance is binary.
        """
        if validate:
            result = self._registry.validate("usage_event", event)
            if not result.valid:
                raise InvalidUsageEvent(f"usage_event rejected: {'; '.join(result.errors)}")
        self._events.append(dict(event))
        return event["event_uuid"]

    def events(self, query: LedgerQuery | None = None) -> list[dict[str, Any]]:
        """All stored events matching the query, oldest first."""
        q = query or LedgerQuery()
        return [ev for ev in self._events if q.matches(ev)]

    def totals(self, query: LedgerQuery | None = None) -> UsageTotals:
        """Aggregate tokens/requests/cost for the query, free split from paid."""
        acc = _TotalsAccumulator()
        for ev in self.events(query):
            acc.add(ev)
        return acc.result()

    # --- budget checks ----------------------------------------------------

    def check_budget(
        self,
        budget: Budget,
        query: LedgerQuery | None = None,
    ) -> BudgetBreach | None:
        """Evaluate a budget against current usage; returns the first breach
        or None. Callers run this pre-flight AND after each call."""
        return budget.breach(self.totals(query))
