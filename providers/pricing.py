"""Pricing & free-tier constraint metadata for catalog entries (PLAN §8.1/§8.2, issue #210).

The model catalog (providers/model_catalog.py, #118) carries identity,
capabilities, context limits, rate limits and capability flags — but no
pricing. PLAN §8.1 explicitly lists "pricing/free status and free-tier
constraints" as provider metadata the system must maintain, and free-only
routing (#66) plus cost attribution (#28) both need it.

This module adds a dependency-free pricing record that attaches to a
catalog entry key:

- :class:`Pricing` — per-model pricing: currency, per-million-token input/
  output prices, optional request price, and free-tier constraints
  (requests/day, tokens/day, context cap under the free tier).
- :func:`cost_estimate` — deterministic token-based cost estimation used by
  usage accounting (#28) before real metered data lands.
- :class:`PricingStore` — in-memory store keyed by ``provider/model`` with
  effective-cost queries that respect free-tier budgets.

Design rules matching the rest of ``providers/``:

- Storage-agnostic (in-memory dict), serializable via ``to_dict``.
- Absence of pricing is NOT an error — models without a Pricing record are
  simply not cost-attributable; queries return ``None``, never invented data.
- Free-tier constraints are conservative caps: when a budget dimension is
  exhausted the effective price falls back to paid pricing, never to zero.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, replace
from typing import Any

__all__ = ["Pricing", "PricingStore", "TokenUsage", "cost_estimate"]


@dataclass(frozen=True)
class TokenUsage:
    """A single billable interaction's token counts."""

    input_tokens: int = 0
    output_tokens: int = 0

    def to_dict(self) -> dict[str, int]:
        return {"input_tokens": self.input_tokens, "output_tokens": self.output_tokens}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TokenUsage:
        return cls(
            input_tokens=int(d.get("input_tokens", 0)), output_tokens=int(d.get("output_tokens", 0))
        )


def _validate_nonneg(name: str, value: float) -> float:
    if value < 0:
        raise ValueError(f"{name} must be >= 0, got {value}")
    return value


@dataclass(frozen=True)
class FreeTier:
    """Free-tier constraints for one model (PLAN §8.1 'free-tier constraints').

    All dimensions are optional caps; ``None`` means "no locally-known limit"
    on that dimension (not "unlimited" — we simply don't enforce).
    """

    requests_per_day: int | None = None
    tokens_per_day: int | None = None
    # Max context window usable while on the free tier; may be smaller than
    # the model's full context window.
    context_token_cap: int | None = None

    def __post_init__(self) -> None:
        for name in ("requests_per_day", "tokens_per_day", "context_token_cap"):
            v = getattr(self, name)
            if v is not None:
                _validate_nonneg(name, v)

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests_per_day": self.requests_per_day,
            "tokens_per_day": self.tokens_per_day,
            "context_token_cap": self.context_token_cap,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FreeTier:
        return cls(
            requests_per_day=d.get("requests_per_day"),
            tokens_per_day=d.get("tokens_per_day"),
            context_token_cap=d.get("context_token_cap"),
        )


@dataclass(frozen=True)
class Pricing:
    """Pricing metadata for one (provider, model).

    Prices are per **million** tokens in ``currency`` (the convention used by
    every major provider), so typical values stay human-readable
    (e.g. 0.15 USD/M input). ``request_price`` is an optional flat per-request
    charge on top of token costs.
    """

    provider: str
    model_id: str
    currency: str = "USD"
    input_per_million: float = 0.0
    output_per_million: float = 0.0
    request_price: float = 0.0
    free_tier: FreeTier | None = None
    source: str = ""  # provenance pointer: pricing page URL / operator note
    verified_at: float = 0.0  # epoch seconds; 0 = never verified

    def __post_init__(self) -> None:
        _validate_nonneg("input_per_million", self.input_per_million)
        _validate_nonneg("output_per_million", self.output_per_million)
        _validate_nonneg("request_price", self.request_price)

    @property
    def key(self) -> str:
        return f"{self.provider}/{self.model_id}"

    @property
    def is_free(self) -> bool:
        """A model prices as free only when every price dimension is zero."""
        return (
            self.input_per_million == 0.0
            and self.output_per_million == 0.0
            and self.request_price == 0.0
        )

    def with_verified(self, now: float, source: str = "") -> Pricing:
        """Return a copy marked as verified at ``now`` (immutability-preserving)."""
        return replace(self, verified_at=now, source=source or self.source)

    def cost(self, usage: TokenUsage) -> float:
        """Deterministic cost estimate for a token usage, ignoring free tier."""
        cost = (
            self.input_per_million * usage.input_tokens / 1_000_000
            + self.output_per_million * usage.output_tokens / 1_000_000
            + self.request_price
        )
        return round(cost, 10)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model_id": self.model_id,
            "currency": self.currency,
            "input_per_million": self.input_per_million,
            "output_per_million": self.output_per_million,
            "request_price": self.request_price,
            "free_tier": self.free_tier.to_dict() if self.free_tier else None,
            "source": self.source,
            "verified_at": self.verified_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Pricing:
        ft = d.get("free_tier")
        return cls(
            provider=str(d["provider"]),
            model_id=str(d["model_id"]),
            currency=str(d.get("currency", "USD")),
            input_per_million=float(d.get("input_per_million", 0.0)),
            output_per_million=float(d.get("output_per_million", 0.0)),
            request_price=float(d.get("request_price", 0.0)),
            free_tier=FreeTier.from_dict(ft) if ft else None,
            source=str(d.get("source", "")),
            verified_at=float(d.get("verified_at", 0.0)),
        )


def cost_estimate(pricing: Pricing | None, usage: TokenUsage) -> float | None:
    """Module-level estimate helper; ``None`` when no pricing is known.

    Usage accounting (#28) must never invent costs for unpriced models —
    absence of data is reported as absence.
    """
    if pricing is None:
        return None
    return pricing.cost(usage)


@dataclass
class DailyBudgetState:
    """Rolling per-day free-tier consumption counters for one model."""

    day_start: float  # epoch seconds of current counting-day start
    requests: int = 0
    tokens: int = 0


class PricingError(ValueError):
    """Raised for invalid pricing-store operations."""


class PricingStore:
    """In-memory pricing catalog keyed by ``provider/model``."""

    DAY_SECONDS = 24 * 3600.0

    def __init__(self, day_seconds: float = DAY_SECONDS) -> None:
        self._pricing: dict[str, Pricing] = {}
        self._budgets: dict[str, DailyBudgetState] = {}
        self.day_seconds = day_seconds

    # --- basic access ------------------------------------------------------

    @staticmethod
    def _key(provider: str, model_id: str) -> str:
        return f"{provider}/{model_id}"

    def get(self, provider: str, model_id: str) -> Pricing | None:
        return self._pricing.get(self._key(provider, model_id))

    def upsert(self, pricing: Pricing) -> Pricing:
        self._pricing[pricing.key] = pricing
        return pricing

    def all_pricing(self) -> list[Pricing]:
        return sorted(self._pricing.values(), key=lambda p: p.key)

    # --- cost attribution ---------------------------------------------------

    def estimate_cost(
        self,
        provider: str,
        model_id: str,
        usage: TokenUsage,
        now: float | None = None,
    ) -> float | None:
        """Cost of one call after applying free-tier budget state.

        - No pricing record → ``None`` (unknown, never guessed).
        - Within remaining free-tier budget → 0.0.
        - Free tier exhausted or absent → full paid price.
        """
        now = time.time() if now is None else now
        pricing = self.get(provider, model_id)
        if pricing is None:
            return None
        if self._within_free_budget(provider, model_id, pricing, usage, now):
            self._consume_free_budget(provider, model_id, usage, now)
            return 0.0
        return pricing.cost(usage)

    def _roll_day(self, key: str, now: float) -> DailyBudgetState:
        state = self._budgets.get(key)
        if state is None or (now - state.day_start) >= self.day_seconds:
            state = DailyBudgetState(day_start=now)
            self._budgets[key] = state
        return state

    def _within_free_budget(
        self, provider: str, model_id: str, pricing: Pricing, usage: TokenUsage, now: float
    ) -> bool:
        if pricing.free_tier is None or pricing.is_free:
            # A fully-free model has no budget to exhaust.
            return pricing.is_free
        ft = pricing.free_tier
        state = self._roll_day(self._key(provider, model_id), now)
        total_tokens = usage.input_tokens + usage.output_tokens
        if ft.requests_per_day is not None and state.requests + 1 > ft.requests_per_day:
            return False
        if ft.tokens_per_day is not None and state.tokens + total_tokens > ft.tokens_per_day:
            return False
        return True

    def _consume_free_budget(
        self, provider: str, model_id: str, usage: TokenUsage, now: float
    ) -> None:
        if pricing := self._pricing.get(self._key(provider, model_id)):
            if pricing.free_tier is not None and not pricing.is_free:
                state = self._roll_day(self._key(provider, model_id), now)
                state.requests += 1
                state.tokens += usage.input_tokens + usage.output_tokens

    def remaining_free_budget(
        self, provider: str, model_id: str, now: float | None = None
    ) -> dict[str, int | float | None]:
        """Human/agent-readable snapshot of what's left of the free tier today."""
        now = time.time() if now is None else now
        pricing = self.get(provider, model_id)
        if pricing is None or pricing.free_tier is None or pricing.is_free:
            return {"requests": None, "tokens": None}
        ft = pricing.free_tier
        state = self._roll_day(self._key(provider, model_id), now)
        req_left = (
            max(0, ft.requests_per_day - state.requests)
            if ft.requests_per_day is not None
            else None
        )
        tok_left = (
            max(0, ft.tokens_per_day - state.tokens) if ft.tokens_per_day is not None else None
        )
        return {"requests": req_left, "tokens": tok_left}

    # --- persistence helpers --------------------------------------------------

    def export_pricing(self) -> list[dict[str, Any]]:
        return [p.to_dict() for p in self.all_pricing()]

    def import_pricing(self, records: list[dict[str, Any]]) -> int:
        count = 0
        for raw in records:
            self.upsert(Pricing.from_dict(raw))
            count += 1
        return count


# Re-exported so tests/callers can mint ids without importing uuid themselves
# elsewhere; kept private-use here to avoid leaking uuid into module API docs.
_ = uuid
_ = field
