"""Tests for providers/pricing.py — pricing & free-tier metadata (issue #210, PLAN §8.1/§8.2)."""

from __future__ import annotations

import pytest

from providers.pricing import (
    FreeTier,
    Pricing,
    PricingStore,
    TokenUsage,
    cost_estimate,
)

NOW = 1_800_000_000.0


def make_pricing(**overrides) -> Pricing:
    base = dict(
        provider="gateway",
        model_id="m1",
        input_per_million=0.15,
        output_per_million=0.60,
        request_price=0.01,
        free_tier=FreeTier(requests_per_day=3, tokens_per_day=10_000),
        source="https://example.com/pricing",
        verified_at=NOW,
    )
    base.update(overrides)
    return Pricing(**base)


class TestPricingRecord:
    def test_cost_math(self):
        p = make_pricing()
        # 0.15*2 + 0.60*0.5 = 0.60 token cost + 0.01 request price
        assert p.cost(TokenUsage(2_000_000, 500_000)) == pytest.approx(0.61)

    def test_zero_pricing_is_free(self):
        assert make_pricing(input_per_million=0, output_per_million=0, request_price=0).is_free
        assert not make_pricing().is_free
        # Any single nonzero dimension disqualifies free status.
        assert not make_pricing(
            input_per_million=0, output_per_million=0, request_price=1.0
        ).is_free

    def test_negative_price_rejected(self):
        with pytest.raises(ValueError):
            make_pricing(input_per_million=-0.1)
        with pytest.raises(ValueError):
            FreeTier(requests_per_day=-1)

    def test_roundtrip_dict(self):
        p = make_pricing()
        restored = Pricing.from_dict(p.to_dict())
        assert restored == p

    def test_free_tier_none_roundtrip(self):
        p = make_pricing(free_tier=None)
        assert Pricing.from_dict(p.to_dict()).free_tier is None

    def test_with_verified_is_immutable_copy(self):
        p = make_pricing(verified_at=0.0, source="")
        q = p.with_verified(NOW, "op note")
        assert p.verified_at == 0.0 and p.source == ""
        assert q.verified_at == NOW and q.source == "op note"


class TestCostEstimate:
    def test_unknown_pricing_returns_none(self):
        # Absence of pricing must surface as None, never an invented number.
        assert cost_estimate(None, TokenUsage(100, 100)) is None

    def test_known_pricing(self):
        assert cost_estimate(make_pricing(), TokenUsage(1_000_000, 0)) == pytest.approx(0.16)


class TestFreeTierBudgets:
    def test_requests_exhaust_to_paid(self):
        store = PricingStore()
        store.upsert(make_pricing(free_tier=FreeTier(requests_per_day=2)))
        u = TokenUsage(0, 0)
        assert store.estimate_cost("gateway", "m1", u, now=NOW) == 0.0
        assert store.estimate_cost("gateway", "m1", u, now=NOW) == 0.0
        # Third request exceeds requests_per_day → paid.
        assert store.estimate_cost("gateway", "m1", u, now=NOW) == pytest.approx(0.01)

    def test_tokens_exhaust_to_paid(self):
        store = PricingStore()
        store.upsert(make_pricing(request_price=0.0, free_tier=FreeTier(tokens_per_day=1_000)))
        small = TokenUsage(400, 400)  # 800 tokens, fits under the cap
        assert store.estimate_cost("gateway", "m1", small, now=NOW) == 0.0
        big = TokenUsage(700, 700)  # would push total to 2200 > 1000 → paid
        expected = 0.15 * 700 / 1_000_000 + 0.60 * 700 / 1_000_000
        assert store.estimate_cost("gateway", "m1", big, now=NOW) == pytest.approx(expected)
        # Even an over-cap single call is billed paid (conservative, never split).
        assert store.estimate_cost("gateway", "m1", big, now=NOW + 1) == pytest.approx(expected)

    def test_budget_resets_next_day(self):
        store = PricingStore(day_seconds=3600.0)
        store.upsert(make_pricing(free_tier=FreeTier(requests_per_day=1)))
        u = TokenUsage(0, 0)
        assert store.estimate_cost("gateway", "m1", u, now=NOW) == 0.0
        assert store.estimate_cost("gateway", "m1", u, now=NOW) == pytest.approx(0.01)
        # Next window: budget reset → free again.
        assert store.estimate_cost("gateway", "m1", u, now=NOW + 3600.0) == 0.0

    def test_no_free_tier_always_paid(self):
        store = PricingStore()
        store.upsert(make_pricing(free_tier=None))
        assert store.estimate_cost("gateway", "m1", TokenUsage(0, 0), now=NOW) == pytest.approx(
            0.01
        )

    def test_unpriced_model_costs_none(self):
        store = PricingStore()
        assert store.estimate_cost("gateway", "ghost", TokenUsage(5, 5), now=NOW) is None

    def test_fully_free_model_never_exhausts(self):
        store = PricingStore()
        store.upsert(
            make_pricing(
                input_per_million=0,
                output_per_million=0,
                request_price=0,
                free_tier=FreeTier(requests_per_day=1),
            )
        )
        for _ in range(5):
            assert store.estimate_cost("gateway", "m1", TokenUsage(9, 9), now=NOW) == 0.0

    def test_remaining_budget_snapshot(self):
        store = PricingStore()
        store.upsert(make_pricing())
        store.estimate_cost("gateway", "m1", TokenUsage(1_000, 1_000), now=NOW)
        rem = store.remaining_free_budget("gateway", "m1", now=NOW)
        assert rem == {"requests": 2, "tokens": 8_000}
        # Unpriced model → no budget info at all.
        assert store.remaining_free_budget("gateway", "ghost", now=NOW) == {
            "requests": None,
            "tokens": None,
        }


class TestStorePersistence:
    def test_export_import_roundtrip(self):
        store = PricingStore()
        store.upsert(make_pricing())
        store.upsert(make_pricing(model_id="m2", free_tier=None))
        data = store.export_pricing()
        other = PricingStore()
        assert other.import_pricing(data) == 2
        assert other.all_pricing() == store.all_pricing()

    def test_all_pricing_sorted_by_key(self):
        store = PricingStore()
        store.upsert(make_pricing(model_id="zeta"))
        store.upsert(make_pricing(model_id="alpha"))
        assert [p.model_id for p in store.all_pricing()] == ["alpha", "zeta"]
