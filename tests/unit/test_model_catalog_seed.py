"""Tests for the maintained seed model catalog (issue #210, PLAN §8.2)."""

from __future__ import annotations

import pytest

from providers.free_status import FreeStatus
from providers.model_catalog import CatalogEntry, ModelCatalog
from providers.model_catalog.seed import (
    SEED_ENTRIES,
    CatalogValidationError,
    load_seed_catalog,
    validate_entry,
)


def test_seed_entries_all_valid_and_unknown_status():
    assert len(SEED_ENTRIES) >= 3  # one per PLAN §8.2 provider class
    keys = set()
    for entry in SEED_ENTRIES:
        validate_entry(entry)  # must not raise
        # Seeds never pre-approve freeness — that's the #87 human gate.
        assert entry.free_status is FreeStatus.UNKNOWN
        keys.add(entry.key)
    assert len(keys) == len(SEED_ENTRIES)  # unique identity


def test_load_seed_catalog_populates_and_roundtrips():
    cat = load_seed_catalog(now=100.0)
    assert isinstance(cat, ModelCatalog)
    for entry in SEED_ENTRIES:
        got = cat.get(entry.provider, entry.model_id)
        assert got is not None
        assert CatalogEntry.from_dict(got.to_dict()) == got
        # Seed metadata preserved verbatim apart from the verification stamp
        # applied by upsert.
        expected = CatalogEntry.from_dict(entry.to_dict())
        expected.last_verified = 100.0
        assert got == expected
        assert got.last_verified == 100.0
        # Serialization roundtrip preserves new pricing fields.
        assert CatalogEntry.from_dict(got.to_dict()) == got


def test_load_into_existing_catalog_does_not_clobber():
    cat = ModelCatalog()
    existing = CatalogEntry(provider="other", model_id="m", context_window=1)
    cat.upsert(existing, now=1.0)
    load_seed_catalog(cat, now=2.0)
    kept = cat.get("other", "m")
    assert kept is not None and kept.last_verified == 1.0


@pytest.mark.parametrize(
    "field,value",
    [
        ("context_window", -5),
        ("request_rate_limit", 0),
        ("token_rate_limit", -1),
        ("price_input_per_mtok", -0.01),
    ],
)
def test_validate_rejects_bad_limits(field, value):
    entry = CatalogEntry(provider="p", model_id="m", **{field: value})
    if field.startswith("price_"):
        entry.price_currency = "USD"
    with pytest.raises(CatalogValidationError):
        validate_entry(entry)


def test_pricing_requires_currency():
    entry = CatalogEntry(provider="p", model_id="m", price_input_per_mtok=1.0)
    with pytest.raises(CatalogValidationError):
        validate_entry(entry)
    entry.price_currency = "USD"
    validate_entry(entry)  # ok


def test_paid_pricing_contradicts_free_status():
    entry = CatalogEntry(
        provider="p",
        model_id="m",
        price_input_per_mtok=3.0,
        price_output_per_mtok=15.0,
        price_currency="USD",
        free_status=FreeStatus.FREE,
    )
    with pytest.raises(CatalogValidationError):
        validate_entry(entry)


def test_zero_price_is_free_tier_compatible():
    entry = CatalogEntry(
        provider="p",
        model_id="m",
        price_input_per_mtok=0.0,
        price_output_per_mtok=0.0,
        price_currency="USD",
        free_status=FreeStatus.FREE,
    )
    validate_entry(entry)


def test_free_tier_constraint_keys_are_validated():
    entry = CatalogEntry(provider="p", model_id="m", free_tier_constraints={"nonsense": 1})
    with pytest.raises(CatalogValidationError):
        validate_entry(entry)
